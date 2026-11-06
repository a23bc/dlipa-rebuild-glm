# Architecture

What runs where, why it is shaped this way, and which failures forced each
decision. Every "why" below points at something observed on device, because most
of the design is the residue of a specific failure rather than a preference.

---

## The shape of the thing

```
Swift UI            SearchScreen · VersionListView · DownloadsScreen · AccountsScreen
                    DownloadManager (jobs outlive the screens that start them)
      │
Swift networking    AppStoreClient  signed transport, bag, login, download
                    StoreBag        bag.xml (loc- prefixed keys)
                    SAPSigner       thin wrapper over the Go bridge
                    AssetStaging    asks the bridge for the Apple binaries; on
                                    a normal build none are bundled, so the
                                    first sign fetches them from Apple (~212 MB
                                    of range reads, measured on device)
      │  (gomobile c-archive, declarations copied by hand into
      │   DLiPA-Bridging-Header.h and checked by scripts/check-bridging-header.py)
Go bridge           sapbridge.go   Sign · SignatureHeaderValue · KBSync ·
                                   StoreSmoke · EntDownload
      │
Go core             internal/sap
                      machine      the arm64 guest: Unicorn TCI, one per process
                      machimage    Mach-O loader for CoreFP / AMS / commerce
                      signer       SAP handshake, session, kbsync generation
                      assets       staged asset loading and validation
                    internal/store
                      profile      recorded pages and call sites of the real store
                      cachepages   slice of the dyld shared cache the guest reaches for
                      emulator     the Store runtime: mapping, hooks, encoder, Execute
```

Two processes' worth of Apple code run inside one app: the **SAP machine** (signs
bodies) and the **Store runtime** (builds and sends Store requests). Both are
tenants on the same Unicorn engine.

---

## Only one engine, only one store runtime

`uc_open` initialises TCG's translator buffer **once per process**. A second
engine fails with `Could not allocate dynamic translator buffer`, so the Store
runtime does not get its own address space — it borrows the SAP machine's engine
and maps its own pages into the same guest.

The store runtime, in turn, can only be opened **once per process**. Opening it a
second time does not fail loudly; it silently produces a broken session:

```
open(): kept 9927 cache pages and 5087 profile pages the machine already had
encoder setAccount: unknown receiver 0x5000007fefb0 for setAccount:
```

The first session's pages are still mapped and still carry the `ret` patches the
runtime installs at every recorded call site. The second open sees them as
"already there", skips restoring, and hands the encoder objects belonging to a
session that has ended. The guest then takes an exception.

So `sap.Signer` keeps one `storeRuntime` and one kbsync blob for the life of the
signer, and `Close` takes the runtime down **before** the machine — the runtime
puts back the bytes it patched, and that work needs the engine to still exist.

**Known consequence:** while the runtime is up, those patched call sites stay
patched on the engine that also signs. A later SAP signature may fail. Nothing in
the current flows depends on signing after a download starts, but it is a real
constraint, not a theoretical one.

---

## The download flow

```
SearchScreen ──tap──▶ DownloadManager.start()  (returns immediately)
                            │
                            ├─ AppSession.download
                            │     ├─ AppStoreClient.requestDownload
                            │     │     └─ bridge EntDownload
                            │     │           kbsync (before open, see below)
                            │     │           open or reuse the store runtime
                            │     │           EncodeProbe → RequestParts → Execute
                            │     │           parse plist: songList[0].URL
                            │     └─ URLSession download  ──▶ Downloads/  (+ progress)
                            └─ job.state / job.received  ──▶ DownloadsScreen
```

The URL request and the transfer have very different lifetimes — minutes of
emulated work, then ordinary networking — and were originally both inside the
screen that started them. That is why the app looked hung. `DownloadManager` owns
them now; screens come and go.

---

## Decisions that were forced, not chosen

| Decision | The failure that forced it |
|---|---|
| kbsync is generated **before** the store runtime opens | Generated after, the generator runs past its one-minute bound at `0x100000da692c` and never returns |
| `Content-Type: application/x-www-form-urlencoded` on ent/download | Left at the encoder's `application/x-apple-plist`, the endpoint answers **500 with an empty body** |
| `User-Agent: Configurator/2.18 …` | Without it, 500. With it, 401 — which was progress, because 401 says "credentials", not "shape" |
| The session cookie header must be sent | Token alone gets **401**. A token identifies an account; the cookies are the session |
| `salableAdamId` is a **string** | As an integer the server returns 500. Upstream formats it with `strconv.FormatInt` |
| `externalVersionId` must be non-empty | Empty → 500 with no body. The probe never succeeded without one; the first real download reproduced it |
| Endpoint comes from the bag | Hardcoding `downloaddispatch…` is correct today, but the pod this account is routed through is the bag's business |
| Bridging header declarations are compared by **full selector** | `storeSmoke` grew a parameter, the header did not, and the script compared only the first label — so it reported a match while the build failed with "extra argument" |

---

## Memory and time on device

Opening the store runtime maps about 70 MB into the guest, and `uc_mem_map` costs
**0.7–2 s per MiB** on this device. The first open therefore takes ~2 minutes; the
breakdown was measured, not estimated:

```
phase cache pages  at 31.0s     39 MB of dyld shared cache
phase page table   at 31.0s     negligible
phase region maps  at 1m28s     170 regions, dominated by a 19 MB span
phase call sites   at 1m28s     13,370 patches, 21 ms
```

Two optimisations landed and one did not:

* pages are mapped in runs and patches applied a page at a time — the per-page
  `uc_mem_map` / `uc_mem_write` calls were the original cost;
* translation-cache flushes are batched to once per map set;
* chunking the 19 MB region into 4 MiB pieces changed nothing (37.5 s vs 38.3 s).
  The cost is linear in bytes, so the only remaining lever is mapping less, which
  is why the runtime is kept open rather than optimised further.

---

## Diagnostics

Everything the app does is observable without a debugger, because attaching one is
not something anyone wants to do to report a bug:

* **stderr recorder** — each launch captures the previous run's stderr to a file
  the Diagnostics tab can share.
* **phase stamps** — `open()` reports its own clock at each stage
  (`phase cache pages at …`), so time goes where the code measured it rather than
  where log timestamps suggest. Log timestamps are *not* evidence here: stderr is
  drained in batches, and lines seconds apart on the clock arrive tens of seconds
  apart.
* **main-queue heartbeat** — a two-second timer during probes. If it stops while
  the spinner still turns, the main thread is blocked; if it continues, the app is
  merely slow.
* **store smoke** — a diagnostic build path that runs the same encode/execute the
  production download uses and prints the request, headers, response status and
  body head.

---

## What is deliberately not here

* **Classic `volumeStoreDownloadProduct`** still exists as a fallback. It answers
  `2042` for a signed-in session and its `buyProduct` fallback answers
  `MZCommerce.SystemError`; it is kept only until the encoder path has run a while
  in the field, then it goes.
* **No cached kbsync across launches.** It is generated once per signer and lives
  in memory.
* **No second store runtime**, and no attempt to make one work: see above.
