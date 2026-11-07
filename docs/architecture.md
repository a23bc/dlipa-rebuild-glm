# Architecture

What runs where, why it is shaped this way, and which failures forced each decision. Every "why" below points at something observed on device, because most of the design is the residue of a specific failure rather than a preference.

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

Two processes' worth of Apple code run inside one app: the **SAP machine** (signs bodies) and the **Store runtime** (builds and sends Store requests). Both are tenants on the same Unicorn engine.

---

## Only one engine, only one store runtime

`uc_open` initialises TCG's translator buffer **once per process**. A second engine fails with `Could not allocate dynamic translator buffer`, so the Store runtime does not get its own address space — it borrows the SAP machine's engine and maps its own pages into the same guest.

The store runtime, in turn, can only be opened **once without a close in between**. Opening it a second time does not fail loudly; it silently produces a broken session:

```
open(): kept 9927 cache pages and 5087 profile pages the machine already had
encoder setAccount: unknown receiver 0x5000007fefb0 for setAccount:
```

The first session's pages are still mapped and still carry the `ret` patches the runtime installs at every recorded call site. The second open sees them as "already there", skips restoring, and hands the encoder objects belonging to a session that has ended. The guest then takes an exception.

So `sap.Signer` keeps one `storeRuntime` for the life of the signer, and `Close` takes the runtime down **before** the machine — the runtime puts back the bytes it patched, and that work needs the engine to still exist. The kbsync blob is not part of that arrangement: every request resolves its own, by DSID, from memory or disk, which is what lets the one runtime answer more than one account.

That scopes the rule to the lifetime of a session, not of the process. `Close` restores every patched call site, drops the hooks and releases the Go-side tables the guest's objects were held in, and whether it should also release the pages has now been run on device, twice, on two consecutive builds -- with and without the release. Both times a signature taken on the machine immediately after the close failed the same way: `SAP signing returned -42306`, with `x0` holding that number in two's complement, `x1` pointing inside AppleMediaServices and a null output pointer. And both times the session opened afterwards came up rather than dying on the map -- 934 ms with 36447 pages released, 739 ms with the pages left mapped, `skipped 2 images` and 20 profile pages recorded as the machine's against the 33 before the close -- and then died one call later at the same receiver, `0x5000007fefb0`, that the quoted open-without-close case produces. In the second build that death did not return: the fault is a `BRK #0` at the return stub, the only bound on such a run is 20,000,000 instructions with no wall-clock timeout, and the thread holds the signer's mutex while it spends them, so the app looked frozen for minutes.

Nothing in the download path closes a runtime any more, and a second account is served by the first account's runtime. The refusal that used to guard this was guarding the wrong thing: what it described as a framework error for the second account is what a single in-memory kbsync slot does when it answers one account with another account's blob -- `ent/download (encoder) HTTP 500, 0 bytes` with an empty body, and no disk read in the log to say so.

**Known consequence:** while the runtime is up, those patched call sites stay patched on the engine that also signs. A later SAP signature may fail. Nothing in the current flows depends on signing after a download starts, but it is a real constraint, not a theoretical one.

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

The URL request and the transfer have very different lifetimes — seconds of emulated work, then ordinary networking — and were originally both inside the screen that started them. That is why the app looked hung. `DownloadManager` owns them now; screens come and go.

---

## The kbsync blob

The blob Apple wants attached to each signed request is produced by running the guest, and it is the most expensive thing this app does on a user's behalf: **32.4 s measured on device, of which 32.06 s is the storeagent global init and 371 ms is the call that is actually about the account** -- each step stamps its own wall time, emulation starts and Go-emulated instructions now, so the silence between the request and the open is gone. The init step takes the hardware block and the SC Info path and no DSID, which is why the blob is kept rather than regenerated, and why a fresh sign-in generates it before anything asks. Three sources are tried in this order:

1. **memory** — the signer holds one blob and the DSID it belongs to;
2. **disk** — `Library/Caches/dlipa/kbsync-v1-<dsid>.bin`, written with mode 0600 only after Apple has accepted the blob once, and read back with no measurable cost;
3. **generate** — `machine.GenerateKBSyncOn`, the expensive path.

A blob Apple rejects is removed from memory and from disk, and the next attempt generates a fresh one (`cached kbsync rejected (%s), discarded`) -- unless the answer was about the account or the licence rather than the blob (`9610`, `5002`, `2042`, `2034`, `2002`, `signInRequired`, `passwordTokenExpired`), which keeps it: an earlier build deleted the blob on those answers and turned a browse of the version history into a restart-only dead end.

Upgrades no longer clear the cache. The sweep keyed on `CFBundleShortVersionString` conflated shipping a build with shipping a bridge whose guest assumptions changed, and only the second is a reason to discard a blob that costs 32 s to replace; `CFBundleVersion` is the CI run number, which is why that one was never the key. Retirement is the **format version inside the stored name** -- bump `kbsync-v1` when what a blob has to be changes, and every old one retires by missing -- plus Apple's own rejection, which was always the mechanism doing the real work. A file whose name carries no version predates this change: it is not read, and the first lookup that misses deletes it, because credential material nothing reads has no business staying in the container.

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

Opening the store runtime is a few thousand `uc_mem_map` calls, and what one of them costs depends on **what is already mapped around it**, not only on how many bytes it covers.

Eager mapping states the price plainly: 9,927 shared-cache pages, 38.8 MiB, `open(): mapped 9927 shared-cache pages in 3833 runs, 31056 ms` — about 0.8 s per MiB, and unchanged when the same pages are sent in smaller runs. The more expensive consequence is that those 38.8 MiB then sit in the address space for every phase that follows:

| | eager | on demand |
|---|---|---|
| shared cache | `mapped 9927 … in 31056 ms` | `indexed 9903 … 336 ms, mapped none` |
| region maps | `170 regions mapped in 1m2.149s` | `193 regions mapped in 127ms` |
| `phase hooks` | `1m33.985s` – `1m39.383s` | `1.006s` – `1.215s` |

The on-demand open maps *more* regions (193 against 170) and finishes that phase in 127 ms instead of 62.1 s. The region set barely differs between the two runs, so neither the count nor the bytes in it can account for a 490-fold gap. What does differ, by 38.8 MiB, is the shared cache already in the address space when the phase runs — which makes the 0.8 s per MiB a rate paid inside the eager configuration rather than a constant of the call. That is the reason the default now indexes the cache and hands out a page per fault:

```
open(): indexed 9903 shared-cache pages in 3833 runs, 336 ms, mapped none (1631 dropped: inside a loaded image, 186130 instructions rewritten)
open(): phase cache pages  at 885ms
open(): phase page table   at 892ms
open(): 193 regions mapped in 127ms
open(): phase region maps  at 1.172s
open(): phase call sites   at 1.172s
open(): phase pac strip    at 1.214s
open(): phase metadata     at 1.215s
open(): phase hooks        at 1.215s
```

The index is not free — 163–336 ms plus a resident table — and the flow that pays it back is the ordinary one: the signed download on record asks for **none** of the indexed pages,

```
ent download: shared cache served 0 pages (0 KiB in 0 ms), 0 faults outside the blob, 0 failed, 9903 untouched
```

so demand paging costs the download path nothing up front and charges only per page a flow actually touches.

Two optimisations landed and one did not:

* pages are mapped in runs and patches applied a page at a time — the per-page `uc_mem_map` / `uc_mem_write` calls were the original cost;
* translation-cache flushes are batched to once per map set;
* chunking the 19 MB region into 4 MiB pieces changed nothing (37.5 s vs 38.3 s), and a 1 MiB split was worse and was reverted. Bytes are the unit of the price, but the rate comes from the map state around them: the lever that works is not mapping them at all.

The runtime is still kept open for the life of the signer, and the reason is no longer the clock — at 1.2 s an open would be affordable. It is kept open because closing it is what breaks: a signature taken on the machine right after a `Close` returned -42306, with and without releasing the address space, and the session opened afterwards died one call later at the same receiver. So nothing in the download path closes one, and a second account is served through the first account's runtime — see above.

---

## Diagnostics

Everything the app does is observable without a debugger, because attaching one is not something anyone wants to do to report a bug. [`diagnostics.md`](diagnostics.md) is the operator's half of this — every switch on the Diagnostics tab, what it changes and when it takes effect, and what the lines it produces mean; this section is the half about why observation is shaped the way it is.

* **stderr recorder** — each launch captures the previous run's stderr to a file the Diagnostics tab can share.
* **phase stamps** — `open()` reports its own clock at each stage (`phase cache pages at …`), so time goes where the code measured it rather than where log timestamps suggest. Log timestamps are *not* a stopwatch: stderr is drained in batches, so lines seconds apart on the clock arrive tens of seconds apart, and a batch boundary can fall anywhere inside the interval being measured.
* **main-queue heartbeat** — a two-second timer during probes. If it stops while the spinner still turns, the main thread is blocked; if it continues, the app is merely slow.
* **store smoke** — a diagnostic build path that runs the same encode/execute the production download uses and prints the request, headers, response status and body head.

The 117 s figure is the worked example, because it is the one number here that came off the clock and looked right. A capture put `08:10:00` on the incoming request and `08:11:57` on the open, with nothing in between, and 117 s of kbsync generation is a plausible reading of that interval. It is still not a measurement: silence is exactly what a drain looks like, and nothing in the interval says when generation began or ended.

What settles that case is structural, not temporal. A later capture logs `ent download: kbsync from disk (212 bytes)` at the point where the first one fell silent, and its open follows with no gap at all. Two runs of the same flow, one generating and one reading a file — that is the difference the timestamps were being asked to show, and the line shows it without the clock. Read the log for *what happened*; read a phase stamp for *how long it took*.

---

## What is deliberately not here

* **Classic `volumeStoreDownloadProduct`** still exists as a fallback. It answers `2042` for a signed-in session and its `buyProduct` fallback answers `MZCommerce.SystemError`; it is kept only until the encoder path has run a while in the field, then it goes.
* **No second store runtime**, and no attempt to make one work: see above.
