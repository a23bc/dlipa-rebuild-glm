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

## Authenticating through a redirect

`authenticate` is addressed to the generic host and answered by a Store pod, and the pod is discovered from the redirect rather than known in advance. The upstream contract for that hop is explicit: a `Location` can be a full URL, a bare path, a protocol-relative host, or a query string, the **payload travels unchanged**, and the signature is recomputed for each destination.

Reaching it needed the redirect to arrive at our own code, and for as long as this app existed it did not: the session let URLSession follow redirects itself, and URLSession's policy for a 301 or 302 on a POST is to turn it into a **GET with no body**. So the first hop always landed on the pod broken. It worked anyway, by accident -- the pod answered that bodyless GET with a 404, the response URL named the pod, and the next attempt went there as a proper signed POST and got a 200. The comment in the initialiser said "redirects are handled manually" while nothing had switched off the automatic following, and the manual loop that had been written for exactly this job was unreachable.

What it leaned on was the pod's willingness to 404 a bodyless GET. When that stopped -- three device captures answered the same request with 204, 404 and 301 in one session, and the URL never moved -- authentication had no way to find the pod at all, and the failure surfaced as an unusable status with no diagnostic behind it.

Now the signed session refuses to follow (`NoAutoRedirectDelegate` hands `nil` to the redirect callback), and the loop owns every hop: same method and bytes, signature recomputed, credential headers dropped when the host changes, https and Apple hosts only, and a hop budget. The other session -- the bag and the classic endpoints -- keeps the automatic policy, because there following a CDN redirect is the behaviour that works.

Each hop the loop *refuses* is logged with the status, the Location (query stripped, because a Location's query can be a token), the response URL and the request URL. That is not decoration: `HTTP 301` cannot tell "Apple sent no Location" from "we could not resolve it" from "it left Apple's domain", and those three faults need three different fixes. 303 is deliberately not converted into a GET -- with automatic following gone it now reaches the caller as a 303, which is a visible failure, and no endpoint in this app is known to answer one.

Two things read out of the reference implementation while this was being checked, both worth stating because they change what a 204 means.

The first is that **a transient 204, 403, 404, 429 or 5xx from `authenticate` is expected traffic**: upstream retries exactly those statuses, with an exponential backoff and precedence for a `Retry-After` header, and it gives up only after its own attempt budget with the message "apple returned no usable authentication response; try again later or from another network". A 204 is therefore not evidence that our request is malformed -- it is evidence that the pod it landed on is not answering. The phrase "or from another network" is upstream telling its user where it thinks the fault lives.

The second is that upstream **isolates sign-in traffic from everything else**: the login client is a separate client with keep-alives disabled, its own dial timeout, and a deliberate comment that a login connection must not be shared with, or reused for, other Store operations. Redirects stay on that connection because only the URL changes -- the payload, and the signature recomputed over those same bytes at each `Send`, travel unchanged. This app cannot disable keep-alives: URLSession exposes no such switch, and the `Connection` header is one of the ones it refuses to send. What it *can* do is stop sharing, by giving the signed session a configuration of its own rather than the one the bag requests use. Whether the shared pool is what produced 204 then 404 then 301 for identical bytes on an unmoving URL is not measured, and it is the surviving explanation that a rollback cannot rule out -- so it stays a hypothesis with a name, not a fix that was applied.

So the question moved from "what do we send" to "where is it answered". The sending had already been checked: the clear-text wire log showed the six payload fields the reference client sends, the signature over exactly those bytes, the trailing slash, no cookie, and the hardware guid from the run that last signed in -- and the answer was still an empty 204, an HTML 404, or a 301 with no `Location`. That is where the endpoint probe comes from: the remaining question is answerable without a device and without credentials, using a body of the right shape carrying a probe address, a probe password, and no signature. Measured from this machine on 2026-11-10, the same unsigned POST repeated three times returned **404, then 204, then 301** -- and around it:

| Path | Same host, same minute, three attempts each |
| --- | --- |
| `MZFinance.woa/wa/authenticate/` | 404 html / 204 empty / 301 html, **no `Location` on any of them**, and 504 appears when the pod form is used |
| `MZFinance.woa/wa/logout` (sibling selector, same web application) | **200 with XML**, stable |
| `MZFinance.woa/wa/authorizeMachine`, `deauthorizeMachine`, `accountSummary` | **200 with XML**, stable |
| `MZBuy.woa/wa/buyProduct` | **200 with XML**, stable |
| `DownloadDispatch.woa/wa/ent/download` | 500 with XML, stable |
| 16 different pods, `p<N>-buy…/authenticate/` | 404, 204, 301, or a connect failure -- none returned XML |

The web application is up. The other selectors of the very same application answer with XML in the same second from the same connection pool. Only `authenticate` fails, and it fails differently on each try, which is what a routing condition looks like and not what a rejection looks like. It also means the earlier hope -- that a pod host would answer where the generic host refused -- is closed: every pod tried returns the same family, so there is no host to route to and nothing in our request to change.

The one behaviour change that follows from the instability: **a redirect that names no destination is now treated as transient**, alongside 204/403/404/429/5xx. It used to be a hard failure, and a hard failure on a request that had already returned three different codes in three seconds made a bad second into a failed sign-in.

Two things this does not explain, kept honest: the probe is unsigned, so it cannot show what a *signed* request gets from a healthy backend -- the device capture covers that, and it gets the same family; and the probe ran from one network, so it could not separate a global change from a regional one.

The second limit closed the same day, from the device itself. The probe was run three times over Wi-Fi and three times over cellular, nine authenticate attempts on each path, and the two lists are the same list:

| Network | Nine unsigned POSTs to `wa/authenticate/` | Sibling `wa/logout` | `ent/download` |
| --- | --- | --- | --- |
| Wi-Fi | 204, 301, 204, 503, 403, 500, 500, 403, 204 | **200 XML**, every press | 500 XML, every press |
| Cellular | 204, 404, 204, 403, 301, 204, 204, 301, 204 | **200 XML**, every press | 500 XML, every press |

Eighteen attempts, eighteen edge answers, no `Location` in any of them, no XML from that path once -- and the two networks disagree only about which edge codes appeared in the rotation, not about whether any of them reached the application. So the fault is neither the region, the route, nor the request: it is that this selector is not being handed to the application from anywhere we can reach, while its neighbours on the same host and in the same web application are. Nothing further in the app can change that, which is why the work stopped at the message that says so, and why the probe button is the instrument for the only remaining question -- whether and when it comes back.

What closed even that question is the upstream command-line client: it shipped its adaptation on **2026-11-08**, one day before this app began returning front-end codes for a byte-correct request. Its `storeauth` package produces the **anisette headers** locally -- `X-Apple-I-MD`, `X-Apple-I-MD-M`, `X-Apple-I-MD-RINFO`, `X-Apple-I-MD-LU`, `X-Apple-I-SRL-NO`, `X-Apple-I-Client-Time`, `X-Apple-I-TimeZone`, `X-Apple-Locale` -- from `gsa.apple.com`'s provisioning endpoints and, once it holds a provisioned state, from AppleMediaServices' type-2 flow plus the `com.apple.adid` service running inside its emulated runtimes. On store requests the same two values go out as **`X-Apple-AMD` / `X-Apple-AMD-M`**, persisted under `anisette-v4`, and the response carries a challenge pair: `X-Apple-AMD-Action` / `X-Apple-AMD-Data`, where `RP` means run the provisioning step and `SP` means run the kbsync step, then retry.

So the rotating edge codes were a missing header, and the header was about to become required. This app has an emulator for the same framework and the `setAnisetteType:` switch already present on its request builders -- but the switch is always passed `0`, "none", and the AuthKit challenge path is `panic("AuthKit anisette challenge is not supported")`. The fix is therefore neither routing nor retry policy: produce those headers here -- provision a device identity, run the anisette flow in the guest already open, map the pair onto store requests, honour the `RP`/`SP` challenge. The state it yields belongs in the keychain, which is where task #27 was already going to move the tokens and the blob.

No credential fault looks like any of this, and that is the sentence to keep in front of the next investigation: Apple states credential problems with HTTP 200 and a `failureType`, which is how 2034, 2002, 2083 and 9610 have always arrived here, and a signature problem is a 401 or 403 with a body to read. A 301 with no `Location` is upstream's own documented shape for a path that is no longer answered where it was asked -- and with nothing to follow, the pod that used to be discovered from the redirect cannot be discovered from this exchange at all. The endpoint and User-Agent overrides on the diagnostics tab stay, because they are how a future answer to "where did it go" gets tested without a build; the readings and the order they are worth trying in are in [`probes/developer-state.md`](probes/developer-state.md).

---

## Producing the anisette proof

The header is required; the open question is where the two values come from. There are two routes and they are not close in cost, so the choice is made by measurement rather than preference.

**Route 1 -- the device's own identity framework.** iOS ships `AppleDeviceIdentity`/`CoreADI`, and `AppleMediaServices` carries the anisette classes. If this process can load them and reach an entry point that returns the proof, the work is: provision (two HTTP calls to `gsa.apple.com`), request the pair, persist the state, attach the headers -- a few hundred lines, mostly Swift, no new emulated code, and no extra Apple binaries. What has to be measured first, and cannot be measured from the macOS side, is whether the sandbox lets those images load at all and whether the framework's service answers to a third-party app. The Diagnostics button *Probe the anisette entry points* prints exactly that: `dlopen=`, the C entry points found by `dlsym`, the classes whose names mention anisette/OTP/ADI and the selectors each one implements.

**Route 2 -- emulate the identity service**, the way the store framework is already emulated. The reference client took this route, and the size of it is measured, not estimated -- an earlier paragraph here said "roughly 1,900 lines across four files", which was a guess read off two file names and is wrong by more than a factor of two:

| Commit (2026-11-08) | Files | Added, excluding tests |
| --- | --- | --- |
| `fix: restore app store authentication locally` | 40 | **3,834** |
| `feat: discover storefronts dynamically` | 22 | 327 |
| `fix: handle authentication server dialogs` | 4 | 132 |
| `fix: support percent-encoded url component queries` | 2 | 5 |
| `fix: use current store request user agents` | 4 | 2 |

The largest single pieces are `modern_adi.go` at 662 lines and the platform shims at 1,274 added lines; `storeauth` itself is about 650. It opens **four concurrent emulated runtimes** -- the commerce image with pinned entry points at `+0x1b4400`, `+0x1d5124` and `+0x1dab04`; `adid` at base `0x200000000000`; `fairplayd` at `0x600000000000`; and `FairPlayIOKit` as a *kernel* image at `0x700000000510` with its own `kernelBase` -- and it stages **three more Apple binaries** from the same restore image: `adid` 9,797,952 bytes, `fairplayd` 37,689,264, `FairPlayIOKit` 2,132,320. That is 49.6 MB on top of the 212 MB already downloaded, each with a pinned digest.

Route 2 is the only option if Route 1 measures negative, and it carries a second cost this project has already argued about: four concurrent guests on a phone, where one runtime open measures 1.2 s, a generation step 32 s of full-core work, and the process reaches about 560 MB RSS today with a single runtime. If it comes to this, the memory and concurrency of the runtime pool get measured before the emulation is written, not after.

What makes Route 2 survivable rather than merely large: the reference client builds and runs on Windows as well, with its own Unicorn runtime fetched on demand (`internal/sap/unicorn/library_windows.go` and its `library_prepare_windows_*` siblings). So the same flow -- machine provisioning against `gsa.apple.com` and an OTP request, which involves **no Apple ID and no password at all** -- can be executed on this PC as a reference oracle: a known-correct header pair per identity, reproducible in seconds, against which the ported code can be tested before anything reaches the device. Without that, every question about the emulation costs a build and an install; with it, most of them cost a command.

**Common to both routes.** Whatever produces the pair, the rest does not depend on the answer: the machine-provisioning exchange with `gsa.apple.com` (`startMachineProvisioning` → `spim` → `finishMachineProvisioning` with `cpim` → `ptm`, `tk` and `X-Apple-I-MD-RINFO`), the plist envelope of an empty `Header` dict and a `Request` dict, the `akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0` user agent with the `<MacBookPro13,3> …` client-info header, the state that has to survive restarts, and the header set itself -- `X-Apple-I-MD`, `X-Apple-I-MD-M`, `X-Apple-I-MD-RINFO`, `X-Apple-I-MD-LU`, `X-Apple-I-SRL-NO`, `X-Apple-I-Client-Time`, `X-Apple-I-TimeZone`, `X-Apple-Locale`, `X-Mme-Device-Id`, `X-MMe-Client-Info` -- with the first two additionally mapped onto `X-Apple-AMD` / `X-Apple-AMD-M` for store requests.

And one requirement both routes inherit from the failure that produced this whole investigation: the identity state is per device, so it belongs in the keychain beside the password, not in the preferences file that an uninstall takes with it. The identifier that goes into the provisioning exchange is the device's; getting it wrong does not fail loudly, it yields a proof Apple refuses -- which is exactly the class of failure that cost four days here.

## The failure was never ours, and that is now on the record elsewhere

Two independent confirmations, found after the readings in this file were written.

The first is the version we depend on. `sapbridge/go.mod` requires `github.com/majd/ipatool/v2 v2.7.0` -- the release whose sign-in broke, and the same release the reference client fixed with the 3,834-line adaptation above. Our bridge is a trimmed copy of that lineage, so it inherited the breakage rather than causing it.

The second is upstream's own issue tracker, which reported our exact symptom on our exact date. Issue #642, opened 2026-11-06 against ipatool 2.7.0:

```
sign-in request failed: authentication request failed after 3 attempts (HTTP 204, 404, 204):
apple returned no usable authentication response; try again later or from another network:
unexpected response from Apple (HTTP 204): empty or non-plist authentication response
(body length=0, content type="")
```

`HTTP 204, 404, 204` in one session, empty body, no `Location` -- the same rotating edge answers that package 497 captured here and that the unsigned probe reproduced eighteen times on two networks. A second issue, #650 (2026-11-09), records the other half of the same change: the restore-image range requests began answering HTTP 403 to Go's default `User-Agent`, fixed by sending a real one -- which is why the User-Agent override on the diagnostics tab was worth keeping.

Two conclusions follow, and they are the reason the remaining work is a port rather than a hunt. The endpoint requirement changed server-side, so no amount of waiting, reinstalling, identity resetting, or reverting our binaries restores the old behaviour; and the fix is client-side emulation of the identity service, which the reference client has already written and shipped.

## Reading, 2026-11-10: route 1 measured negative on the device

Package 505 on the failing device, and the shape of the answer is worth writing down because it is not the shape people expect from a "framework not found":

| Image | mapped | dlopen | what is in it |
| --- | --- | --- | --- |
| `AppleDeviceIdentity` | NO | **FAIL, no such file at both dyld paths** | -- |
| `CoreADI` | NO | **FAIL, same** | -- |
| `AppleMediaServices` | **YES** (already in the process) | OK | 419 classes; `AMSAnisetteProvisionTask` with `performProvisioning :: @16@0:8`, `_startProvisioningWithOutputSessionID:error: :: @32@0:8^I16^@24` |
| `AuthKit` | **YES** | OK | `AKAnisetteData` with `routingInfo :: Q16@0:8`; `AKAnisetteProvisioningController` with `anisetteDataWithCompletion: :: v24@0:8@?16` and `fetchAnisetteDataAndProvisionIfNecessary:error: :: @28@0:8B16^@20` |
| `AOSKit` | NO | OK | **3 classes, none matching** |
| `StoreServices` | NO | OK | 385 classes, **0 matching** |
| `AppleIDAuthSupport` | YES | OK | 2 classes, 0 matching |
| every `adi_*` / `aos_anisette_*` C name | -- | -- | **0/11 in all four loadable images** |

The classes that do exist are the *client* half: `AKAnisetteProvisioningClientInterface` and `AKAnisetteProvisioningDaemonInterface` both report `methods=none`, because an XPC protocol stub has no implementations -- they describe a daemon, they do not run one. So the proof would have to come from a system service holding the device key, and the library that computes it is not present at any path. That closes route 1 in practice.

One measurement was deliberately not taken. The obvious next probe was to open an `NSXPCConnection` to the candidate services and report what came back -- but a key-value send to an unknown remote can raise an exception *on the remote*, and NSXPC delivers that back into the calling process, where Swift cannot catch it. A crash is not a price worth paying for one log line, and the two facts above (no identity library, stub interfaces only) already decide the route. If the port ever needs the daemon question re-asked, it has to be asked from a place that can survive a remote throw.


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
