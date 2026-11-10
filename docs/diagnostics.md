# Diagnostics

The failures in this app are not visible from the interface. The interesting work happens in Go, behind file descriptor 2, inside a CPU-emulated guest that runs for minutes on one core; from the outside a wrong turn and a slow one look identical. The Diagnostics tab exists to make those two distinguishable without a debugger, because nobody wants to attach one just to report a bug.

This document is the operator's reference for that tab: every switch, what it changes, when it takes effect and what you lose by turning it off; every button, and the question it answers. The meaning of the lines the switches produce is here too — including the ones that no longer appear by default.

For *why* the design is shaped this way, see [`architecture.md`](architecture.md); this file is about what you can press and what you can read.

---

## Where the log comes from

Two producers feed one window.

* **Swift** writes through `AppLog` (os_log plus an in-memory ring). Categories are `app`, `auth`, `sap`, `assets`, `network`, `download`; levels are debug, info, warn, error.
* **Go** writes to stderr with a `[SAP]` prefix. On launch, `StderrCapture` truncates `Library/Caches/dlipa-stderr.log`, reopens fd 2 onto it and tails it: a one-second timer reads the bytes appended since the last tick and pushes each line into `AppLog` as `.info` / `.sap`. The previous launch's file is dumped into the log at startup between the `===== PREVIOUS LAUNCH STDERR =====` markers, which is how a process that died mid-run still gets read.

Three consequences matter when reading a capture:

* **Timestamps are not a stopwatch.** The Go lines arrive in one-second batches, so lines that were written milliseconds apart can carry timestamps tens of seconds apart, and a batch boundary can fall anywhere inside the interval you are trying to measure. Read the log for *what happened*; read a phase stamp — `open(): phase … at …` — for *how long it took*.
* **The window holds 4,000 entries; the screen shows the last 400.** Rows above the window are replaced by `… N earlier entries omitted …`. **Share log** exports all 4,000, once, because that is a click and not a render.
* **With "Record log" off, the in-app window stays empty** — including the stderr drain. `os_log` still receives everything, so Console.app does not need the switch; the share-it-from-the-phone flow does.

---

## The switches

| Row | Default | Takes effect | Preference key |
| --- | --- | --- | --- |
| Record log | off in release, on in debug builds | immediately | `com.a23bc.dliparebuild.recordLog` |
| Open the SAP runtime at launch | off | next launch | `com.a23bc.dliparebuild.prewarmAtLaunch` |
| Map the shared cache on demand | **on** | next launch | `com.a23bc.dliparebuild.lazyCachePages` |
| Reuse one runtime across accounts | **on** | next launch | `com.a23bc.dliparebuild.accountReuseProbe` |
| Log the mapping measurements | off | next launch | `com.a23bc.dliparebuild.mappingCensus` |
| Generate kbsync when signing in | **on** | next sign-in | `com.a23bc.dliparebuild.pregenerateKBSync` |
| Developer state | off | immediately | `com.a23bc.dliparebuild.devState` |

"Next launch" is a property of the code, not a convenience: the bridge reads each of these once, at startup, and hands the value to the Go side, where the decision is made inside an `open()` or a download that is already in progress. Flipping a row does nothing to the run you are looking at. One row is read at the next sign-in instead, because that is where it applies. Every one of them logs which way the launch went, so a capture always says which shape it took — a switch that is silent when off cannot be told apart from a switch that was never read.

### Record log

On, every level reaches the buffer, including the debug lines that describe a request and its response. Off, the buffer records nothing. Release builds start at `.info`, so the detail that explains a failure is dropped before anyone can read it unless this is on: turn it on, reproduce, share.

It is not free. During a store-runtime open the guest writes tens of lines per second, and each one used to cost a copy of the whole window plus a re-render of the whole text; that is what made the interface unresponsive while the guest was running, and it is why the render is now throttled to one per quarter second, why the tail is read as rows rather than as one joined string, and why the loudest producer is behind the switch below. If the screen freezes with this on and does not freeze with it off, that is a bug in the log path, not a fact about the guest.

### Open the SAP runtime at launch

On, the SAP signer machine is built during startup, so the first download reuses a session that already exists. Off — the default — the engine opens on the first request that needs it.

The reason it is off by default is the risk, not the speed: opening the engine is the step that can end the process before a screen is drawn, and a launch that dies before the UI is unusable in a way a slow first download is not.

```
SAP runtime pre-warmed
SAP pre-warm off by switch: the engine opens on first use
SAP pre-warm skipped: bag carries no SAP configuration
```

### Map the shared cache on demand

Chooses the shape of the next store-runtime open: map all 38.8 MiB of the dyld shared cache up front, or index 9,903–9,927 pages and hand one over only when the guest touches it.

Device, both shapes: **99.3 s** to open with the cache mapped in full against **1.2 s** indexed, of which the indexing itself is 163–336 ms. The flow that pays for it afterwards is the ordinary signed download, which asked for **none** of the indexed pages:

```
ent download: shared cache served 0 pages (0 KiB in 0 ms), 0 faults outside the blob, 0 failed, 9903 untouched
```

On is the default because that is the measured shape; off is kept as the way back to what every earlier build shipped, and as the comparison case. The full argument — including why the eager configuration makes the *following* phase 490× slower — is in `architecture.md`, "Memory and time on device".

```
open(): indexed 9903 shared-cache pages in 3833 runs, 336 ms, mapped none (1631 dropped: inside a loaded image, 186130 instructions rewritten)
open(): mapped 9927 shared-cache pages in 3833 runs, 31056 ms (…)
```

Which of those two a launch printed tells you which shape it took; the served-pages line after the request tells you what it cost.

### Reuse one runtime across accounts

On, a download for a second signed-in account runs through the store runtime the first account opened. Off, it is refused with a message asking for a restart.

The machine that signs SAP requests is hardware-bound and account-free; the store guest is the part that carries state, and what it carries travels in the request instead: the per-account kbsync blob is resolved by DSID, the account object is created fresh for every request, and the encoder is told not to take cookies or storefront from the guest. Device, one launch: A, then B, then A again, three downloads served.

Nothing is closed to make this work, and that matters: closing is measured broken. The signature taken right after a `Close()` returned `-42306` — `x0=0xffff5abe`, `x1=0x1a24c39e4`, inside AppleMediaServices, with a null output pointer — both with and without releasing the address space, and a session opened afterwards died at the same heap address (`0x5000007fefb0`, in `setAccount:`) every time. A design that avoids the close is worth more here than one that repairs it.

```
account switch: a second account reuses the runtime (probe)
account switch: a second account is refused until a restart
ent download: reusing DSID <a>'s store runtime for DSID <b>
ent download: no cached kbsync for DSID <b> while its store session is open; …
```

The last line is the one shape reuse cannot serve: a second account whose kbsync blob has never been generated, with the first account's session still open. Generating it is forbidden while a store session is mapped, so the request refuses rather than corrupting the live guest. Sign in as that account and use it once on its own, and the blob is cached.

### Log the mapping measurements

Off by default. On, an `open()` prints the two instruments that measure the mapping itself. Both lines below are from a device capture of a demand-paged open, unedited:

```
  map census: 4 KiB at +128 MiB: n=23 total=14ms median=1ms worst=2ms
  region 0x1e7753000+0x3c8000 mapped per page (951 new, 2 maps, probe 2ms, map 1ms)
```

The first line is one cell of the map-cost census. Its two axes are the span of a single `uc_mem_map` call and how much the phase had already mapped when the call ran, in 16 MiB steps; each cell reports how many calls landed in it, and the total, median and worst time they took. Read a fixed span *down* the progress column: a median that grows means the price is the bookkeeping of what is already mapped, and mapping in a different order is the lever; a row that is flat and rises only with span means the price is bytes, and only mapping less helps.

That test was run, twice, at 4 MiB and at 1 MiB. The two agree: 176 calls over 73.6 MiB in 62.2 s, and 230 calls over 85.9 MiB in 65.8 s — 844 ms per MiB against 766. Chopping the same ground finer moved nothing but the call count, so the mapping price is about **0.8 s per MiB of newly mapped bytes**, and the cache-pages phase pays the same rate (38.8 MiB in 32.8 s). The whole of `open()` is ~125 MiB at that rate, which is its measured 99 s. That is why the default is off: the question these lines answer has an answer, it is recorded here and in the code, and it did not change the design.

The second line appears when a whole-range map fails and the range is filled page by page instead: pages mapped fresh, map calls, and the time spent probing versus mapping. It is the successor to the shape that cost minutes — one `uc_mem_map` per page, where a single 951-page region took 78 s.

Those two example numbers are what the census reports today, with the cache indexed rather than mapped: the same 951-page region is 3 ms end to end, and the heaviest cell in the capture is 14 ms across 23 calls. Turned on now, the instrument reads as confirmation rather than as diagnosis -- which is the right shape for a switch that defaults off, because the answer it re-prints is the one already recorded above.

Why the instrument survives the default: it is what killed three speculative levers — chunking the region phase into 4 MiB pieces (37.5 s against 38.3 s, nothing), a 1 MiB split (worse, reverted), and a per-page map on the sparse profile (the 78 s above) — and it is what found the coupling between the region phase and the shared cache. The demand-paged run maps *more* regions (193 against 170) and finished the phase in 127 ms instead of 62.1 s, so neither the count nor the bytes in the region set can account for a 490-fold gap; what differs, by 38.8 MiB, is the cache already in the address space. A measurement nobody can switch back on is a measurement that gets guessed at again.

Turning this on costs log volume, not time. Counted on device, on two launches of the same build: the open's own second holds **118 lines with the census on, 89 of them these two prints**, and **38 lines with it off** — and the region phase measured 105 ms off against 100 ms on, which is inside noise. Turning it off costs only the breakdown: the summary that survives is `open(): 193 regions mapped in 105ms`, so the phase still has a number, without the per-cell shape that explains it.

### Generate kbsync when signing in

On, a finished sign-in immediately asks the guest for that account's kbsync blob, instead of leaving that work for the first download to discover.

The reason is a measurement, not a hunch. The stamps say a generation costs 32.4 s of which **32.06 s is the `storeagent global init` step** — a call that takes the hardware block and the SC Info path and *no DSID* — while the part that is actually about the account, `generate`, costs 371 ms. So the expensive half is not the per-account half, and the moment to pay it is the one where nobody is waiting on a result: sign-in has just proved the person means to download something, and the signer's machine is already open by then.

Off puts that 32 s back in front of a progress bar, once per account per format version. It is on the page because paying 32 s of full-core work at sign-in is a real cost on a warm device, and because signing into an account one never downloads from buys nothing.

Two rules decide what actually happens, and both announce themselves:

* a download already in flight skips the pre-generation, because generating against a mapped store session is the failure this project calls e3;
* the work runs off the main thread, because an emulated guest holding the screen thread is indistinguishable from a hang — which is the same reason the store-smoke button starts a heartbeat.

```
kbsync pre-generated at sign-in: 212 bytes in 32.4s
kbsync pre-generation off by switch: the first download pays it
kbsync pre-generation skipped: a download is in flight (e3)
kbsync pre-generation failed, the first download will generate: <error>
```

The last is not a failed sign-in. The download path generates for itself and reports there, where a result is already being waited on, so a pre-generation that dies costs only the retry.

### Developer state

Development scaffolding, off by default, and the only switch here that writes nothing about itself at launch: it is read live, so turning it on and reproducing happen in the same run.

It exists because of a specific dead end. `authenticate` answers 301, 204 and 404 inside one session, and rolling the app back to earlier builds — the one that introduced demand paging, the one that introduced the pre-warm — changes nothing. Persistent state that outlives the binary is the only explanation that survives a rollback, and this app has four of them: keychain items, the shared `HTTPCookieStorage` (which on iOS is itself stored in the keychain and survives a reinstall), the app's preferences, and the kbsync blobs under `Library/Caches/dlipa`. So the question is not *which* of them is wrong but **what is actually in them, and does what a request takes from them match what the endpoint expects** — which is answerable only by looking.

Two things change when it is on:

**Every signed request and response is logged whole**, header values and bodies in clear text. The status line says what came back; these say what was carried, and a 301 whose `Location` is missing, whose `Location` points somewhere unexpected, and whose `Location` this client refused are three faults the status line cannot separate:

```
wire out POST https://buy.itunes.apple.com/…/authenticate/ | Cookie=…, X-Apple-ActionSignature=…, … | body <the plist>
wire in 301 https://buy.itunes.apple.com/…/authenticate/ | Location=…, Content-Type=…, … | body <html>
```

The redaction that the other lines carry — credential values replaced by their length, the `Location` stripped of its query — is deliberately not applied here. During development the state on the wire is the thing under investigation; `docs/probes/developer-state.md` says what has to happen before a release build is ever cut.

**The persisted stores can be read and changed.** *Dump persisted state to the log* writes one block:

```
===== DEV STATE BEGIN =====
keychain: 3 item(s)
  [generic password, data-protection] service=com.a23bc.dliparebuild account=… value=…
cookies in the shared jar: 2
  itunes.apple.com X-Token=… (path /, expires …)
preferences: 8 key(s)
  com.a23bc.dliparebuild.accounts = dict …
  caches/dlipa kbsync-v1-20825825307.bin (212 bytes)
===== DEV STATE END =====
```

*List keychain items* puts a row per item on the page instead, each with the shape that found it — an item written through the data-protection keychain is invisible to a query that does not ask for it, so one unflagged pass would report "empty" and send the search in the wrong direction. `Set` writes a chosen value into that slot (or creates it) and `Delete` removes it; both answer with the OSStatus, because "deleted" and "there was nothing to delete" are different facts and a silent delete is how an item a query could not see keeps hiding. The point is to be able to empty the password slot, or fill it with a known-wrong value, and see whether the 2034 auto-relogin path is what sends an authenticate request nobody asked for.

*Delete every cookie* clears the shared jar — the one store this app does not own and cannot show in a preference row.

**Overrides in force** reaches past the stores and changes the request itself: a typed authenticate endpoint and a typed `User-Agent`, each restored to the built-in value by setting it with an empty field. This exists because of what the wire log showed — a well-formed request answered by an HTML 404, an empty 204 and a 301 that carries **no `Location` at all**. With no redirect to follow there is nothing to discover the pod from, so the remaining questions are about where the request lands, and every host is then one sign-in rather than one build. Whatever is in force is printed on the row, named in the log on the request that uses it (`authenticate endpoint overridden for development: …`), and included in a dump, so a capture always says which shape produced it.

Two more controls exist for the case where the row to be changed does not exist yet. Turning the switch on logs a warning first — *developer state on: the log now carries credentials in clear text, including the sign-in password* — because what it unlocks is a log that holds the Apple ID password, and the share button sits two rows below it. And *write the password slot* creates the keychain item a successful sign-in would create, through the same call and with the same accessibility attribute: without it, the 2034 refresh path cannot be driven at all while sign-in itself is broken, since a sign-in is the only thing that ever writes that row.

### An upgrade no longer discards the blobs

Not a switch, but it belongs with the switches because it used to be one, and because the reason for the row above is the same reason this changed.

Until now, a launch that saw a different `CFBundleShortVersionString` deleted every cached blob. That conflated shipping a build with shipping a bridge whose guest assumptions changed — and only the second is a reason to throw a blob away, since the first costs each account 32 s at its next download.

Retirement now happens two ways, both narrower: the stored file name carries a blob format version (`kbsync-v1-<dsid>.bin`), so changing what a blob has to be and moving that constant makes every old one retire by missing; and a blob Apple refuses is dropped by the answer that refused it, classified by what the refusal was about — an account or licence answer keeps the blob, because the blob did not cause it. A stored file whose name carries no version is not read, and is deleted on the way past, because credential material nothing reads should not sit in the container.

```
kbsync cache: blobs kept across the upgrade
[SAP] ent download: dropped the un-versioned kbsync file for DSID <n>
[SAP] ent download: cached kbsync kept (9610 answers about the account, not the blob)
[SAP] ent download: cached kbsync rejected (<code>), discarded
```

---

## The buttons

| Button | The question it answers | Notes |
| --- | --- | --- |
| Run SAP self test | Does the `probeapp` chain run on this device? | Synchronous once started; works before sign-in, because it never touches the account UI. Prints `SELF TEST PASSED` or `FAILED`; the buttons release after 120 s even if no report line arrives. |
| Run framework probe | Which frameworks can this process even load? | `dlopen`s the candidates and prints `[PROBE] <name> \| exists=… \| dlopen=OK \| symbols=n/m …`, then lists the private frameworks. Nothing here reaches the network. |
| Generate kbsync (Gate 0) | Can this device produce a kbsync blob at all? | The answer decides whether the download plan continues. **35–117 s is normal**, and the step stamps below say where it goes. |
| Open Store runtime (E1-a) | Can the guest be opened and driven on this device? | Runs the same encode/execute the production download uses and prints the request, headers, response status and body head. Starts the heartbeat. |
| Fetch SAP assets (measure) | What does extraction cost *on this device*? | The same extraction CI runs. It asks go-macho for about 1.6 GB in one allocation during the export step, which is enough to end the process. Pressing it while a download is already waiting joins that run rather than starting a second 212 MB download. |
| Probe the authentication endpoint | Is the sign-in path answering at all, from here, right now? | Five **unsigned** requests — a body of the right shape with a probe address, a probe password, no signature — three at `authenticate`, one at a sibling selector of the same web application, one at the download endpoint. Prints `endpoint probe <what> -> HTTP <code>, <content-type>, <Location or "no Location">, <body>`. The comparison is the point: `authenticate` returning 404/204/301 while `logout` and `buyProduct` return 200 with XML from the same host in the same second says the fault is the route to that one selector, not the credentials and not the host. |
| Share log | — | Exports the whole window, not the displayed tail. Warns with `share log pressed with an empty log` if the record switch was off. |
| Clear log | — | Empties the buffer; the files under `Library/Caches` are untouched. |

**Generate kbsync** and **Open Store runtime** are the pair that has to be read together, and they are the reason "how long did that take" could not be answered from the clock here. Generation used to print nothing at all: it runs inside the already-open SAP machine, and the only lines in that package belonged to opening the machine, not to the call. So a launch that generated a blob looked like a gap between `[SAP] ent input: …` and the first `open()` line. On device that gap has measured 35 s and 117 s. A capture put `08:10:00` on the incoming request and `08:11:57` on the open with nothing in between, and 117 s of generation is a plausible reading — but silence is exactly what the one-second drain looks like, and nothing in the interval said when generation began or ended. What settled that case was structural: `ent download: kbsync from disk (212 bytes)` at the point where the earlier capture fell silent, with no gap before the open. Two runs of the same flow, one generating and one reading a file — that is the difference the timestamps were being asked to show, and the line shows it without the clock.

The gap itself now stamps its own shape, one line per step plus the total. These are device numbers, from two launches of the same build on two flows — the Gate 0 button, then a real download with the account's cached blob deleted — and the counters matched exactly between them:

```
[SAP] kbsync: storeagent global init in 32.06s (2223 emulation starts, 2198 instructions emulated in Go)
[SAP] kbsync: generate in 363ms (1134 emulation starts, 1132 instructions emulated in Go)
[SAP] kbsync: DSID 20825825307 generated 212 bytes in 32.423s (init and generate)
[SAP] kbsync: storeagent global close in 103ms (383 emulation starts, 382 instructions emulated in Go)
```

**98.9% of a generation is the storeagent global init** — 32.06 s of 32.42 s — and that call takes the hardware block and the SC Info path and *no DSID*. The step that is actually about the account costs 371 ms. That is the whole argument for the sign-in row above, and the whole reason the row defaults on.

Read the two counters together, because the wall time alone cannot separate the two ways this costs money. `emulation starts` is how often the engine had to be entered, each run bounded at 20,000,000 instructions, and every instruction the compatibility layer handles also costs a start — so a small count means the engine ran a lot of Apple's code and nothing was interpreted in Go. `instructions emulated in Go` is the compatibility layer's own work: `eor3`, `svc`, the paired `casp` in the crypto loops, each one executed by this process between engine restarts. On device the two counters are equal to within 25 in the init step and 2 in the generate step, so nearly every restart ends at a compatibility stop — and yet one start costs 14.4 ms in init against 0.32 ms in generate, which is why making the restarts rarer cannot buy the 32 s back: the time is the work between the stops. The threads fact is worth knowing too, because it is where a "fix" would have gone: that path exhausted the process's threads once (`qemu_thread_create: Resource temporarily unavailable` at `0x18088a368`, a `casp` inside a crypto loop) and a handler that failed to advance the program counter hung for five minutes printing nothing.

What these lines cannot say is *why* 32 s of engine work is 32 s. The next instrument asks the host what the guest was calling while it ran, and that line is not in this build; when it is, it appears under each step as `kbsync <step> asked the host: …`.

---

## Reading a launch

The lines that say which shape a launch took, in the order they appear:

```
kbsync cache: blobs kept across the upgrade
shared cache: pages will be mapped on demand       (or)  shared cache: mapped in full at open (switch off)
account switch: a second account reuses the runtime (probe)   (or)  … is refused until a restart
map census: mapping measurements will be logged    (or)  map census: off by switch, …
SAP runtime pre-warmed                             (or)  SAP pre-warm off by switch: …
```

At each sign-in, one more line says whether that account's blob was generated there: `kbsync pre-generated at sign-in: …`, `… off by switch: …`, or `… skipped: a download is in flight (e3)`.

The first line is not a switch, and it replaced one. The cached blobs under `Library/Caches/dlipa/kbsync-v1-<dsid>.bin` used to be deleted by any launch whose `CFBundleShortVersionString` differed, which made the first download of every new build pay a regeneration — measured at 32 s, and once at 117 s. See "An upgrade no longer discards the blobs" above for what retires a blob now.

At sign-in, the lines that say what Apple actually answered:

```
authenticate request to <url> headers: Content-Type=…, User-Agent=…
signed request to <url> returned 204, request 461 bytes, response 0 bytes
not following redirect: HTTP 301, no Location header, location none, response url …, request url …
authenticate ended with HTTP 204 and 0 bytes after 3 request tries, none of which produced a body
sign-in failed: the store answered with no content (HTTP 204); sign in again
sign-in failed: the request was answered by Apple's front end, not by the store (HTTP 301, text/html, 162 bytes). This is not your password: a credential problem arrives as HTTP 200 with a failureType.
```

The last line is the one that changed on 2026-11-10. A non-2xx used to paste up to 200 characters of whatever Apple sent into the message, which is right for a plist (the `failureType` and `customerMessage` are the answer) and wrong for an edge page, where the HTML repeats the status code and hides the fact that the request never reached the application. An HTML body now produces the sentence above instead.

The second and third are the pair that turns a mystery into a fact. `request N bytes, response M bytes` used to be one word -- `body N bytes` -- which read as though a 204 had answered with 461 bytes of content when the number was the size of what we sent. And `not following redirect` names which of the three faults a 301 was: no `Location` at all, one that could not be resolved as https, or one that left Apple's domain. The destination is written without its query, because a `Location` is allowed to carry a token there and this log gets shared.

With **Developer state** on, the same exchanges appear again as `wire out` / `wire in` pairs with every header value and both bodies in clear text, un-redacted on purpose -- see that switch above.

During a download, the useful ones:

```
[SAP] ent input: dsid=… storefront=… token=…ch cookies=… app=…
[SAP] ent download: kbsync from disk (212 bytes)
[SAP] ent download: store runtime opened
[SAP] sign: … bytes in, …, … emulation starts (… -> …), heap used …
[SAP] ent download: shared cache served 0 pages (0 KiB in 0 ms), 0 faults outside the blob, 0 failed, 9903 untouched
[SAP] ent download: response carries sinfs=1 metadata=1 md5=1
[SAP] ent download: cached kbsync kept (9610 answers about the account, not the blob)
[SAP] ent download: cached kbsync rejected (<code>), discarded
[SAP] patch ipa: rewrote com.toyopagroup.picaboo-14.31.1.0.ipa: 342 MiB, 2 of 2 entries new, 3.56s, 96 MiB/s
```

The `kbsync from disk` line above is the cached case; a run that has to generate prints the `kbsync:` step stamps in its place, and the two together are what separates a 35 s download from a 117 s one without asking the clock.

Two of those carry the numbers this project argues with. The served-pages line is the demand-paging bet reported honestly: on the signed download the guest asked for no pages at all, which is why indexing 9,903 of them in 336 ms beats mapping them for 32.8 s. The `patch ipa` line is the cost of writing the package back — measured at 772 MiB in 13.667 s (56 MiB/s), 342 MiB in 4.046 s (85 MiB/s), and the same 342 MiB again at 3.56 s and at 5.418 s (96 MiB/s and 63 MiB/s), which is why the rate is written as a range here rather than as a constant — and when a package already carries everything the flow would inject, it says so and rewrites nothing:

```
[SAP] patch ipa: <file> already carries all <n> entries; nothing rewritten
```

That last one is the shape rather than a measurement: no device flow has yet re-patched a package that already carried the entries, so the short-circuit has never printed.

The kept/rejected pair is the blob cache policy. A failure about the account or the licence — `9610`, `5002`, `2042`, `2034`, `2002`, `signInRequired`, `passwordTokenExpired` — keeps the cached kbsync, because the blob did not cause it; an earlier build deleted the blob on those answers and turned a browse of the version history into a restart-only dead end. Anything else discards it, and `nothing was stored` marks the case where the failure hit a blob that was generated for this request, so there was nothing on disk to lose.
