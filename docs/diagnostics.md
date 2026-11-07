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

"Next launch" is a property of the code, not a convenience: the bridge reads each of these once, at startup, and hands the value to the Go side, where the decision is made inside an `open()` or a download that is already in progress. Flipping a row does nothing to the run you are looking at. Every one of them logs which way the launch went, so a capture always says which shape it took — a switch that is silent when off cannot be told apart from a switch that was never read.

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

---

## The buttons

| Button | The question it answers | Notes |
| --- | --- | --- |
| Run SAP self test | Does the `probeapp` chain run on this device? | Synchronous once started; works before sign-in, because it never touches the account UI. Prints `SELF TEST PASSED` or `FAILED`; the buttons release after 120 s even if no report line arrives. |
| Run framework probe | Which frameworks can this process even load? | `dlopen`s the candidates and prints `[PROBE] <name> \| exists=… \| dlopen=OK \| symbols=n/m …`, then lists the private frameworks. Nothing here reaches the network. |
| Generate kbsync (Gate 0) | Can this device produce a kbsync blob at all? | The answer decides whether the download plan continues. **35–117 s of silence is normal** — see below. |
| Open Store runtime (E1-a) | Can the guest be opened and driven on this device? | Runs the same encode/execute the production download uses and prints the request, headers, response status and body head. Starts the heartbeat. |
| Fetch SAP assets (measure) | What does extraction cost *on this device*? | The same extraction CI runs. It asks go-macho for about 1.6 GB in one allocation during the export step, which is enough to end the process. Pressing it while a download is already waiting joins that run rather than starting a second 212 MB download. |
| Share log | — | Exports the whole window, not the displayed tail. Warns with `share log pressed with an empty log` if the record switch was off. |
| Clear log | — | Empties the buffer; the files under `Library/Caches` are untouched. |

**Generate kbsync** and **Open Store runtime** are the pair that has to be read together, and they are the reason "how long did that take" cannot be answered from the clock here. The generation itself prints nothing: it runs inside the already-open SAP machine, and the only lines in that package belong to opening the machine, not to the call. So a launch that generated a blob looks like a gap between `[SAP] ent input: …` and the first `open()` line. On device that gap has measured 35 s and 117 s. A later capture put `08:10:00` on the incoming request and `08:11:57` on the open with nothing in between, and 117 s of generation is a plausible reading — but silence is exactly what the one-second drain looks like, and nothing in the interval says when generation began or ended. What settles it is structural: `ent download: kbsync from disk (212 bytes)` at the point where the first capture fell silent, with no gap before the open. Two runs of the same flow, one generating and one reading a file — that is the difference the timestamps were being asked to show, and the line shows it without the clock.

Adding stamps inside generation is the open item that would make this readable rather than inferable.

---

## Reading a launch

The lines that say which shape a launch took, in the order they appear:

```
new version <x>: kbsync cache cleared              (or)  kbsync cache kept: version <x> unchanged
shared cache: pages will be mapped on demand       (or)  shared cache: mapped in full at open (switch off)
account switch: a second account reuses the runtime (probe)   (or)  … is refused until a restart
map census: mapping measurements will be logged    (or)  map census: off by switch, …
SAP runtime pre-warmed                             (or)  SAP pre-warm off by switch: …
```

The first is not a switch: the cached kbsync blobs under `Library/Caches/dlipa/kbsync-<dsid>.bin` are dropped when `CFBundleShortVersionString` changes, because a blob produced by an earlier build of the bridge is not something a new build should trust. It is keyed on the version rather than the CI run number deliberately — the run number changes on every push, and clearing on it cost the first download of each new build a regeneration measured at 117 s. A fresh install prints the cleared line too, because there is no stored version to compare against.

During a download, the useful ones:

```
[SAP] ent input: dsid=… storefront=… token=…ch/… cookies=… app=…
[SAP] ent download: kbsync from disk (212 bytes)
[SAP] ent download: store runtime opened
[SAP] sign: … bytes in, …, … emulation starts (… -> …), heap used …
[SAP] ent download: shared cache served 0 pages (0 KiB in 0 ms), 0 faults outside the blob, 0 failed, 9903 untouched
[SAP] ent download: response carries sinfs=1 metadata=1 md5=1
[SAP] ent download: cached kbsync kept (9610 answers about the account, not the blob)
[SAP] ent download: cached kbsync rejected (<code>), discarded
[SAP] patch ipa: rewrote com.toyopagroup.picaboo-14.31.1.0.ipa: 342 MiB, 2 of 2 entries new, 3.56s, 96 MiB/s
```

Two of those carry the numbers this project argues with. The served-pages line is the demand-paging bet reported honestly: on the signed download the guest asked for no pages at all, which is why indexing 9,903 of them in 336 ms beats mapping them for 32.8 s. The `patch ipa` line is the cost of writing the package back — measured at 772 MiB in 13.667 s (56 MiB/s) and 342 MiB in 4.046 s (85 MiB/s) — and when a package already carries everything the flow would inject, it says so and rewrites nothing:

```
[SAP] patch ipa: <file> already carries all <n> entries; nothing rewritten
```

That last one is the shape rather than a measurement: no device flow has yet re-patched a package that already carried the entries, so the short-circuit has never printed.

The kept/rejected pair is the blob cache policy. A failure about the account or the licence — `9610`, `5002`, `2042`, `2034`, `2002`, `signInRequired`, `passwordTokenExpired` — keeps the cached kbsync, because the blob did not cause it; an earlier build deleted the blob on those answers and turned a browse of the version history into a restart-only dead end. Anything else discards it, and `nothing was stored` marks the case where the failure hit a blob that was generated for this request, so there was nothing on disk to lose.
