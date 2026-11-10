# Probe: the anisette proof, off-device

Branch: `feat/anisette-login`. Workflow: `Probe anisette proof (Linux)`
(`.github/workflows/probe-anisette.yml`), test `sapbridge/anisette_live_test.go`.

## What it asks

Whether the merged anisette line produces the headers Apple answers the
sign-in with, on a host that can actually run the emulator. Three sub-questions,
each with its own criterion in the log:

| question | criterion |
| --- | --- |
| does our own v4 extractor finish on a fresh cache | `assets:` line reports transferred bytes, requests and peak heap |
| does the ADI machine provision and prove | ten `X-Apple-I-*` / `X-Mme-*` headers, then a replay from persisted state that keeps `X-Mme-Device-Id` and changes `X-Apple-I-MD` |
| does the store runtime still sign after the hook-table merge | signature decodes to ~668 bytes for the 461-byte body, the count device run 497 measured |

Nothing here needs an Apple ID. The identity is a random sixteen-byte value
given to gsa's public `startMachineProvisioning` / `finishMachineProvisioning`.

## Why a probe at all, when Windows already produced the headers

Because the Windows reading came from **upstream's** binary, not from this
repository. Our bridge refuses Windows outright
(`sapbridge/internal/sap/unicorn/library_windows.go`: `unicorn is not available
on windows; build for darwin, ios or linux`) — the emulator arrives through
purego, so a Windows host can compile the merge and nothing more. Linux with
the pinned stock library is the cheapest host that can go past the compiler.

## Numbers established before this probe runs

From the reference client on this machine (Windows x64, go1.27.3, Unicorn
2.1.4, JIT/TCG):

* cold asset resolution **10m6s**; warm **7s** end to end for the whole proof;
* with our own extractor, on the same machine and the same seven pieces:
  **6m16s**, **174,733,872 bytes produced**;
* instrumented (this repository's `measure`, which replaces
  `http.DefaultTransport`): **297.2 MiB in 6191 requests** (mean 49.2 KiB,
  largest 1021.4 KiB), **peak heap 721.6 MiB**, `allocated 16.8 GiB`, and
  **26m20s** for the same work that took 6m16s unmeasured.

That last pair is the reason the elapsed figures need care: `measure.sampleHeap`
calls `runtime.ReadMemStats` from a 5 ms ticker, and `ReadMemStats` stops the
whole process. The byte and request counts are trustworthy because they come
from a body reader; the elapsed time is inflated roughly fourfold on this host.
It also means the device figure quoted in `sapbridge/assets.go` — "211.7 MiB
over 457 range requests in 52 seconds" — carries the same instrument cost, so
its byte counts stand and its seconds do not compare with anything unmeasured.

Read the probe the same way: treat its timing as an upper bound that includes
the instrument, and its header and byte counts as the answer.

## What the linux run named

The cost behind the three minutes is not Apple's arithmetic. Counting every
host service the guest entered while the modern ADI daemon initialised:

| `initializeDaemon` | wall | busiest symbol |
| --- | --- | --- |
| before | 3m0.001s | `_CFRunLoopRun`, 39,645,456 entries of 40,141,810 starts |
| after | 44ms | `_arc4random`, 5 entries |

adid installs its XPC event handler and then calls `CFRunLoopRun`, which is the
guest saying "park me". Our shim does stop the engine, but Unicorn reports a
stopped run and an exhausted instruction chunk the same way -- no error, and a
queryable reason only for timeouts -- so `invoke` read the park as "chunk ran
out", resumed at the same address, and re-fired the same shim forever until
`sapGuestTimeout` (3m) ended it. The deadline error never surfaced, because
`initializeDaemon` reports one only when no handler was installed, so the whole
loop presented as a slow daemon. `Machine.invoke` now checks the park flag
before restarting.

Why this matters more on the phone than here: the spin was 4.5 microseconds per
entry with JIT acceleration, it is dead time in either mode, and the TCI build
pays more per restart, not less.

Two network conditions, both host-side, stop that run from reaching the headers
here -- neither is the emulation:

* `https://www.apple.com/appleca/AppleIncRootCertificate.cer`, which the
  provisioning fallback downloads, answers **403 to every client from this
  network** -- `curl` on Windows and in WSL alike, while `https://www.apple.com/`
  itself gives 200. This is the CN-facing edge refusing the certificate paths.
* This WSL distribution's trust store contains **no Apple certificate at all**
  (`openssl crl2pkcs7` over `/etc/ssl/certs/ca-certificates.crt` prints zero),
  so `gsa.apple.com`'s chain, which is rooted at Apple Root CA, fails
  verification first and is what sends the code to that 403 download.

Earlier warm runs of the same proof printed all ten headers, so at least one of
those two conditions changed since; which one is not established here. A GitHub
runner has both a complete `ca-certificates` bundle and non-CN egress, so the
header-level proof of this fix belongs in this job's log, not on this machine.

## What is still owed after a green run

* **Timing on the phone.** The device runs the no-JIT TCI build (iOS refuses
  executable anonymous memory for an un-jailbroken app), so its emulator cost
  is a different quantity from anything this job measures. Use the existing
  stamps (`sapbridge/internal/sap/machine/callcounts.go`,
  `Machine.TraceCalls`) rather than new instrumentation.
* **Peak heap for the fetch.** 721.6 MiB here, against a process that jetsams
  near 215 MB resident today. Tracked as "v4 抓取上设备前先降峰值堆与请求数".
* **The staged four-file route.** `readBundleDir` still reads four binaries and
  `scripts/export-sap-assets.go` still exports four, while the loader validates
  seven. Builds that stage assets fail validation with `adid is empty or
  missing`; the normal build, which stages nothing, is unaffected. Also
  `AssetStaging.totalBytes = 125_000_000` and the consent wording still describe
  the four-piece profile.
