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
