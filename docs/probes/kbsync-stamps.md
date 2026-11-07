# Probe: the kbsync step stamps

Branch `perf/kbsync-stamps` @ `6b64d9d`. Built as run 42346595022 (CFBundleVersion 486), package `a33dce4-DLiPARebuild-198483d1.ipa`, device logs `build/dl-ipa/486-generate.txt` and `build/dl-ipa/486-download.txt`.

**Status: local only.** PR #17 was opened against it, then left unmerged and closed out on 2026-11-07 by decision: this is instrumentation of the probe class, and a probe branch is not on the road to `main`. The remote ref was deleted the same day. What the numbers said is recorded here, which is the thing a reader actually needs; the code is kept because re-measuring costs one workflow dispatch.

The host-profile follow-up lives on `perf/kbsync-shim-profile`, stacked on this branch. Each branch carries its own note at `docs/probes/<branch-name>.md`, so this file is not on the other branch and that one is not here.

## What it adds

- `Machine.arm64Handled`, incremented at the compatibility layer's single call site in `invoke` -- the count of instructions this process executed in Go instead of letting the engine run them.
- `kbsyncMeasure` and the `kbsyncStep` wrapper: wall time, emulation starts and Go-emulated instructions per step, plus one total line. Unconditional, four lines per generation, no switch -- a generation is once per account per version, or one button press.
- Covers all three paths that generate: the download queue, the Gate 0 button, and the second-emulator path CI and the measurement commands use.

## What it decided

Two launches of the same build, two different flows -- Gate 0, then a real download with the account's cached blob deleted in Filza:

```
kbsync: storeagent global init in 32.06s   / 32.067s   (2223 starts, 2198 emulated in Go)
kbsync: generate in 363ms                  / 371ms     (1134 starts, 1132 emulated in Go)
kbsync: DSID 20825825307 generated 212 bytes in 32.423s / 32.439s
kbsync: storeagent global close in 103ms               (383 starts, 382 emulated in Go)
```

- **98.9% of a generation is the StoreAgent global init**, and that call takes the hardware block and the SC Info path and no DSID -- so the expensive part is not the account-specific part, and it is paid again for every account, every version bump and every button press.
- The counters were identical across the two flows while the wall time of the whole path moved 32.42 s to 32.44 s, and between this build and the next one the same step ran 32.06 s then 35.76 s with the counters unchanged. Counts are the invariant; seconds are the noise.
- What it could not decide, and why the profile branch exists: the split says *which* step costs, not *why* it costs. The answer to the why -- host handlers account for 2 ms of the 35.76 s, so it is Apple's arithmetic under TCI -- is in the sibling branch's file, and it is what closed the question.

## If this is ever re-run

```
gh workflow run build-ios.yml --ref perf/kbsync-stamps
```

Artifact `DLiPA-ipa`; name the package `{run number}-DLiPARebuild-{binary digest}.ipa`, the same form as `487-DLiPARebuild-7ace8f17.ipa`. Press **Generate kbsync (Gate 0)** -- that path always generates, so no blob has to be deleted first -- and expect the four lines between `kbsync gate: generating, this may take a while` and `kbsync OK: 212 bytes in N.Ns`.

## What would earn a place on `main`

Not the four lines on their own: with the question answered, they are instrumentation without a standing question, which is the same category as the census lines -- and those came with a switch and a documentation row before they stayed. If they come at all, they come as that shape: a diagnostics row, off by default, and a line in `docs/diagnostics.md` saying what is missing when it is off.

The piece worth arguing for is on the other branch and is not instrumentation: the dispatcher counters had their write side removed while the read side stayed, so `callreport_test` reports zero calls and cannot fail. See `docs/probes/kbsync-shim-profile.md` on `perf/kbsync-shim-profile`.

One correction from these runs, recorded because it invalidates a test that was designed here: the blob is not byte-stable -- `000400034443e153` at 486 and `0004000333f84969` at 487 for the same DSID -- so a StoreAgent global cached across accounts cannot be checked for account bleed by comparing blob bytes. That test has to be functional.
