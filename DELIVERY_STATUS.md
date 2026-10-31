# Status

Last rewritten 2026-10-31, at `d483713`. This page says what works today and what
does not. It is deliberately short and holds nothing that changes per build: for
the artifact, take the newest run of **Build iOS IPA** (Actions → the run →
`DLiPA-ipa`); for the build identity, the app prints `BuildID: build_commit=…` on
every launch.

## Works

- **Sign-in**, including 2FA, against the account's store pod
- **kbsync** and **request signing** — the SAP machine runs the pinned macOS
  binaries and produces both
- **Search** and version listing
- **Accounts**: add, switch, remove, and the persisted session state
- **Diagnostics**: the Store runtime smoke test, and signing again after it
  (the call sites it patches are restored on close)

## Does not work

- **Download.** Every request to the store's download endpoints is answered
  `2042 AuthTokenResumeFreeBuy`. Sign-in, cookies, headers, host and query have
  all been ruled out on device, including a request that copies ipatool's header
  set byte for byte. `PLAN-download-2042.md` has the evidence, the three
  remaining differences below the request, and the one experiment that would
  split the problem in two. **Read it before touching the download path.**
- **Store runtime** (the emulator that would let the app encode Store requests
  itself): it stops on a Swift type whose metadata the profile does not carry.
  The profile is generated from Apple's binaries on a macOS runner; that run
  never exercised the path which builds the type, so the page is zeroes.
- **Pre-warm crash.** Occasionally the app dies at launch with `Could not
  allocate dynamic translator buffer`. iOS fits one emulator, and pre-warm
  starts one while the process is still growing. Not part of the download
  problem; noted in the plan.

## Why the bundle is signed the way it is

The entitlements plist handed to `ldid` carries three keys, written whole rather
than assembled with `plutil -insert` (which validates values and rejects every
team identifier offered):

    application-identifier                    A23BC00001.com.a23bc.dliparebuild
    com.apple.developer.team-identifier       A23BC00001
    get-task-allow                            true

MobileInstallation types a bundle from a handful of identifying fields; without
`application-identifier` it types the app as System and the install fails with
181. No certificate is involved and none is needed — the team value is arbitrary
for a locally signed binary, because TrollStore rewrites it when it re-signs on
install.

## Where the rest lives

- `README.md` — how to build, install and sign
- `PLAN-download-2042.md` — open work, with the judgement criteria for each step
- `sapbridge/VERIFICATION.md` — how the Go side was verified
- `Archive/` — local notes; **not in version control**, so nothing that must
  survive a clone belongs there
