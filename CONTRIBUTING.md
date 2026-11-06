# Contributing

Everything here is derived from a fork of an app whose source was never published, and the parts that work were arrived at by measuring on a real device. The notes below exist so the next person does not have to rediscover that.

## Read first

* [`README.md`](README.md) — what is broken upstream, what this rebuild does, how to install the artifact.
* [`docs/architecture.md`](docs/architecture.md) — how the pieces fit, and why each piece is shaped the way it is. It records decisions that were forced by specific failures; read it before changing the guest, the signer or the download path.
* [`DELIVERY_STATUS.md`](DELIVERY_STATUS.md) — what works today and the evidence.
* [`sapbridge/VERIFICATION.md`](sapbridge/VERIFICATION.md) — the Go build and test matrix.

## The constraint that shapes the whole workflow

Nobody here has a Mac. A Swift mistake costs a macOS archive round trip, which is six to eight minutes per attempt, and the archive is the only real compiler. So there are two check layers, and they are not interchangeable:

| | what it is | cost | runs |
| --- | --- | --- | --- |
| **Lint** | SwiftLint plus the iOS 15 API tripwire, on ubuntu | ~25 s | every push and every pull request |
| **Build iOS IPA** | the archive, on macOS | ~5 min | `workflow_dispatch` only, by hand |

Run the cheap one until it is green, then dispatch the expensive one.

```bash
gh workflow run build-ios.yml --ref <your-branch>
gh run watch <run-id> --exit-status --interval 20   # its exit code lies; confirm with gh run view --json
```

Artifacts are `DLiPA-ipa` (containing `DLiPARebuild-<digest>.ipa`) and `sapbridge-ios`. The digest in the name is a digest of the binary, which is the point: a stale copy cannot be mistaken for the current one. To tell a downloaded package apart from a guess, read `Payload/DLiPARebuild.app/BuildID.txt` inside it -- it carries `build_commit`, `build_run` and `build_time`.

## Checks that can run on any machine

```bash
bash scripts/check-ios15-apis.sh          # seconds; greps for post-iOS-15 API names
python scripts/check-bridging-header.py   # the header is hand-maintained; the Go side drifts
cd sapbridge && go vet ./... && go test -timeout 180s ./...
```

Those three run in git bash on Windows, which is why they are worth running before a push. SwiftLint itself has no Windows build, so it is the workflow's job; on a Linux machine or in a container:

```bash
swiftlint lint --config .swiftlint.yml app probeapp
```

The bridging header check exists because gomobile's c-archive mapping is not documented, and one mapping has never been proven on this device: a Go `bool` argument. Exported functions therefore take pointer-free value types and return errors through `NSError**`. Adding a `bool` parameter is not a style choice to argue about; it is an ABI question with no answer here.

The iOS 15 tripwire is a name list, not a type checker. It misses an iOS 17 argument added to a method that has existed since iOS 13, and it over-reports when one of those names belongs to this project. Silence a genuine false positive by putting `ios15-ok:` anywhere on the line.

## Commit messages

Enforced locally by commitlint (`subject-case: lower-case`, `header-max-length: 100`, `@commitlint/config-conventional`). CI does not check them, so read this before your first push. The config lives in the working tree only — `commitlint.config.js` and `.husky/` are not tracked, so a fresh clone has no hook and needs none of this to follow.

```
<type>[optional scope]: <subject, entirely lower-case>
```

* **The subject has no capital letters anywhere in it.** That rules out `SAP`, `Apple`, `MiB`, `iOS`, `IPA` and `kbsync`-is-fine-but-`KBSync`-is-not in the subject line. Proper nouns belong in the body. This is the rule that fails most often.
* Types are the config-conventional set (`feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`, `revert`). There is no `measure` type: measurement commits are `perf` or `chore` with the numbers in the body.
* Scope is the area, not the ticket: `emulator`, `app`, `sap`, `ci`, `assets`.
* The body says why, in prose, lower-case first word. It is where the numbers live: a performance or a behaviour change that ships without the measured before-and-after is very hard to defend six months later.

```
perf(emulator): map the shared cache on demand by default

device numbers: 99.3 s to open the store runtime with the cache mapped in full against 1.2 s indexed, and the two flows watched afterwards took no page from it at all.
```

## Line breaks

One paragraph per line, and let the renderer break it. That goes for commit bodies, pull request bodies and every markdown file here. A newline is reserved for what actually carries structure: a table row, the layout tree, a code block, a list item.

The reason is not aesthetic. A hard wrap survives one edit; the next edit has a different line length, so it gets reflowed by hand, and a one-word change lands as a diff over the whole paragraph. The commit body had the same problem and is why `body-max-line-length` and `footer-max-line-length` are off in `commitlint.config.js` — config-conventional defaults both to 100 columns. The header keeps its 100-character limit, because a subject is one line by definition.

## Branches, pull requests, verification

* One branch per subject, based on `main`: `perf/<subject>`, `fix/<subject>`, `chore/<subject>`, `docs/<subject>`.
* The pull request body has three parts (the template writes the skeleton): what changed, the criterion that says it worked, and what is knowingly left. If a change was measured and it did not help, that belongs in the body -- several levers here were killed by their own numbers, and a killed lever without a record comes back as a new idea.
* Nothing counts as verified until it ran on the device. Type checking and the Go suite prove code correctness, not feature correctness: the download path has twice looked healthy in the build log and failed a minute later inside the guest. Say which build you ran and paste the log lines that matter.

## Reproducing a device failure

Ask for the log before reading the code: Diagnostics -> the share button, or connect the device and read the stderr the app relays. Every launch begins with the five `BuildID:` lines, which is what makes a report attributable to a commit. `[SAP]` lines from the guest are relayed into the same log.

## Apple's binaries

The app downloads the four macOS 27 SAP binaries from Apple itself, on the device, after asking the user once (they are ~212 MB). No Apple binary is bundled, committed, hosted or attached to a release, and no PR should add one. `VendorAssets/` and `*.ipa` are ignored for that reason. If a change needs a different asset source, raise it as an issue before building it.

## Things not to do

* Do not open the engine at launch behind a new default. `uc_open` succeeds and the deferred init can fail to allocate the translator buffer, which ends the process with no exception and no crash report -- before the user sees a screen. That is why the store runtime opens on first use, and why pre-warm is a switch.
* Do not map the shared cache back in full without a device measurement saying the demand pager served pages that needed it.
* Do not force-push a branch that has a pull request, and do not commit under an `--no-verify` shortcut because the hook rejected a capital letter.
