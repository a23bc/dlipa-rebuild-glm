# Releasing

What a build carries, what the numbers in it mean, and which of them anything
actually reads.

---

## Version fields

| Field | Source | Meaning |
|---|---|---|
| `MARKETING_VERSION` | `app/project.yml`, edited by hand | the release number |
| `CURRENT_PROJECT_VERSION` | `github.run_number`, passed to `xcodebuild` | build identity |

`MARKETING_VERSION` stays a decision. Nothing bumps it automatically, and the
rebuild has not settled whether it continues upstream DLiPA's numbering — which is
the same reason there is no `CHANGELOG.md` yet.

`CURRENT_PROJECT_VERSION` used to matter at runtime: the kbsync cache was cleared
by `CFBundleVersion + "/" + CFBundleShortVersionString`, and since the bundle
version is the CI run number, every new build threw the blob away and paid for a
regeneration before its first download. The app now compares
`CFBundleShortVersionString` alone. The field still changes on every run and
still appears in the bundle; nothing reads it.

## The artifact

`DLiPARebuild-<digest>.ipa`, where `<digest>` is the first 8 hex characters of the
**sha256 of the executable inside the bundle** — a digest of the file, not of the
commit. That is what the name is for: a copy downloaded from an earlier run cannot
be mistaken for the current build, because it is a different binary.

`Payload/DLiPARebuild.app/BuildID.txt` is the file that answers "which commit is
this". The workflow writes it, and the app logs its contents at launch. Use it
instead of probing the Mach-O for strings: Swift merges string literals, so a
build can lack a probe string it logically contains.

## Signing and install

The workflow builds with `CODE_SIGNING_ALLOWED=NO` and then seals the executable
with `ldid` and a fixed entitlement set — `get-task-allow`, `allow-jit`,
`allow-unsigned-executable-memory`, `disable-library-validation`,
`private.cs.debugger`, `kernel.increased-memory-limit`. There is no certificate
and no provisioning profile inside the IPA.

TrollStore installs that bundle as it stands, entitlements included. A tool that
re-signs with an Apple ID replaces the set with whatever the profile allows, and
the app has not been tested under the resulting memory and debugging limits; the
README offers AltStore and Sideloadly, but that is a statement about the install
path rather than a measurement of this app under a re-signed entitlement set.

## What must not be published

The four Apple binaries the signer needs are fetched from Apple on the device and
are never bundled, committed or attached to a release — see the asset gate in
`README.md` and the reasoning in `NOTICE`.
