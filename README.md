# DLiPA — SAP-adapted rebuild

DLiPA stopped working because Apple now requires App Store private-API requests
to carry an `X-Apple-ActionSignature` header, and because the download endpoint
advertised in `bag.xml` moved to `ent/download`. This repository rebuilds the
app with both changes, and builds an installable IPA on GitHub Actions.

**Current state:** sign-in, kbsync, signing, search, account handling, version
history and **download** all work on device. The download no longer goes through
the classic `volumeStoreDownloadProduct` request — the Store's own code builds the
`ent/download` request inside an emulated guest, which is what Apple now requires
and what this project spent most of its effort arriving at. See
[`docs/architecture.md`](docs/architecture.md) for how that works and why each
piece is shaped the way it is.

Downloads run in the background: starting one returns immediately, progress is on
the Downloads tab, and the app stays usable while the emulated Store runtime
works — seconds, now that the shared cache is indexed and mapped on demand
rather than mapped in full at every open.

**No Apple Developer account is required.** The IPA is sealed but not signed with a certificate, and you
sign it with your own Apple ID using AltStore or Sideloadly — the same flow the
original DLiPA README recommended.

---

## What was wrong, and what changed

| Problem | Evidence | Fix here |
|---|---|---|
| Requests were unsigned | Signed request → HTTP 200 + session cookie; unsigned → **HTTP 403** | `sapbridge` signs every body |
| authenticate URL lacked a trailing slash | Without it Apple answers **HTTP 204** empty; with it, HTTP 200 | `AppStoreClient.authenticate` appends `/` |
| The classic download request was refused | `volumeStoreDownloadProduct` answers **2042** (`AuthTokenResumeFreeBuy`), and its `buyProduct` fallback answers `MZCommerce.SystemError` | the request is no longer built by hand: the Store's own encoder builds it inside the emulated guest |
| That request was signed but still refused | 500 with an empty body, through five field-level attempts | `Content-Type: x-www-form-urlencoded`, `User-Agent: Configurator/2.18`, the **session cookies**, `salableAdamId` as a *string*, and a non-empty `externalVersionId` |
| No kbsync blob | `ent/download` binds the download to account and device through kbsync | `internal/sap/ent_fetch.go` generates it *before* the runtime opens |
| guid was a random UUID | `ent/download` requires a 6-byte GUID | `HardwareIdentity.stable()` |
| dsid was a string | `ent/download` requires a decimal DSID | `SAPSigner.parseDSID` |

The controlled experiment behind the first two rows is in
`../SIGNATURE_EXPERIMENT.md`.

---

## Layout

    app/                        Xcode project (XcodeGen) + Swift sources
      project.yml               target DLiPARebuild, iOS 15, name auto-picked
      DLiPARebuild/
        DLiPA-Bridging-Header.h  hand-written declarations for the Go archive
        Networking/
          AppStoreClient.swift   signed transport, bag, login, download
          StoreBag.swift         bag.xml parsing (handles loc- prefix)
          SAPSigner.swift        wraps the Go bridge
          AssetStaging.swift     copies the 126 MB assets out of the bundle
        Model/
          AppSession.swift       session, account, the download primitive
          DownloadManager.swift  jobs that outlive the screen that started them
          StoreApp.swift         catalogue entry
        UI/
          SearchScreen.swift     search, download, version sheet
          VersionListView.swift  version ids, tap to download that build
          DownloadsScreen.swift  running and finished downloads, one list
          AccountsScreen.swift  SettingsScreen.swift  DiagnosticsScreen.swift
        Logging/
          StderrCapture.swift    previous launch's stderr, shareable from the app
    sapbridge/                  Go module
      sapbridge.go              Sign / KBSync / StoreSmoke / EntDownload (bridge)
      internal/sap/
        signer_local.go         the machine, the session, one store runtime
        ent_fetch.go            production ent/download through the encoder
        store_smoke.go          the diagnostic probe (E1-E4 live here first)
        machine/ machimage/     the arm64 guest and the Mach-O loader
      internal/store/
        emulator/               Store runtime: mapping, hooks, encoder, Execute
        profile/ cachepages/    recorded pages, and the dyld cache slice
    scripts/
      check-bridging-header.py  generated header vs the hand-written one
      build-unicorn-ios.sh      cross-compiles Unicorn TCI
      package-ipa.sh            sealed .app -> .ipa
    docs/architecture.md        how the pieces fit and why
    VendorAssets/               extraction output of the Fetch SAP assets
                                workflow; gitignored, and no build needs it
    .github/workflows/
      build-ios.yml             macOS runner: bridge -> app -> IPA -> artifact

---

## Documentation

* **[docs/architecture.md](docs/architecture.md)** — how the pieces fit: the two
  tenants on one guest, why the Store runtime is opened once and kept open, the
  download flow end to end, the decisions that were forced by specific failures,
  and what an open costs on device.
* `DELIVERY_STATUS.md` — what works today, what does not, and the evidence.
* `sapbridge/VERIFICATION.md` — build and test matrix for the Go side.

---

## Building

### On GitHub Actions (recommended)

Push to `main` or open a pull request. The workflow runs two jobs:

1. **go-bridge** — unit tests, cross-compiles Unicorn for iOS arm64, binds the
   Go module into `SapBridge.framework` with gomobile.
2. **app** — downloads the framework and builds the app. Nothing here touches
   the four Apple binaries: they are not in the bundle, and the app fetches
   them from Apple on the device the first time it needs to sign. The job then
   seals it with a generated CodeResources, packages it as `DLiPA-<digest>.ipa`, uploads it
   as an artifact. Tagged pushes also attach it to a release.

Run it manually from the Actions tab with **Run workflow**.

### Locally (macOS with Xcode)

    brew install ldid cmake xcodegen

    # 1. Unicorn for iOS
    ./scripts/build-unicorn-ios.sh

    # 2. bind the Go bridge
    cd sapbridge
    CGO_ENABLED=1 GOOS=ios GOARCH=arm64 gomobile bind \
      -target=ios/arm64 -o ../app/DLiPARebuild/Frameworks/SapBridge.xcframework .
    cd ..

    # 3. generate the project and build
    cd app
    xcodegen generate
    xcodebuild -project DLiPARebuild.xcodeproj -scheme DLiPARebuild \
      -configuration Release -sdk iphoneos \
      -destination "generic/platform=iOS" \
      CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO

    # 4. package
    ./scripts/package-ipa.sh build/Build/Products/Release-iphoneos/DLiPARebuild.app DLiPARebuild.ipa

## Installing

Download the `DLiPARebuild-<digest>.ipa` artifact from the workflow run - the name
carries a short digest of the binary, so a stale copy cannot be mistaken for the
current build (or a release), then:

- **AltStore** — My Apps tab, tap +, choose the IPA, sign in with your Apple ID
- **Sideloadly** — drag the IPA in, sign in

Free Apple IDs get a 7-day certificate, so re-sign weekly. A paid developer
account lasts a year.

---

## Scope

This is a **functional core**, not a full UI recreation of DLiPA 1.4. It
implements sign-in, search, version history and the signed download path — the
parts that needed fixing.

Known gaps, in the order they are likely to matter:

* the classic `volumeStoreDownloadProduct` path is still present as a fallback.
  It answers `2042` and its `buyProduct` fallback answers `SystemError`, so it
  contributes nothing; it goes once the encoder path has run in the field.
* purchases, and therefore apps the account does not already own, are not
  supported. This downloads, not buys.
* the store runtime is opened once and kept open, because the guest carries the
  account's session state — so switching accounts needs an app restart. An open
  now costs about 1.2 s, against about 99 s while the shared cache was still
  mapped in full (see the architecture note). The original app's 100 Objective-C classes, 12 localisations,
CocoaHTTPServer install flow and SSZipArchive packaging are not reproduced;
the source was never published, only the compiled IPA.

## Licence

This project's own code is [AGPL-3.0](LICENSE). Code inherited from DLiPA and
ipatool stays under MIT; see [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

Components it depends on keep their own terms, and some of them matter:
**Unicorn is GNU GPL v2 and is statically linked**, so its terms travel with
the binary. It is not upstream Unicorn: the build uses
[1rhino2/unicorn-tci](https://github.com/1rhino2/unicorn-tci), a fork with the
QEMU TCI interpreter restored, pinned at a commit. Upstream ships only the JIT,
and iOS refuses executable anonymous memory on a non-jailed device, so the
translation cache cannot be allocated at all. The full breakdown - ipatool, Unicorn, the Go dependencies, the
Apple binaries, and the resources taken from the original DLiPA 1.4 - is in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

## Acknowledgements

- [unicorn-tci](https://github.com/1rhino2/unicorn-tci) by 1rhino2 — the TCI fork
  of Unicorn this app is built against, GPL v2 with a linking exception
- [Unicorn](https://github.com/unicorn-engine/unicorn) by Nguyen Anh Quynh and
  contributors — the CPU emulator that fork derives from
- [ipatool](https://github.com/majd/ipatool) by Majd Alfhaily — the SAP signing
  stack this project vendors, MIT licensed
- [DLiPA](https://github.com/AhmedBafkir/DLiPA) by Ahmed Bafkir — the original app
