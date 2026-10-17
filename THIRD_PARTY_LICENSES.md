# Third-party licences

Components this project depends on, and the terms they keep. See
[LICENSE](LICENSE) for the licence covering this project's own code.

## ipatool - the SAP protocol implementation

- **Source** <https://github.com/majd/ipatool>
- **Copyright** (c) 2021 Majd Alfhaily
- **Licence** MIT

`sapbridge/internal/sap/` is a trimmed, vendored copy of the relevant parts of
ipatool v2: the two-leg sign-sap-setup handshake, the FairPlay kbsync blob, the
ent/download request shape, and the CoreFP guest execution. The iOS W^X patch
for Unicorn comes from the same place.

## Unicorn CPU emulator

- **Source** <https://github.com/unicorn-engine/unicorn>
- **Copyright** (c) 2013-2021 Nguyen Anh Quynh and other contributors
- **Licence** GNU GPL v2, with a linking exception permitting static linking of
  the bundled qemu and glib sources

Built for iOS arm64 by `scripts/build-unicorn-ios.sh` from the pinned 2.1.4
release and statically linked into the app. Nothing from the Unicorn source is
vendored into this repository; it is fetched at build time.

> **Note for anyone redistributing.** Unicorn is statically linked, so its GPL
> terms travel with the binary. The MIT licence on this repository does not and
> cannot override that. Confirm the linking exception covers your use before
> shipping.

## Go dependencies

| Package | Version | Licence |
|---|---|---|
| [blacktop/go-macho](https://github.com/blacktop/go-macho) | v1.1.282 | MIT |
| [ebitengine/purego](https://github.com/ebitengine/purego) | v0.10.2 | Apache 2.0 |
| [howett.net/plist](https://github.com/howett.net/plist) | v1.0.1 | BSD 2-Clause |
| [golang.org/x/mobile](https://go.dev/blog/gomobile) | latest | BSD 3-Clause (The Go Authors) |

## Apple binaries

The four binaries in `VendorAssets/` - `CoreFP`, `AppleMediaServices`,
`commerce`, `CoreFP.icxs` - are Apple copyright, extracted from a macOS restore
image. They are included only because the signing protocol requires running
them. **Not redistributable on their own terms.**

## Resources from the original DLiPA 1.4

`Assets.car`, the app icons and the 14 `Localizable.strings` files come from the
original DLiPA 1.4 application. Its repository
(<https://github.com/AhmedBafkir/DLiPA>) publishes no source and **states no
licence**, so no terms can be relied on here.

They are carried over so this build is a drop-in replacement. Because nothing
is granted, replacing them with originals is the safer choice before wide
redistribution.
