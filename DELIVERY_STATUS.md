# The signature now names the application

    DLiPA-80cfc099.ipa    85.45 MB
    sha256  c15267fbdfc5b3c50788cca51f6f63859bd22f4ecc15b7727e46570e7daa1e73
    run     https://github.com/a23bc/dlipa-rebuild/actions/runs/39023655342

## Point taken on scope

The goal is a rebuild that restores what DLiPA did, not a reproduction of the
original bundle. That distinction cost real progress: several rounds went on
byte-level parity with the original, and two of those fixed differences that
turned out not to matter.

Where parity *is* the right tool is narrow, and worth stating precisely:
MobileInstallation types a bundle from a handful of identifying fields, so those
fields have to be well formed. Nothing else about the bundle has to match.

## The actual defect

The install log showed TrollStore reading one entitlement from our binary where
it read three from the original:

    ours      get-task-allow
    original  application-identifier
              com.apple.developer.team-identifier
              get-task-allow

Without `application-identifier` the signature does not name an application, and
MobileInstallation types it System. That is the 181.

## What changed

The entitlements plist passed to ldid now carries all three keys, written whole
rather than assembled with `plutil -insert`, which validates values and rejected
every team identifier offered - including a well-formed ten-character one.

No certificate is involved and none is needed. The team value is arbitrary for a
locally signed binary; TrollStore rewrites it when it re-signs on install.

## Verified in the shipped IPA

The DER entitlements slot now reads:

    application-identifier                    A23BC00001.com.a23bc.dliparebuild
    com.apple.developer.team-identifier       A23BC00001
    get-task-allow                            true

Which is the same three keys, in the same form, as the original. The bundle root
and the CodeResources manifest are unchanged from the previous build.

## Where the download stands (2026-10-31)

Sign-in, kbsync, signing, search and account handling work. The download does
not: every attempt at the store's download endpoints is answered `2042
AuthTokenResumeFreeBuy`. Five hypotheses have been tested on device and none of
them was the cause, including a request that copies ipatool's header set byte for
byte.

The state, the evidence, the three remaining differences that cannot be fixed by
editing a header, and the one experiment that would split the problem in two are
written down in `PLAN-download-2042.md`. Read that before touching the download
path again -- it exists so the next round starts from what is already known
rather than from another guess.
