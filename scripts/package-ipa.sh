#!/bin/sh
# Package an unsigned .app as an installable .ipa.
#
# The IPA format is a zip whose root contains Payload/. AltStore, Sideloadly and
# TrollStore all accept an unsigned payload; the signature is applied on the
# device when the user signs in.
set -eu

APP=${1:?usage: package-ipa.sh <path-to-.app> <output.ipa>}
OUT=${2:?usage: package-ipa.sh <path-to-.app> <output.ipa>}

if [ ! -d "$APP" ]; then
  echo "::error::$APP is not a directory" >&2
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

mkdir -p "$WORK/Payload"
cp -R "$APP" "$WORK/Payload/"

# _CodeSignature is kept. It is the sealing manifest MobileInstallation reads,
# and without it the bundle is typed as System and registration fails with
# error 181. This step only copies; scripts/make-coderesources.py creates it.
# iTunesArtwork is optional but some tools look for it.
if [ -f "$APP/iTunesArtwork" ]; then
  cp "$APP/iTunesArtwork" "$WORK/"
fi

# $OLDPWD is not reliable inside a subshell, so resolve the output path
# before changing directory.
case $OUT in
  /*) OUT_ABS=$OUT ;;
  *) OUT_ABS=$(pwd)/$OUT ;;
esac

( cd "$WORK" && zip -qry "$OUT_ABS" . )

echo "==> wrote $OUT_ABS"
ls -la "$OUT_ABS"
shasum -a 256 "$OUT_ABS"
