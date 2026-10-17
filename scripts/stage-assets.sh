#!/bin/sh
# Stage the four pinned Apple SAP binaries into the app bundle and verify them.
# A silently wrong asset would make the SAP handshake fail with an opaque error,
# so the digests are checked here where the failure message can be clear.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
SRC=${1:-$ROOT/VendorAssets}
DST=${2:-$ROOT/app/DLiPA/Resources/SapAssets}

mkdir -p "$DST"

verify() {
  name=$1
  want=$2
  got=$(shasum -a 256 "$SRC/$name" | cut -d" " -f1)
  if [ "$got" != "$want" ]; then
    echo "::error::$name digest mismatch: got $got want $want" >&2
    exit 1
  fi
  cp "$SRC/$name" "$DST/$name"
  echo "  ok $name"
}

echo "==> verifying Apple SAP assets"
verify CoreFP            2c30fa2b5f695fd66c0360dce72f54757d03ddb7107549715c12cb359a003b46
verify AppleMediaServices 95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4
verify commerce          76de40a4a32f691947cb926ce3b128d2fc446f7cac9755f831c406cf5a316ac9
verify CoreFP.icxs       cb8f55330ec567da3e692dab5f5388bed0312dd9093340477c5759078cc2aa7b

echo "==> staged to $DST"
du -sh "$DST"
