#!/bin/sh
# Cross-compile the Unicorn TCI (interpreter) fork for iOS arm64 and stage the
# static library and its headers where the Go build and the app build can use
# them.
#
# WHY THIS FORK. Two properties are required and the upstream release has
# neither:
#
#   1. Interpreter, not JIT. On a non-jailbroken device iOS refuses executable
#      anonymous memory, so a TCG code_gen_buffer cannot be allocated at all.
#      The TCI build makes the JIT target a virtual machine that is interpreted,
#      so no executable page is ever requested.
#   2. x86-64 guest. The SAP guest is a macOS x86-64 dylib, and sap_guest.c
#      opens the machine with uc_open(UC_ARCH_X86, UC_MODE_64). The arch baked
#      into this archive has to match, so UNICORN_ARCH=x86.
#
# Do not "fix" UNICORN_ARCH to aarch64. That was the wrong assumption in an
# earlier plan (Archive/PLAN-B-arm64.md): it targets a different SAP stack
# entirely. For this route the guest is x86-64 and the archive must say so.
#
# The fork ships the QEMU tree with tci.c already restored, so unlike the
# upstream 2.1.4 build there is no patch to apply. Pinned by commit so the
# build is reproducible.
set -eu

TCI_REPO=1rhino2/unicorn-tci
TCI_COMMIT=e3f075a627
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT HUP INT TERM

echo "==> Unicorn TCI ($TCI_REPO@$TCI_COMMIT) for iOS arm64, guest arch x86"

curl -fL --retry 3 \
  "https://codeload.github.com/$TCI_REPO/tar.gz/$TCI_COMMIT" \
  -o "$BUILD_DIR/tci.tar.gz"
mkdir -p "$BUILD_DIR/src"
tar -xzf "$BUILD_DIR/tci.tar.gz" -C "$BUILD_DIR/src" --strip-components=1

# The QEMU tree, the CMake entry point and the public headers all live under
# unicorn-engine-sys-tci/. The repository root also holds a Cargo crate, which
# is why this is not simply the extraction root.
SRC_DIR="$BUILD_DIR/src/unicorn-engine-sys-tci"
if [ ! -f "$SRC_DIR/CMakeLists.txt" ]; then
  echo "::error::CMakeLists.txt not found at $SRC_DIR" >&2
  exit 1
fi

# The whole point of this fork is the interpreter target. If the option is
# gone, the pin has drifted and a JIT-only library would be produced - which
# links fine and then fails on the device. Stop here instead.
if ! grep -q "UNICORN_INTERPRETER" "$SRC_DIR/CMakeLists.txt"; then
  echo "::error::UNICORN_INTERPRETER not found in $SRC_DIR/CMakeLists.txt; the pinned fork changed" >&2
  exit 1
fi

SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)
cmake -S "$SRC_DIR" -B "$BUILD_DIR/build" \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_OSX_SYSROOT="$SDKROOT" \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
  -DCMAKE_C_FLAGS="-target arm64-apple-ios15.0" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DUNICORN_ARCH=x86 \
  -DUNICORN_INTERPRETER=on \
  -DUNICORN_BUILD_TESTS=OFF \
  -DUNICORN_INSTALL=OFF
cmake --build "$BUILD_DIR/build" --parallel "$(sysctl -n hw.ncpu)"

# CMake links two archives: libunicorn-static.a holds only the common target,
# while libunicorn.a is the full library including the per-arch softmmu
# objects. Choosing the wrong one leaves uc_open resolvable but the arch
# helpers undefined, which surfaces as missing reg_write_aarch64 and
# g_array_new at link time.
ARCHIVE="$BUILD_DIR/build/libunicorn.a"
if [ ! -f "$ARCHIVE" ]; then
  ARCHIVE=$(find "$BUILD_DIR/build" -name "libunicorn*.a" | head -n 1)
fi
if [ -z "$ARCHIVE" ] || [ ! -f "$ARCHIVE" ]; then
  echo "::error::libunicorn archive was not produced" >&2
  exit 1
fi

# The archive is only useful if it really carries the interpreter. A JIT-only
# build has the same filename and the same exported uc_* symbols, so the
# symbol table is the only place the difference shows. tci.c is compiled into
# the archive when UNICORN_INTERPRETER is on.
if ! nm -g "$ARCHIVE" 2>/dev/null | grep -qi "tci"; then
  echo "::warning::no tci symbol in $ARCHIVE; verify this is an interpreter build"
fi
if ! nm -g "$ARCHIVE" 2>/dev/null | grep -q "uc_open"; then
  echo "::error::uc_open not found in $ARCHIVE; the archive is not a Unicorn library" >&2
  exit 1
fi

mkdir -p "$ROOT/build/ios"
cp "$ARCHIVE" "$ROOT/build/ios/libunicorn.a"
echo "==> using $ARCHIVE"

# sap_guest.c compiles against the Unicorn headers, so the public include tree
# has to travel with the archive. The sources include <unicorn/unicorn.h> and
# <unicorn/x86.h>, so the directory to put on HEADER_SEARCH_PATHS is the parent
# of unicorn/ - i.e. include/ itself.
INCLUDE_SRC="$SRC_DIR/include"
if [ ! -f "$INCLUDE_SRC/unicorn/unicorn.h" ]; then
  echo "::error::unicorn headers not found under $INCLUDE_SRC" >&2
  exit 1
fi
# rm first: a stale tree from an older Unicorn would otherwise be merged into
# the new one, and header drift is silent until the app fails to compile.
rm -rf "$ROOT/build/ios/include"
cp -R "$INCLUDE_SRC" "$ROOT/build/ios/include"
if [ ! -f "$ROOT/build/ios/include/unicorn/unicorn.h" ]; then
  echo "::error::include staging did not produce build/ios/include/unicorn/unicorn.h" >&2
  exit 1
fi
echo "==> staged $ROOT/build/ios/include from $INCLUDE_SRC"

# purego resolves the statically linked API through dlsym, so the symbols must
# be exported. The Go build adds these flags via CGO_LDFLAGS.
cat > "$ROOT/build/ios/unicorn.env" <<EOF
CGO_ENABLED=1
GOOS=ios
GOARCH=arm64
CGO_LDFLAGS=-Wl,-force_load,$ROOT/build/ios/libunicorn.a -Wl,-export_dynamic
EOF

echo "==> staged build/ios/libunicorn.a (TCI, guest x86) and build/ios/include"
ls -la "$ROOT/build/ios"
