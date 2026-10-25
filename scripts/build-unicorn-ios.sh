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
#   2. The guest arch must match the engine that calls uc_open. Route A runs
#      sap_guest.c, a macOS x86-64 dylib opened with uc_open(UC_ARCH_X86, ...),
#      so its archive is UNICORN_ARCH=x86. Route B (Archive/PLAN-B-arm64.md,
#      Archive/PLAN-arm64-download.md) runs the macOS 27 machine package, whose
#      AppleMediaServices asset is arm64 only, so its archive is
#      UNICORN_ARCH=aarch64.
#
# The two must change together with the caller. Changing UNICORN_ARCH alone
# produces a library that links and then fails at uc_open, which is why an
# earlier attempt concluded aarch64 was wrong: it changed the archive while the
# C engine still asked for x86.
#
# Environment:
#   UNICORN_ARCH   x86 (default) or aarch64
#   OUT_DIR        where to stage the archive and headers (default build/ios)
#   HOST_BUILD     1 builds for the macOS host instead of iOS, so CI can run
#                  the interpreter instead of only linking it
#
# The fork ships the QEMU tree with tci.c already restored, so unlike the
# upstream 2.1.4 build there is no patch to apply. Pinned by commit so the
# build is reproducible.
set -eu

TCI_REPO=1rhino2/unicorn-tci
TCI_COMMIT=e3f075a627
UNICORN_ARCH=${UNICORN_ARCH:-x86}
HOST_BUILD=${HOST_BUILD:-0}
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
OUT_DIR=${OUT_DIR:-$ROOT/build/ios}
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

if [ "$HOST_BUILD" = "1" ]; then
  echo "==> host build for the macOS runner (so CI can execute, not just link)"
  cmake -S "$SRC_DIR" -B "$BUILD_DIR/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DUNICORN_ARCH="$UNICORN_ARCH" \
    -DUNICORN_INTERPRETER=on \
    -DUNICORN_BUILD_TESTS=OFF \
    -DUNICORN_INSTALL=OFF
else
  SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)
  cmake -S "$SRC_DIR" -B "$BUILD_DIR/build" \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_SYSROOT="$SDKROOT" \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
    -DCMAKE_C_FLAGS="-target arm64-apple-ios15.0 -DCONFIG_TCG_INTERPRETER=1" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DUNICORN_ARCH="$UNICORN_ARCH" \
    -DUNICORN_INTERPRETER=on \
    -DUNICORN_BUILD_TESTS=OFF \
    -DUNICORN_INSTALL=OFF
fi

# CONFIG_TCG_INTERPRETER decides one line of alloc_code_gen_buffer:
#
#   #if CONFIG_TCG_INTERPRETER
#       int prot = PROT_WRITE | PROT_READ;
#   #else
#       int prot = PROT_WRITE | PROT_READ | PROT_EXEC;
#   #endif
#
# iOS refuses the executable anonymous mapping, and QEMU turns that into
# exit(1) from code_gen_alloc, so the app dies at the first uc_mem_map with
# nothing in the log. It is worth stating the flag explicitly rather than
# trusting that UNICORN_INTERPRETER reached every translation unit: the device
# failed at an 8 MiB mmap with 63 MB resident, which is not a size problem and
# is exactly what a PROT_EXEC request looks like.
if ! grep -q "CONFIG_TCG_INTERPRETER" "$BUILD_DIR/build/config-host.h" 2>/dev/null; then
  echo "::warning::CONFIG_TCG_INTERPRETER is not in config-host.h; relying on the explicit -D" >&2
fi

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
# A JIT archive and a TCI archive have the same filename and the same uc_*
# symbols, so the archive alone cannot tell them apart. The authority is what
# qemu/configure wrote: CONFIG_TCG_INTERPRETER=y in config-host.mak. It matters
# because the two differ in one line of alloc_code_gen_buffer -- the JIT branch
# asks for PROT_EXEC anonymous memory, which iOS refuses, and then QEMU calls
# exit(1) with no crash log. A JIT build therefore links fine and dies at
# uc_open on device, which is exactly what happened.
if ! grep -q "^CONFIG_TCG_INTERPRETER=y" "$BUILD_DIR/build/config-host.mak" 2>/dev/null; then
  echo "::error::CONFIG_TCG_INTERPRETER is not set in config-host.mak" >&2
  echo "::error::UNICORN_INTERPRETER did not reach qemu/configure" >&2
  grep -i interpreter "$BUILD_DIR/build/config-host.mak" >&2 || true
  exit 1
fi
echo "==> interpreter confirmed: CONFIG_TCG_INTERPRETER=y"
if ! nm -g "$ARCHIVE" 2>/dev/null | grep -q "uc_open"; then
  echo "::error::uc_open not found in $ARCHIVE; the archive is not a Unicorn library" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
cp "$ARCHIVE" "$OUT_DIR/libunicorn.a"
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
rm -rf "$OUT_DIR/include"
cp -R "$INCLUDE_SRC" "$OUT_DIR/include"
if [ ! -f "$OUT_DIR/include/unicorn/unicorn.h" ]; then
  echo "::error::include staging did not produce $OUT_DIR/include/unicorn/unicorn.h" >&2
  exit 1
fi
echo "==> staged $OUT_DIR/include from $INCLUDE_SRC"

# purego resolves the statically linked API through dlsym, so the symbols must
# be exported. The Go build adds these flags via CGO_LDFLAGS.
cat > "$OUT_DIR/unicorn.env" <<EOF
CGO_ENABLED=1
GOOS=ios
GOARCH=arm64
CGO_LDFLAGS=-Wl,-force_load,$OUT_DIR/libunicorn.a -Wl,-export_dynamic
EOF

echo "==> staged $OUT_DIR/libunicorn.a (TCI, guest $UNICORN_ARCH)"
ls -la "$OUT_DIR"
