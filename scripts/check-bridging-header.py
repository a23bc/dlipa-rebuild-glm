#!/usr/bin/env python3
"""Check the hand-written bridging header against gomobile's generated one.

The app links the gomobile c-archive instead of embedding its framework, so
Swift never sees Sapbridge.objc.h; every declaration is copied into
DLiPA-Bridging-Header.h by hand. A declaration left out of that copy is invisible
to Swift while the archive exports it perfectly well, and the only symptom is
"value of type 'SapbridgeSigner' has no member 'x'" several minutes into a build.

Usage: check-bridging-header.py <generated Sapbridge.objc.h> <bridging header>
"""

import re
import sys

# Declarations gomobile emits that no caller reaches, so the bridging header
# deliberately does not mirror them:
#
#   initWithRef:  <goSeqRefInterface> plumbing; gobind's own bookkeeping, never
#                 called by app code
#   setBundleDir: class-level setter for the exported BundleDir variable. The app
#                 calls SapbridgeSetBundleDir(), the C entry point, which is
#                 declared in the bridging header
IGNORED = {"initWithRef", "setBundleDir"}


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check-bridging-header.py GENERATED BRIDGING", file=sys.stderr)
        return 2

    # utf-8-sig: a byte-order mark would otherwise hide the first declaration
    # from the anchored patterns below.
    generated = open(sys.argv[1], encoding="utf-8-sig").read()
    bridging = open(sys.argv[2], encoding="utf-8-sig").read()

    missing = []

    def labels(line: str) -> list[str]:
        """Selector labels in order, ignoring the parameter types."""
        return re.findall(r"(\w+):\s*\(", line)

    bridging_signatures = [
        labels(line) for line in bridging.splitlines() if re.match(r"^[-+]\s*\(", line)
    ]

    # ObjC methods: compare the whole label sequence, not just the first one.
    #
    # Checking only the first label let a signature change through: storeSmoke:
    # gained a parameter, the bridging header still declared three, and this
    # script reported "matches the generated API" because it found the word
    # storeSmoke somewhere. The build then failed with "extra argument", which
    # says nothing about the header being stale.
    for match in re.finditer(r"^[-+]\s*\([^)]*\)\s*(\w+):.*$", generated, re.M):
        line = match.group(0)
        sequence = labels(line)

        if not sequence or sequence[0] in IGNORED:
            continue

        if sequence not in bridging_signatures:
            missing.append(":".join(sequence) + ":")

    # Package-level functions: FOUNDATION_EXPORT NSData* SapbridgeKBSync(...)
    for match in re.finditer(r"^FOUNDATION_EXPORT\b.*?\b(\w+)\(", generated, re.M):
        name = match.group(1)
        if name not in bridging:
            missing.append(name)

    if missing:
        unique = sorted(set(missing))
        print("::error::the bridging header is missing: " + ", ".join(unique))
        print("::error::add them to DLiPARebuild/DLiPA-Bridging-Header.h; "
              "the archive exports them but Swift cannot see them")
        return 1

    print("bridging header matches the generated API")
    return 0


if __name__ == "__main__":
    sys.exit(main())
