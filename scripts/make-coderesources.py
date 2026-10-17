#!/usr/bin/env python3
# Generate _CodeSignature/CodeResources for an unsigned iOS .app.
#
# Why this exists:
#   TrollStore error 181 "Unable to register" with ApplicationType = System means
#   MobileInstallation did not find the bundle sealed. Two things seal it:
#     - an LC_CODE_SIGNATURE load command in the Mach-O executable
#     - _CodeSignature/CodeResources, a plist listing every resource and its
#       SHA-256
#   The original DLiPA 1.4 IPA, which installs, has both. An IPA with neither
#   is rejected even though ldid and the CoreTrust bypass both succeed.
#
#   codesign would produce this, but it refuses to walk .lproj directories
#   ("bundle format unrecognized"). Homebrew ldid no longer supports -S. So it
#   is generated directly.
#
# Usage: make-coderesources.py <path-to-.app>

import hashlib
import os
import plistlib
import sys

# Matches the rules in the original DLiPA CodeResources, which is the shape
# iOS expects for an app bundle.
RULES = {
    "^.*": True,
    "^.*\\.lproj/": {"optional": True, "weight": 1000.0},
    "^.*\\.lproj/locversion.plist$": {"omit": True, "weight": 1100.0},
    "^Base\\.lproj/": {"weight": 1010.0},
    "^version.plist$": True,
}

RULES2 = {
    ".*\\.dSYM($|/)": {"weight": 11.0},
    "^(.*/)?\\.DS_Store$": {"omit": True, "weight": 2000.0},
    "^.*": True,
    "^.*\\.lproj/": {"optional": True, "weight": 1000.0},
    "^.*\\.lproj/locversion.plist$": {"omit": True, "weight": 1100.0},
    "^Base\\.lproj/": {"weight": 1010.0},
    "^Info\\.plist$": {"omit": True, "weight": 20.0},
    "^PkgInfo$": {"omit": True, "weight": 20.0},
    "^embedded\\.provisionprofile$": {"weight": 20.0},
    "^version\\.plist$": {"weight": 20.0},
}

# The main executable is sealed by its own LC_CODE_SIGNATURE, not by
# CodeResources. The original DLiPA does not list it, so neither do we.
# embedded.mobileprovision is a signing residue and is absent from an
# unsigned build anyway.
SKIP_DIRS = {"_CodeSignature", "SC_Info"}
SKIP_FILES = {"ResourceFork", ".DS_Store"}


def walk(app):
    """Yield bundle-relative paths of every file except the executable."""
    for dirpath, dirnames, filenames in os.walk(app):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if name in SKIP_FILES:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, app)
            yield rel.replace(os.sep, "/")


def main(app):
    if not os.path.isdir(app):
        sys.exit("not a directory: " + app)

    # The executable named by CFBundleExecutable is sealed separately.
    with open(os.path.join(app, "Info.plist"), "rb") as fh:
        info = plistlib.load(fh)
    executable = info.get("CFBundleExecutable")
    if executable:
        SKIP_FILES.add(executable)

    files = {}
    files2 = {}
    for rel in walk(app):
        # Info.plist and PkgInfo are hashed but listed in rules2 as omitted
        # from files2, matching the original.
        with open(os.path.join(app, rel), "rb") as fh:
            data = fh.read()
        digest = hashlib.sha1(data).digest()
        entry = {"hash": digest, "version": 2}
        files[rel] = entry
        if rel in ("Info.plist", "PkgInfo"):
            continue
        files2[rel] = {"hash2": hashlib.sha256(data).digest()}

    resources = {
        "files": files,
        "files2": files2,
        "rules": RULES,
        "rules2": RULES2,
    }

    out_dir = os.path.join(app, "_CodeSignature")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "CodeResources")
    with open(out, "wb") as fh:
        plistlib.dump(resources, fh, fmt=plistlib.FMT_XML)

    print("==> wrote " + out)
    print("    " + str(len(files)) + " files, " + str(len(files2)) + " with sha256")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: make-coderesources.py <path-to-.app>")
    main(sys.argv[1])
