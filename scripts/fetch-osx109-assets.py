#!/usr/bin/env python3
"""Fetch the OS X 10.9 SAP binaries from Apple's public update package.

Why the 2013 build: the SAP entry points live in CommerceKit, and the macOS 27
copy of that framework is a chained-fixup binary whose x86-64 slice the classic
dyld-info reader cannot process. The 10.9 copy is plain LC_DYLD_INFO_ONLY, is
x86-64, and is the same build ipatool-rs drives successfully.

Only ~31 MB of the 1.27 GB package is transferred. The payload is one long
bzip2 stream stored uncompressed, so decompression can resume at a block
boundary if the stream header is supplied by hand.

Usage:
    fetch-osx109-assets.py --out <directory>
"""

import argparse
import bz2
import hashlib
import os
import re
import struct
import sys
import urllib.request
import zlib

UPDATE_URL = (
    "https://swcdn.apple.com/content/downloads/27/34/041-98128-A_SYPWICN3KH/"
    "5dqkl4rqgbsr18yzy61yeie9g3cmjc5hiv/OSXUpd10.9.pkg"
)

# Offset of a bzip2 block boundary inside the payload stream.
PAYLOAD_BZ_OFFSET = 0x352F40D5
# Bytes to drop after decompression, before the first CPIO header.
PAYLOAD_CPIO_SKIP = 0x3A4
MAX_TRANSFER = 256 << 20

FRAMEWORKS = "./System/Library/PrivateFrameworks/"

REQUIRED = [
    ("CommerceKit", "CommerceKit.framework/Versions/A/CommerceKit",
     3271840, "b84ff12c21987856c0a17b78f1ad82b73195a6dec5f3b208a17d245555a2c8a2"),
    ("CommerceCore",
     "CommerceKit.framework/Versions/A/Frameworks/CommerceCore.framework/Versions/A/CommerceCore",
     207744, "c5401e57402230f3c876409d295319ddf1e61287bc882683c5d61277be7bc1f2"),
    ("CoreFP", "CoreFP.framework/Versions/A/CoreFP",
     29014912, "f19141336be4198d0f8991bb00017c915efc7aeaece36c345f7faa1237ea6074"),
    ("CoreFP.icxs", "CoreFP.framework/Versions/A/CoreFP.icxs",
     5288352, "473e78af86979f5bd4f6269561caf770b3d16c098d918846eeac8cdd2fe6566a"),
]


def ranged(start, end):
    request = urllib.request.Request(
        UPDATE_URL,
        headers={"Range": "bytes=%d-%d" % (start, end), "User-Agent": "curl/8"},
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        return response.read()


def payload_start():
    """Absolute offset of the bzip2 block boundary we resume from."""
    header = ranged(0, 27)
    if header[:4] != b"xar!":
        raise SystemExit("not a XAR archive")
    header_size = struct.unpack(">H", header[4:6])[0]
    toc_compressed = struct.unpack(">Q", header[8:16])[0]

    toc = zlib.decompress(ranged(header_size, header_size + toc_compressed - 1))
    text = toc.decode("utf-8", "replace")

    match = re.search(r"<name>Payload</name>.*?<offset>(\d+)</offset>", text, re.S)
    if not match:
        raise SystemExit("payload entry not found in the table of contents")

    heap = header_size + toc_compressed
    return heap + int(match.group(1)) + PAYLOAD_BZ_OFFSET


def extract(out_dir):
    start = payload_start()
    print("payload range starts at %d" % start)

    wanted = {FRAMEWORKS + path: (name, digest) for name, path, _, digest in REQUIRED}
    sizes = {name: size for name, _, size, _ in REQUIRED}

    os.makedirs(out_dir, exist_ok=True)

    request = urllib.request.Request(
        UPDATE_URL,
        headers={"Range": "bytes=%d-%d" % (start, start + MAX_TRANSFER - 1)},
    )
    stream = urllib.request.urlopen(request, timeout=600)

    decoder = bz2.BZ2Decompressor()
    buffer = bytearray()
    found = {}
    transferred = 0
    skipped = False
    first = True

    while len(found) < len(REQUIRED) and transferred < MAX_TRANSFER:
        chunk = stream.read(1 << 20)
        if not chunk:
            break
        transferred += len(chunk)

        try:
            # Resuming mid-stream needs a stream header; only four bytes of it.
            buffer.extend(decoder.decompress((b"BZh9" if first else b"") + chunk))
        except OSError as error:
            raise SystemExit("bzip2: %s" % error)
        first = False

        if not skipped:
            if len(buffer) < PAYLOAD_CPIO_SKIP:
                continue
            del buffer[:PAYLOAD_CPIO_SKIP]
            skipped = True

        while len(buffer) >= 76 and bytes(buffer[:6]) == b"070707":
            try:
                name_size = int(bytes(buffer[59:65]).strip() or b"0", 8)
                file_size = int(bytes(buffer[65:76]).strip() or b"0", 8)
            except ValueError:
                break
            total = 76 + name_size + file_size
            if len(buffer) < total:
                break

            name = bytes(buffer[76:76 + name_size - 1]).decode("utf-8", "replace")
            if name == "TRAILER!!!":
                buffer = bytearray()
                break

            if name in wanted:
                label, digest = wanted[name]
                body = bytes(buffer[76 + name_size:total])
                actual = hashlib.sha256(body).hexdigest()
                if actual != digest:
                    raise SystemExit("%s: sha256 %s does not match %s" % (label, actual, digest))
                if len(body) != sizes[label]:
                    raise SystemExit("%s: size %d does not match %d" % (label, len(body), sizes[label]))
                with open(os.path.join(out_dir, label), "wb") as handle:
                    handle.write(body)
                found[label] = True
                print("  %-14s %d bytes  ok" % (label, len(body)))

            del buffer[:total]

    if len(found) < len(REQUIRED):
        raise SystemExit("only %d of %d assets were extracted" % (len(found), len(REQUIRED)))

    print("transferred %d MB" % (transferred >> 20))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    extract(args.out)


if __name__ == "__main__":
    main()
