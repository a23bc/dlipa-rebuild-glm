#!/usr/bin/env python3
"""
Prepare the commerce binary for native execution on iOS.

Input:  commerce (macOS arm64e Mach-O, ~8MB)
Output: commerce_native (iOS arm64 Mach-O, PAC stripped, ldid signed)

The commerce binary contains Apple's FairPlay SAP signing code as arm64e
machine code with Pointer Authentication Codes (PAC). iOS apps cannot
execute arm64e code (only arm64), and the PAC instructions would trap.
This script:

1. Parses the Mach-O to find the arm64e slice
2. Strips PAC instructions from __TEXT:
   - braa  -> br    (branch with auth -> plain branch)
   - blraa -> blr   (branch-link with auth -> plain branch-link)
   - retab -> ret   (return with auth -> plain return)
   - pac*  -> nop   (sign instructions -> nop)
   - aut*  -> nop   (auth instructions -> nop)
3. Changes the Mach-O header from arm64e to arm64
4. Writes the modified binary
5. Signs with ldid (called by the CI workflow)

The output binary is included in the app bundle. At runtime, the app
mmaps it with PROT_READ|PROT_EXEC — iOS allows this because the file
has a valid code signature (from ldid) and is covered by the bundle's
CodeResources.

This approach bypasses Unicorn entirely. The ARM64 code runs natively
on the iOS device's CPU. No JIT, no emulation, no anonymous executable
memory. The only overhead is setting up data segments and host function
stubs (malloc, free, arc4random, etc.) at the expected addresses.

Based on the PAC stripping technique from lbr77/sap-unicorn:
https://github.com/lbr77/sap-unicorn
"""

import struct
import sys
import os

# Mach-O constants
MH_MAGIC_64 = 0xfeedfacf
CPU_TYPE_ARM64 = 0x100000c
CPU_SUBTYPE_ARM64E = 2
CPU_SUBTYPE_ARM64_ALL = 0

LC_SEGMENT_64 = 0x19
LC_BUILD_VERSION = 0x32

# Platform constants for LC_BUILD_VERSION
PLATFORM_MACOS = 1
PLATFORM_IOS = 2
PLATFORM_IOSSIMULATOR = 7

# PAC instruction patterns (arm64e)
# These are the instructions we need to rewrite.
# Encoding: top 8 bits + mask to identify the instruction.

# braa  x16, x17  -> br x16
# braa  encoding: 0xd61f0a00 (bits [31:10] = 0xd61f0280)
# blraa x16, x17  -> blr x16
# blraa encoding: 0xd63f0a00 (bits [31:10] = 0xd63f0280)
# retab           -> ret
# retab encoding: 0xd65f0fff -> 0xd65f03c0

# PAC instructions (nop them out):
# pacia, pacib, pacda, pacdb, pacga, paciza, pacizb, pacdza, pacdzb
# autia, autib, autda, autdb, autiza, autizb, autdza, autdzb
# xpaci, xpacd
# All start with 0xd5032 (hint space) or 0xdac (pacia/pacib/etc.)

# NOP = 0xd503201f

NOP = 0xd503201f

def is_pac_instr(word):
    """Check if a 32-bit instruction is a PAC-related instruction."""
    # pacia/pacib/pacda/pacdb/pacga: 0xdac0xxxx - 0xdac7xxxx
    # autia/autib/autda/autdb: 0xdac8xxxx - 0xdacfxxxx
    # paciza/pacizb/pacdza/pacdzb: 0xdacxxxxx (specific patterns)
    # autiza/autizb/autdza/autdzb: 0xdacxxxxx
    # xpaci/xpacd: 0xd503211f / 0xd503215f
    # pacsp/autesp: system instructions

    # Check for PAC/AUT in the data hint space
    if (word & 0xfffffc00) == 0xd5032100:  # XPACI, XPACD, etc.
        return True
    if (word & 0xffe0fc00) == 0xdac00000:  # PACIA, PACIB, etc.
        return True
    if (word & 0xffe0fc00) == 0xdac00400:  # AUTIA, AUTIB, etc.
        return True
    # More specific patterns
    if (word & 0xff000000) == 0xda000000:  # PAC instructions
        # Check it's actually a PAC instruction
        op = (word >> 12) & 0xff
        if op in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                   0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                   0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d):
            return True
    return False

def strip_pac_instruction(word):
    """Return the non-PAC version of an instruction, or NOP."""
    # braa x16, x17 -> br x16
    # braa: bits [31:10] = 0b1101011000111111010000_10
    # Encoding: 0xD61F0A00 | (Rn << 5) | Rm  (with bit 10 set for auth)
    if (word & 0xfffffc1f) == 0xd61f0800:  # BRAA
        rn = (word >> 5) & 0x1f
        return 0xd61f0000 | (rn << 5)  # BR x16

    # blraa x16, x17 -> blr x16
    if (word & 0xfffffc1f) == 0xd63f0800:  # BLRAA
        rn = (word >> 5) & 0x1f
        return 0xd63f0000 | (rn << 5)  # BLR x16

    # retab -> ret
    if word == 0xd65f0fff:  # RETAB
        return 0xd65f03c0  # RET (x30)

    # braaz x16 -> br x16 (authenticated with zero)
    if (word & 0xfffffc1f) == 0xd61f081f:  # BRAAZ
        rn = (word >> 5) & 0x1f
        return 0xd61f0000 | (rn << 5)  # BR

    # blraaz x16 -> blr x16
    if (word & 0xfffffc1f) == 0xd63f081f:  # BLRAAZ
        rn = (word >> 5) & 0x1f
        return 0xd63f0000 | (rn << 5)  # BLR

    # All other PAC/AUT instructions -> NOP
    if is_pac_instr(word):
        return NOP

    return word

def parse_macho_header(data):
    """Parse the Mach-O header and return segment info."""
    if len(data) < 32:
        return None

    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = \
        struct.unpack_from('<IiiIIIII', data, 0)

    if magic != MH_MAGIC_64:
        # Check if it's a fat binary
        if struct.unpack_from('>I', data, 0)[0] == 0xcafebabe:
            return parse_fat(data)

    return [(0, data, cputype, cpusubtype, ncmds)]

def parse_fat(data):
    """Parse a fat/universal binary and return arm64e slice."""
    nfat_arch = struct.unpack_from('>I', data, 4)[0]
    slices = []
    offset = 8
    for i in range(nfat_arch):
        cputype, cpusubtype, offset_val, size_val, align_val = \
            struct.unpack_from('>iiIII', data, offset)
        if cputype == CPU_TYPE_ARM64:
            slice_data = data[offset_val:offset_val + size_val]
            # Parse the slice's own header for ncmds
            magic = struct.unpack_from('<I', slice_data, 0)[0]
            if magic == MH_MAGIC_64:
                ncmds = struct.unpack_from('<I', slice_data, 16)[0]
                slices.append((offset_val, slice_data, cputype, cpusubtype, ncmds))
        offset += 20
    return slices

def find_text_segment(data):
    """Find the __TEXT segment in a Mach-O 64-bit binary."""
    offset = 32  # After mach_header_64
    ncmds = struct.unpack_from('<I', data, 16)[0]

    segments = []
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, offset)
        if cmd == LC_SEGMENT_64:
            segname = data[offset+8:offset+24].rstrip(b'\x00').decode('ascii', errors='replace')
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, offset+24)
            nsects = struct.unpack_from('<I', data, offset+48)[0]
            segments.append({
                'name': segname,
                'vmaddr': vmaddr,
                'vmsize': vmsize,
                'fileoff': fileoff,
                'filesize': filesize,
                'offset': offset,
                'cmdsize': cmdsize,
                'nsects': nsects,
            })
        offset += cmdsize

    return segments

def strip_pac_in_text(data, text_seg):
    """Strip PAC instructions from the __TEXT segment."""
    fileoff = text_seg['fileoff']
    filesize = text_seg['filesize']
    count = 0

    # Make a mutable copy
    data = bytearray(data)

    # Iterate over 4-byte aligned instructions
    for off in range(fileoff, fileoff + filesize - 3, 4):
        word = struct.unpack_from('<I', data, off)[0]
        new_word = strip_pac_instruction(word)
        if new_word != word:
            struct.pack_into('<I', data, off, new_word)
            count += 1

    return data, count

def change_to_arm64(data):
    """Change the Mach-O header from arm64e/macOS to arm64/iOS."""
    data = bytearray(data)
    # CPU subtype: arm64e (2) -> arm64_all (0)
    struct.pack_into('<I', data, 8, CPU_SUBTYPE_ARM64_ALL)

    # Update LC_BUILD_VERSION: change platform from macOS to iOS
    ncmds = struct.unpack_from('<I', data, 16)[0]
    offset = 32
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, offset)
        if cmd == LC_BUILD_VERSION:
            # LC_BUILD_VERSION layout:
            #   uint32 cmd, cmdsize
            #   uint32 platform  (offset +8)
            #   uint32 minos     (offset +12)
            #   uint32 sdk       (offset +16)
            #   uint32 ntools    (offset +20)
            platform = struct.unpack_from('<I', data, offset + 8)[0]
            minos = struct.unpack_from('<I', data, offset + 12)[0]
            sdk = struct.unpack_from('<I', data, offset + 16)[0]
            print(f"    LC_BUILD_VERSION: platform={platform} minos=0x{minos:08x} sdk=0x{sdk:08x}")

            # Change platform to iOS
            struct.pack_into('<I', data, offset + 8, PLATFORM_IOS)

            # Set minos and sdk to iOS 15.0
            # Version is packed as (major << 16) | (minor << 8) | patch
            # iOS 15.0 = 0x000F0000
            struct.pack_into('<I', data, offset + 12, 0x000F0000)  # minos
            struct.pack_into('<I', data, offset + 16, 0x000F0000)  # sdk

            print(f"    Changed to: platform=IOS minos=15.0 sdk=15.0")
        offset += cmdsize

    return data

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input_commerce> <output_commerce_native>", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    print(f"==> Reading {input_path}")
    with open(input_path, 'rb') as f:
        data = f.read()
    print(f"    Size: {len(data)} bytes")

    # Parse Mach-O
    slices = parse_macho_header(data)
    if not slices:
        print("ERROR: Not a valid Mach-O", file=sys.stderr)
        sys.exit(1)

    # Find arm64e slice
    arm64_slice = None
    for fileoff, slice_data, cputype, cpusubtype, ncmds in slices:
        if cputype == CPU_TYPE_ARM64:
            print(f"    Found ARM64 slice: subtype={cpusubtype}, ncmds={ncmds}")
            arm64_slice = slice_data
            break

    if arm64_slice is None:
        print("ERROR: No ARM64 slice found", file=sys.stderr)
        sys.exit(1)

    # Find __TEXT segment
    segments = find_text_segment(arm64_slice)
    text_seg = None
    for seg in segments:
        print(f"    Segment: {seg['name']:16s} vmaddr=0x{seg['vmaddr']:x} vmsize=0x{seg['vmsize']:x} "
              f"fileoff=0x{seg['fileoff']:x} filesize=0x{seg['filesize']:x}")
        if seg['name'] == '__TEXT':
            text_seg = seg

    if text_seg is None:
        print("ERROR: No __TEXT segment found", file=sys.stderr)
        sys.exit(1)

    # Strip PAC instructions
    print(f"==> Stripping PAC from __TEXT (offset=0x{text_seg['fileoff']:x}, size=0x{text_seg['filesize']:x})")
    arm64_slice, pac_count = strip_pac_in_text(arm64_slice, text_seg)
    print(f"    Stripped {pac_count} PAC instructions")

    # Change header from arm64e to arm64
    print("==> Changing CPU subtype from arm64e to arm64")
    arm64_slice = change_to_arm64(arm64_slice)

    # Write output
    print(f"==> Writing {output_path}")
    with open(output_path, 'wb') as f:
        f.write(arm64_slice)
    print(f"    Size: {len(arm64_slice)} bytes")

    print("==> Done. Sign with: ldid -S <output>")

if __name__ == '__main__':
    main()
