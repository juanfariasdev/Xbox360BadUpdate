#!/usr/bin/env python3
"""
nand_info.py — Xbox 360 NAND dump analyzer for BadUpdate exploit porting
==========================================================================

This tool extracts the information needed to port the BadUpdate exploit to a
different kernel version, starting from a raw NAND dump (.bin file).

Usage:
    python3 nand_info.py <nand_dump.bin> [-o <output_dir>]

What it can do WITHOUT the CPU key:
  - Detect the kernel version from bootloader and XEX2 headers
  - Locate and extract raw kernel (xboxkrnl.exe) and XAM (xam.xex) XEX2 binaries

IMPORTANT — XEX2 files do NOT need the CPU key to decrypt:
  XEX2 files (xboxkrnl.exe, xam.xex, bootanim.xex, etc.) are encrypted with
  the well-known RETAIL XEX2 key, which is the same public key used by official
  Microsoft update packages. The CPU key is NOT required.

  Decrypt with xextool using the retail key:
      xextool -e retail xboxkrnl.exe
  (or with explicit key: xextool -k <RETAIL_KEY_HEX> xboxkrnl.exe)

  This gives you Categories 1–5 of the portability data without the CPU key.
  See 'Tools/update_info.py' for a higher-level workflow using official update
  packages, which are even easier to work with.

What DOES require the CPU key:
  - Decrypting the HV binary (embedded in bootloaders, per-console protection)
  - Extracting Stage4_CleanHvData_Retail_<ver>.bin
  These are Category 6 of the portability data.

  The CPU key is stored in the CPU eFuses and is NOT present in the NAND dump.
  The easiest way to obtain it is to run the BadUpdate exploit itself, then use
  the hypervisor-level access to read the eFuse registers.

See the README section "Sem a CPU key: usando o pacote de atualização oficial"
and "Extraindo a CPU key via BadUpdate" for the complete workflow.
"""

import argparse
import os
import struct
import sys


# ---------------------------------------------------------------------------
# NAND format constants
# ---------------------------------------------------------------------------

# Small-block NAND (Zephyr, Falcon, Opus, Jasper 16MB):
#   1024 blocks × 32 pages/block = 32,768 pages
#   Each page: 512 bytes data + 16 bytes ECC/spare = 528 bytes
NAND_SMALL_PAGE_DATA = 0x200       # 512 bytes of payload per page
NAND_SMALL_PAGE_SPARE = 0x10      # 16 bytes ECC/spare per page
NAND_SMALL_PAGE_TOTAL = NAND_SMALL_PAGE_DATA + NAND_SMALL_PAGE_SPARE  # 528

NAND_SMALL_PAGES_PER_BLOCK = 32
NAND_SMALL_TOTAL_BLOCKS = 1024
NAND_SMALL_TOTAL_PAGES = NAND_SMALL_TOTAL_BLOCKS * NAND_SMALL_PAGES_PER_BLOCK  # 32768

NAND_SIZE_SMALL_NO_SPARE = NAND_SMALL_TOTAL_PAGES * NAND_SMALL_PAGE_DATA   # 0x01000000 (16 MB)
NAND_SIZE_SMALL_WITH_SPARE = NAND_SMALL_TOTAL_PAGES * NAND_SMALL_PAGE_TOTAL  # 0x01080000 (~16.5 MB)

# Big-block Jasper (256 MB / 512 MB) and Trinity/Corona (eMMC 4 GB) are not
# handled by this script — they use a different filesystem layout and are
# typically much larger.


# ---------------------------------------------------------------------------
# Xbox 360 bootloader magic words (big-endian 16-bit values at offset 0 of
# each bootloader stage).  Source: free60 wiki / JRunner community docs.
# ---------------------------------------------------------------------------

BOOTLOADER_MAGIC = {
    0x0200: "CB-A  (Falcon / Opus)",
    0x0210: "CB-B  (Falcon / Opus)",
    0x0220: "CB-B  (Jasper 16 MB)",
    0x0230: "CB-B  (Jasper 256/512 MB)",
    0x0240: "CB    (Trinity / Corona)",
    0x0300: "CD    (all revisions)",
    0x0340: "CF    (all revisions)",
    0x0360: "CG    (all revisions)",
}

# Bootloader header structure (big-endian):
#   +0x00  WORD   magic
#   +0x02  WORD   build / version
#   +0x04  DWORD  flags
#   +0x08  QWORD  entry point (virtual)
#   +0x10  DWORD  size (bytes, including header)
#   +0x14  DWORD  ...
BOOTLOADER_MAGIC_OFFSET = 0x00
BOOTLOADER_VERSION_OFFSET = 0x02
BOOTLOADER_SIZE_OFFSET = 0x10

# The CB stage lives at block 1 in small-block NANDs (byte offset 0x4000).
CB_BLOCK_OFFSET = 1 * NAND_SMALL_PAGES_PER_BLOCK * NAND_SMALL_PAGE_DATA   # 0x4000


# ---------------------------------------------------------------------------
# XEX2 (Xbox Executable version 2) constants
# ---------------------------------------------------------------------------

XEX2_MAGIC = b"XEX2"   # 0x58455832

# XEX2 file header (all big-endian):
#   +0x00  DWORD  magic = 0x58455832
#   +0x04  DWORD  module_flags
#   +0x08  DWORD  code_offset  (offset of encrypted PE image from start of file)
#   +0x0C  DWORD  reserved
#   +0x10  DWORD  security_header_offset
#   +0x14  DWORD  optional_header_count
#   +0x18  optional_header_count × 8-byte directory entries follow

# XEX2 optional header directory entry (big-endian):
#   +0x00  DWORD  key   : upper byte = entry size class, lower 24 bits = header type
#   +0x04  DWORD  value : if key >> 24 == 0: value is the data itself
#                         if key >> 24 == 1: value is offset from file start to 4-byte data
#                         if key >> 24 >  1: value is offset from file start to block of data
#                                            where the first DWORD is the block size in DWORDs

XEX_OPT_HEADER_EXECUTION_ID = 0x00040006

# Sanity-check limits used when parsing XEX2 in a raw NAND scan.
# Real XEX2 files have far fewer optional headers; 256 rules out noise.
MAX_REASONABLE_OPT_HEADERS = 256
# code_offset in a well-formed XEX2 should be well under 256 MB;
# values larger than this indicate a false XEX2 magic match.
MAX_REASONABLE_CODE_OFFSET = 0x10000000      # 256 MB
# Cap on the byte length we'll extract for a single XEX2 blob;
# real system XEX2 files (kernel, XAM) are at most a few MB.
MAX_XEX2_EXTRACT_SIZE = 0x02000000           # 32 MB

# Execution ID block layout (at the offset pointed to by the directory entry):
#   +0x00  DWORD  media_id
#   +0x04  DWORD  version     : bits 31-28 = major, 27-24 = minor, 23-8 = build, 7-0 = QFE
#   +0x08  DWORD  base_version
#   +0x0C  DWORD  title_id
#   +0x10  BYTE   platform
#   +0x11  BYTE   executable_type
#   +0x12  BYTE   disc_number
#   +0x13  BYTE   disc_count
#   +0x14  DWORD  savegame_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def strip_spare_bytes(data: bytes) -> bytes:
    """Remove the 16-byte ECC/spare field from every page in a NAND dump that
    was captured with the spare area included (0x1080000-byte dumps)."""
    out = bytearray()
    offset = 0
    while offset + NAND_SMALL_PAGE_TOTAL <= len(data):
        out.extend(data[offset: offset + NAND_SMALL_PAGE_DATA])
        offset += NAND_SMALL_PAGE_TOTAL
    return bytes(out)


def detect_and_normalize(data: bytes):
    """Detect the NAND dump format and return (normalized_data, description)."""
    size = len(data)
    if size == NAND_SIZE_SMALL_NO_SPARE:
        return data, "16 MB small-block (no spare bytes)"
    if size == NAND_SIZE_SMALL_WITH_SPARE:
        normalized = strip_spare_bytes(data)
        return normalized, f"16 MB small-block (WITH spare bytes — stripped to {len(normalized):#010x} bytes)"
    # Fall through: unsupported / large NAND — attempt anyway on raw data
    return data, (
        f"Unrecognized size {size:#010x} ({size / 1024 / 1024:.1f} MB). "
        "Proceeding as flat binary — results may be partial."
    )


def _read_u16be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0]


def _read_u32be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


# ---------------------------------------------------------------------------
# Bootloader analysis
# ---------------------------------------------------------------------------

def try_parse_bootloader(data: bytes, byte_offset: int, label: str) -> dict | None:
    """Attempt to parse a bootloader header at *byte_offset*.
    Returns a dict with fields, or None if the magic is unrecognised."""
    if byte_offset + 0x20 > len(data):
        return None
    magic = _read_u16be(data, byte_offset + BOOTLOADER_MAGIC_OFFSET)
    if magic not in BOOTLOADER_MAGIC:
        return None
    version = _read_u16be(data, byte_offset + BOOTLOADER_VERSION_OFFSET)
    size = _read_u32be(data, byte_offset + BOOTLOADER_SIZE_OFFSET)
    return {
        "label": label,
        "offset": byte_offset,
        "magic": magic,
        "magic_name": BOOTLOADER_MAGIC[magic],
        "version": version,
        "size": size,
    }


def find_bootloaders(data: bytes) -> list[dict]:
    """Scan the first 0x80000 bytes (blocks 0-31) for known bootloader magic
    values at block-aligned offsets."""
    results = []
    block_size = NAND_SMALL_PAGES_PER_BLOCK * NAND_SMALL_PAGE_DATA  # 0x4000
    scan_blocks = min(32, len(data) // block_size)
    for block_idx in range(scan_blocks):
        byte_off = block_idx * block_size
        info = try_parse_bootloader(data, byte_off, f"block {block_idx}")
        if info:
            results.append(info)
    return results


# ---------------------------------------------------------------------------
# XEX2 scanning and parsing
# ---------------------------------------------------------------------------

def find_xex2_offsets(data: bytes) -> list[int]:
    """Return all byte offsets where a XEX2 magic string appears."""
    offsets = []
    start = 0
    while True:
        pos = data.find(XEX2_MAGIC, start)
        if pos == -1:
            break
        offsets.append(pos)
        start = pos + 4
    return offsets


def parse_xex2_header(data: bytes, base: int) -> dict | None:
    """Parse a XEX2 header at *base*.  Returns a dict on success, None if the
    header looks malformed."""
    if base + 0x20 > len(data):
        return None
    if data[base: base + 4] != XEX2_MAGIC:
        return None

    module_flags = _read_u32be(data, base + 0x04)
    code_offset = _read_u32be(data, base + 0x08)
    security_offset = _read_u32be(data, base + 0x10)
    opt_count = _read_u32be(data, base + 0x14)

    # Sanity: reject obviously bogus headers
    if opt_count > MAX_REASONABLE_OPT_HEADERS or code_offset > MAX_REASONABLE_CODE_OFFSET:
        return None

    # Build the optional-header directory
    opt_headers: dict[int, int] = {}
    dir_base = base + 0x18
    for i in range(opt_count):
        entry_off = dir_base + i * 8
        if entry_off + 8 > len(data):
            break
        key = _read_u32be(data, entry_off)
        val = _read_u32be(data, entry_off + 4)
        opt_headers[key] = val

    result: dict = {
        "offset": base,
        "module_flags": module_flags,
        "code_offset": code_offset,
        "security_offset": security_offset,
        "opt_headers": opt_headers,
        "version": None,
        "title_id": None,
    }

    # Try to extract execution-ID / version info
    exec_id_key = XEX_OPT_HEADER_EXECUTION_ID
    if exec_id_key in opt_headers:
        exec_id_off = base + opt_headers[exec_id_key]
        if exec_id_off + 0x18 <= len(data):
            # First DWORD of the block is its size (in DWORDs); actual data follows
            block_size_dwords = _read_u32be(data, exec_id_off)
            data_off = exec_id_off + 4  # skip the block-size field
            if data_off + 0x14 <= len(data) and block_size_dwords >= 5:
                media_id = _read_u32be(data, data_off + 0x00)
                version_raw = _read_u32be(data, data_off + 0x04)
                title_id = _read_u32be(data, data_off + 0x0C)

                major = (version_raw >> 28) & 0xF
                minor = (version_raw >> 24) & 0xF
                build = (version_raw >> 8) & 0xFFFF
                qfe = version_raw & 0xFF

                result["version"] = {
                    "major": major,
                    "minor": minor,
                    "build": build,
                    "qfe": qfe,
                    "raw": version_raw,
                }
                result["title_id"] = title_id
                result["media_id"] = media_id

    return result


def extract_xex2(data: bytes, base: int, header: dict, out_dir: str) -> str:
    """Extract the raw (encrypted) XEX2 blob starting at *base* to *out_dir*.
    Returns the path of the written file."""
    # The encrypted PE starts at code_offset bytes from the start of the XEX2
    # blob; use that as the approximate size boundary, capped at 32 MB.
    code_off = header.get("code_offset", 0)
    # Estimate: find next XEX2 magic or use a generous cap
    next_pos = data.find(XEX2_MAGIC, base + 4)
    if next_pos == -1 or (next_pos - base) > MAX_XEX2_EXTRACT_SIZE:
        end = min(base + MAX_XEX2_EXTRACT_SIZE, len(data))
    else:
        end = next_pos

    name = f"xex2_offset_0x{base:08X}.xex"
    path = os.path.join(out_dir, name)
    with open(path, "wb") as fh:
        fh.write(data[base: end])
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Xbox 360 NAND dump analyzer — extract kernel version and raw XEX binaries"
    )
    parser.add_argument("nand_dump", help="Path to the NAND dump .bin file")
    parser.add_argument(
        "-o", "--output",
        default="nand_extracted",
        help="Directory to write extracted files into (default: nand_extracted/)",
    )
    parser.add_argument(
        "--no-extract",
        action="store_true",
        help="Skip writing XEX2 files to disk (analysis only)",
    )
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Load and normalize
    # ------------------------------------------------------------------
    print(f"[*] Loading: {args.nand_dump}")
    try:
        with open(args.nand_dump, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        print(f"[!] Cannot open file: {exc}")
        return 1

    print(f"[*] File size : {len(raw):#010x} bytes  ({len(raw) / 1024 / 1024:.2f} MB)")
    data, fmt_desc = detect_and_normalize(raw)
    print(f"[*] Format    : {fmt_desc}")
    if len(data) != len(raw):
        print(f"[*] After strip: {len(data):#010x} bytes")

    if not args.no_extract:
        os.makedirs(args.output, exist_ok=True)

    # ------------------------------------------------------------------
    # Bootloader scan
    # ------------------------------------------------------------------
    print("\n[*] Scanning for bootloader headers …")
    bootloaders = find_bootloaders(data)
    if bootloaders:
        for bl in bootloaders:
            print(
                f"    offset 0x{bl['offset']:08X}  magic=0x{bl['magic']:04X}"
                f"  {bl['magic_name']:<30}  version={bl['version']:5d} (0x{bl['version']:04X})"
                f"  size=0x{bl['size']:X}"
            )
    else:
        print("    No known bootloader magic found in the first 32 blocks.")
        print("    The dump may use a big-block or eMMC layout (not yet supported),")
        print("    or the data may be scrambled / not a valid NAND dump.")

    # ------------------------------------------------------------------
    # XEX2 scan
    # ------------------------------------------------------------------
    print("\n[*] Scanning for XEX2 binaries …")
    xex_offsets = find_xex2_offsets(data)
    print(f"    Found {len(xex_offsets)} XEX2 magic occurrence(s)")

    kernel_build: int | None = None
    parsed_xex2: list[dict] = []

    for pos in xex_offsets:
        hdr = parse_xex2_header(data, pos)
        if hdr is None:
            continue
        parsed_xex2.append(hdr)

        ver = hdr.get("version")
        title_id = hdr.get("title_id")
        ver_str = "?"
        if ver:
            ver_str = (
                f"{ver['major']}.{ver['minor']}.{ver['build']}.{ver['qfe']}"
                f"  (build {ver['build']} = 0x{ver['build']:04X})"
            )

        print(f"\n    XEX2 at 0x{pos:08X}:")
        print(f"      module_flags    = 0x{hdr['module_flags']:08X}")
        print(f"      code_offset     = 0x{hdr['code_offset']:08X}")
        print(f"      version         = {ver_str}")
        if title_id is not None:
            print(f"      title_id        = 0x{title_id:08X}", end="")
            if title_id == 0x00000000:
                print("  ← likely kernel (xboxkrnl.exe)")
            elif title_id == 0x58584D58:  # 'XXMX'
                print("  ← likely XAM (xam.xex)")
            else:
                print()

        # Identify the kernel: title_id == 0, build number > 1000
        if ver and title_id == 0 and ver["build"] > 1000 and kernel_build is None:
            kernel_build = ver["build"]
            print(f"      *** Identified as kernel — build {kernel_build} ***")

        if not args.no_extract:
            path = extract_xex2(data, pos, hdr, args.output)
            print(f"      Extracted (raw/encrypted) → {path}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    if kernel_build:
        print(f"\n  Kernel version : {kernel_build}  (0x{kernel_build:04X})")
        print(f"  KernelConfig   : Common/KernelConfig_Retail_{kernel_build}.asm")
    else:
        print("\n  [!] Kernel version could not be determined automatically.")
        print("      Possible reasons:")
        print("        - The XEX2 execution-ID header is missing or malformed")
        print("        - The NAND filesystem stores the kernel in a compressed/")
        print("          wrapped format that has a different magic before XEX2")
        print("        - The dump is from an eMMC (Slim) console — not yet supported")
        print("      Try loading the extracted XEX2 files in xextool or XeXTract")
        print("      to identify the kernel version manually.")

    if parsed_xex2 and not args.no_extract:
        print(f"\n  Extracted {len(parsed_xex2)} XEX2 file(s) → {args.output}/")

    print("""
  What you can do with the extracted XEX2 files:
  ─────────────────────────────────────────────
    • Determine the kernel version (done above if successful)
    • Open in xextool / XeXTract to view the XEX2 header metadata
    • Decrypt with the RETAIL XEX2 key (no CPU key needed!):

        xextool -e retail xex2_offset_0xXXXXXXXX.xex
        # or: python3 Tools/update_info.py $SystemUpdate/  (official update package)

    • Load the decrypted binary in IDA Pro or Ghidra (PowerPC BE, 64-bit)
      to find the function addresses and ROP gadgets required in KernelConfig

  Key clarification — what needs the CPU key vs. the retail key:
  ─────────────────────────────────────────────────────────────
    • xboxkrnl.exe + xam.xex → encrypted with RETAIL KEY (public, no CPU key needed)
    • bootanim.xex and other XEX2 files → same retail key
    • HV binary (in bootloaders) → CPU-key-derived protection (Category 6 only)

  NOTE: If you do not have the CPU key yet, you can still port and run the
  exploit using only the official $SystemUpdate package for your kernel version.
  The exploit itself (when run successfully) gives you Ring -1 access that can
  be used to read the CPU key from the eFuse registers.

  See the README section "Sem a CPU key: usando o pacote de atualizacao oficial"
  and "Extraindo a CPU key via BadUpdate" for the complete porting guide.
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
