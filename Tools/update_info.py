#!/usr/bin/env python3
"""
update_info.py — Xbox 360 official system update package analyzer
==================================================================

Analyzes an official Xbox 360 $SystemUpdate directory (or a single XEX2 file)
to identify the kernel version and generate the xextool commands needed to
decrypt each binary for use in BadUpdate exploit porting.

Usage:
    python3 Tools/update_info.py <$SystemUpdate_dir_or_xex_file>

Background:
    Official Xbox 360 system update packages are distributed as a directory
    called "$SystemUpdate" containing XEX2 files such as xboxkrnl.exe and
    xam.xex. These files are encrypted with the well-known RETAIL XEX2 key,
    NOT with the per-console CPU key. This means:

      - You do NOT need your CPU key to decrypt them.
      - The same binaries (same build number) look identical on every console.
      - Addresses found in these decrypted binaries are valid for ALL consoles
        running that kernel version.

    This makes official update packages the easiest source for porting data
    (Categories 1-5 in the multi-kernel portability guide).

    Only Category 6 (hypervisor internals) requires the CPU key, because the
    HV binary is embedded in the bootloader chain and uses a per-console key
    derivation for its integrity verification.

    See the README section "Sem a CPU key: usando o pacote de atualizacao
    oficial" for the complete porting workflow.
"""

import argparse
import os
import struct
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Known Xbox 360 system file catalog
# Each entry: filename (lowercase) → (description, categories_needed, notes)
# ---------------------------------------------------------------------------

KNOWN_SYSTEM_FILES: dict[str, tuple[str, list[str], str]] = {
    "xboxkrnl.exe": (
        "Xbox 360 Kernel",
        ["Category 1", "Category 3", "Category 4", "Category 5 (partial)"],
        "Main kernel binary. Contains exported functions, syscall ordinals, "
        "ROP gadgets, and the code page allocator for bootanim.",
    ),
    "xam.xex": (
        "Xbox Application Manager",
        ["Category 2", "Category 4"],
        "Dashboard system binary. Contains XAM exported functions and ROP gadgets.",
    ),
    "bootanim.xex": (
        "Boot Animation XEX",
        ["Category 5"],
        "Boot animation binary. Its load address determines BootAnimCodePageAddress.",
    ),
    "xbdm.xex": (
        "Xbox Debug Manager",
        [],
        "Debug monitor. Not needed for porting; may be absent in some updates.",
    ),
    "xhttp.xex": (
        "Xbox HTTP Library",
        [],
        "HTTP stack. Not needed for porting.",
    ),
    "xonline.xex": (
        "Xbox Online Services",
        [],
        "Online services library. Not needed for porting.",
    ),
    "xgraphics.xex": (
        "Xbox Graphics Library",
        [],
        "Graphics library. Not needed for porting.",
    ),
    "xstudio.xex": (
        "Xbox Live Vision Studio",
        [],
        "Camera support. Not needed for porting.",
    ),
}

# Files to prioritize in the output
PRIORITY_FILES = ["xboxkrnl.exe", "xam.xex", "bootanim.xex"]


# ---------------------------------------------------------------------------
# XEX2 parsing (minimal, same approach as nand_info.py)
# ---------------------------------------------------------------------------

XEX2_MAGIC = b"XEX2"
XEX_OPT_HEADER_EXECUTION_ID = 0x00040006

# Number of bytes to read from a XEX2 file to cover the full header region.
# Real XEX2 optional header directories are well within 2 KB; 2 KB is ample.
XEX2_HEADER_READ_SIZE = 0x800          # 2 KB

# Real XEX2 files have far fewer optional headers; 256 rules out noise/corrupt data.
MAX_REASONABLE_OPT_HEADERS = 256


def _read_u32be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def parse_xex2_header(data: bytes) -> dict | None:
    """Parse a XEX2 header from *data* (full file content).
    Returns a dict with parsed fields, or None if invalid."""
    if len(data) < 0x20:
        return None
    if data[0:4] != XEX2_MAGIC:
        return None

    module_flags = _read_u32be(data, 0x04)
    # Offset of the encrypted PE image from the start of the XEX2 file.
    pe_image_offset = _read_u32be(data, 0x08)
    opt_count = _read_u32be(data, 0x14)

    if opt_count > MAX_REASONABLE_OPT_HEADERS:
        return None

    opt_headers: dict[int, int] = {}
    dir_base = 0x18
    for i in range(opt_count):
        entry_off = dir_base + i * 8
        if entry_off + 8 > len(data):
            break
        key = _read_u32be(data, entry_off)
        val = _read_u32be(data, entry_off + 4)
        opt_headers[key] = val

    result: dict = {
        "module_flags": module_flags,
        "pe_image_offset": pe_image_offset,
        "opt_headers": opt_headers,
        "version": None,
        "title_id": None,
        "media_id": None,
    }

    exec_id_key = XEX_OPT_HEADER_EXECUTION_ID
    if exec_id_key in opt_headers:
        exec_id_off = opt_headers[exec_id_key]
        if exec_id_off + 8 <= len(data):
            block_size_dwords = _read_u32be(data, exec_id_off)
            data_off = exec_id_off + 4
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


def load_xex2_file(path: str) -> dict | None:
    """Load and parse a XEX2 file. Returns parsed header dict or None."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(XEX2_HEADER_READ_SIZE)
    except OSError:
        return None
    return parse_xex2_header(data)


# ---------------------------------------------------------------------------
# Scan helpers
# ---------------------------------------------------------------------------

def find_xex2_files(directory: str) -> list[tuple[str, str]]:
    """Return list of (filename_lower, full_path) for XEX2 files in *directory*."""
    results = []
    try:
        entries = sorted(Path(directory).iterdir())
    except OSError as exc:
        print(f"[!] Cannot read directory: {exc}")
        return results

    for entry in entries:
        if not entry.is_file():
            continue
        try:
            with open(entry, "rb") as fh:
                magic = fh.read(4)
        except OSError:
            continue
        if magic == XEX2_MAGIC:
            results.append((entry.name.lower(), str(entry)))
    return results


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

RETAIL_KEY_NOTE = (
    "20B185A59D28FDF05A249AD90C8B3E2A  (retail system XEX key — publicly known)"
)


def format_xextool_cmd(xex_path: str, output_suffix: str = "_dec") -> str:
    """Return an example xextool command for decrypting *xex_path*."""
    base = os.path.splitext(os.path.basename(xex_path))[0]
    out = base + output_suffix + ".bin"
    return f"xextool -e retail \"{os.path.basename(xex_path)}\" -o \"{out}\""


def print_section(title: str) -> None:
    print(f"\n  {'─' * (len(title) + 2)}")
    print(f"  {title}")
    print(f"  {'─' * (len(title) + 2)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze an Xbox 360 official $SystemUpdate directory or XEX2 file.\n"
            "Reports kernel version and prints xextool commands for porting."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        help=(
            "Path to the $SystemUpdate directory, or a single XEX2 file "
            "(e.g., xboxkrnl.exe)"
        ),
    )
    args = parser.parse_args()

    input_path = args.path
    is_dir = os.path.isdir(input_path)
    is_file = os.path.isfile(input_path)

    if not is_dir and not is_file:
        print(f"[!] Path not found: {input_path}")
        return 1

    # ------------------------------------------------------------------
    # Collect XEX2 files to analyze
    # ------------------------------------------------------------------
    if is_file:
        filename_lower = os.path.basename(input_path).lower()
        xex_files = [(filename_lower, input_path)]
    else:
        print(f"[*] Scanning directory: {input_path}")
        xex_files = find_xex2_files(input_path)
        print(f"    Found {len(xex_files)} XEX2 file(s)")

    if not xex_files:
        print("[!] No XEX2 files found.")
        print("    Make sure you are pointing at a directory containing .exe/.xex files")
        print("    with the XEX2 magic bytes, e.g. the $SystemUpdate folder from an")
        print("    Xbox 360 system update package.")
        return 1

    # ------------------------------------------------------------------
    # Parse each file
    # ------------------------------------------------------------------
    results: list[dict] = []
    kernel_build: int | None = None
    kernel_path: str | None = None

    # Sort: priority files first, then everything else alphabetically
    def sort_key(item: tuple[str, str]) -> tuple[int, str]:
        name = item[0]
        try:
            return (PRIORITY_FILES.index(name), name)
        except ValueError:
            return (len(PRIORITY_FILES), name)

    for fname_lower, fpath in sorted(xex_files, key=sort_key):
        hdr = load_xex2_file(fpath)
        if hdr is None:
            continue

        ver = hdr.get("version")
        title_id = hdr.get("title_id")

        catalog = KNOWN_SYSTEM_FILES.get(fname_lower)
        desc = catalog[0] if catalog else "Unknown XEX2"
        categories = catalog[1] if catalog else []

        ver_str = "?"
        build = None
        if ver:
            build = ver["build"]
            ver_str = f"{ver['major']}.{ver['minor']}.{ver['build']}.{ver['qfe']}"

        results.append({
            "fname": os.path.basename(fpath),
            "fname_lower": fname_lower,
            "path": fpath,
            "desc": desc,
            "categories": categories,
            "version": ver,
            "version_str": ver_str,
            "title_id": title_id,
            "build": build,
            "hdr": hdr,
        })

        # Track kernel version
        if fname_lower == "xboxkrnl.exe" and build:
            kernel_build = build
            kernel_path = fpath
        elif title_id == 0 and build and build > 1000 and kernel_build is None:
            kernel_build = build
            kernel_path = fpath

    # ------------------------------------------------------------------
    # Print file summary table
    # ------------------------------------------------------------------
    print("\n" + "=" * 72)
    print("  FILE SUMMARY")
    print("=" * 72)
    print(f"\n  {'File':<24} {'Version':<22} {'Description'}")
    print(f"  {'────':<24} {'───────':<22} {'───────────'}")
    for r in results:
        print(f"  {r['fname']:<24} {r['version_str']:<22} {r['desc']}")

    # ------------------------------------------------------------------
    # Kernel version
    # ------------------------------------------------------------------
    print()
    if kernel_build:
        print(f"  Detected kernel version : {kernel_build}  (0x{kernel_build:04X})")
        print(f"  KernelConfig to create  : Common/KernelConfig_Retail_{kernel_build}.asm")
    else:
        print("  [!] Kernel version could not be determined from available files.")
        print("      Make sure xboxkrnl.exe is present in the directory.")

    # ------------------------------------------------------------------
    # Encryption key clarification
    # ------------------------------------------------------------------
    print_section("ENCRYPTION: NO CPU KEY REQUIRED")
    print(f"""
    All XEX2 files in official system update packages are encrypted with the
    RETAIL XEX2 key — a well-known public constant, NOT your console's CPU key.

    Retail key : {RETAIL_KEY_NOTE}

    This means you can decrypt xboxkrnl.exe, xam.xex, and bootanim.xex to find
    ALL the addresses in Categories 1-5 of the porting guide without a CPU key.

    Only Category 6 (hypervisor internals) requires the CPU key, because the HV
    binary is embedded in the bootloader chain with per-console protection.
""")

    # ------------------------------------------------------------------
    # xextool commands
    # ------------------------------------------------------------------
    print_section("XEXTOOL COMMANDS (decrypt with retail key)")
    print()
    for r in results:
        if not r["categories"]:
            continue    # skip files not needed for porting
        cmd = format_xextool_cmd(r["path"])
        print(f"    # {r['desc']}  →  {', '.join(r['categories'])}")
        print(f"    {cmd}")
        print()

    if results and not any(r["categories"] for r in results):
        # All files are non-essential; print commands for everything anyway
        for r in results:
            cmd = format_xextool_cmd(r["path"])
            print(f"    # {r['desc']}")
            print(f"    {cmd}")
            print()

    # ------------------------------------------------------------------
    # What to look for after decryption
    # ------------------------------------------------------------------
    print_section("WHAT TO FIND AFTER DECRYPTION (IDA Pro / Ghidra, PPC64 BE)")
    print(f"""
    xboxkrnl.exe  (decrypted)  →  Categories 1, 3, 4, 5
    ─────────────────────────────────────────────────────
    Category 1 — Kernel function addresses:
      XexLoadImage, XexLoadExecutable, XexUnloadImage, MmAllocatePhysicalMemory,
      MmFreePhysicalMemory, IoCreateDevice, IoDeleteDevice, ExAllocatePoolWithTag,
      MmGetPhysicalAddress, KeGetCurrentProcessType, ZwQueryVirtualMemory,
      HalDiskCachePartitionCount, ObReferenceObjectByHandle, etc.
      → Search for these by name in the kernel export table

    Category 3 — Syscall ordinals:
      Wrap functions like HvpXexLoadImageFromMemory, XexGetModuleHandle, etc.
      → Search for 'li r0, <ordinal> ; sc' patterns near known syscall wrappers

    Category 4 — ROP gadgets in kernel:
      Look for short gadget sequences ending in 'blr' or 'bctr'
      e.g. 'ld r0, X(r1) ; mtlr r0 ; ... ; blr'
      → Byte-pattern scan of the decrypted binary

    Category 5 — BootAnimCodePageAddress:
      Find where the kernel maps bootanim.xex's code segment
      → Search for code that calls XexLoadExecutable with bootanim path,
        then reads the resulting code page VA

    xam.xex  (decrypted)  →  Categories 2, 4
    ──────────────────────────────────────────
    Category 2 — XAM function addresses:
      XamGetCurrentTitleId, XamTaskCloseHandle, XamTaskSchedule, etc.
      → XAM exports its functions; look them up in the XEX2 export table

    Category 4 — ROP gadgets in XAM:
      Same technique as for the kernel

    bootanim.xex  (decrypted)  →  Category 5
    ──────────────────────────────────────────
    Category 5 — BootAnimCodePageAddress:
      The VA of bootanim.xex's first code segment in memory
      → Parse the XEX2 security header: 'image_base_address' + first section offset
      → Typically 0x8xxxxxxx; see KernelConfig_Retail_17559.asm for the known value

    HV binary  (requires CPU key)  →  Category 6
    ─────────────────────────────────────────────
    Category 6 data CANNOT come from the update package — the HV binary is not
    distributed separately. It is embedded in the bootloader chain in NAND and
    is protected per-console by the CPU key.
    → Use BadUpdate to get Ring -1 access, then read eFuse registers to get the
      CPU key. See README "Extraindo a CPU key via BadUpdate".
""")

    # ------------------------------------------------------------------
    # Next steps
    # ------------------------------------------------------------------
    if kernel_build:
        print_section(f"NEXT STEPS FOR KERNEL {kernel_build}")
        print(f"""
    1. Decrypt xboxkrnl.exe and xam.xex using the xextool commands above
    2. Load decrypted binaries in IDA Pro or Ghidra (PowerPC 64-bit, big-endian)
    3. Find all addresses listed in the "Categoria 1-5" sections of the README
    4. Create Common/KernelConfig_Retail_{kernel_build}.asm with those values
    5. Update Common/BuildConfig.asm to include the new kernel version
    6. Update Stage4/BadUpdateExploit-4thStage.asm with HV-specific data
       (Category 6 — requires CPU key; see README "Extraindo a CPU key via BadUpdate")
    7. Build the exploit: run build_exploit.bat
    8. Run the exploit on your console to get Ring -1 access
    9. After the exploit succeeds, a custom XKE payload reads eFuse registers
       and writes the CPU key to a USB file (see README for details)
   10. Use the CPU key to create a clean NAND image with xeBuild
""")

    return 0


if __name__ == "__main__":
    sys.exit(main())
