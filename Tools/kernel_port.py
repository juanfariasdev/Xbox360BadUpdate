#!/usr/bin/env python3
"""
kernel_port.py — Xbox 360 kernel address extractor for BadUpdate exploit porting
==================================================================================

Parses one or more *decrypted* XEX2 files (xboxkrnl.exe, xam.xex, bootanim.xex)
and automatically extracts every address required to fill in a
``Common/KernelConfig_Retail_<build>.asm`` file.

The script finds:
  • Kernel function addresses (via XEX2/PE export table)
  • Syscall ordinals and the addresses of their kernel stub functions
    (by scanning for ``li r0, <ordinal> ; sc`` byte patterns)
  • All ROP gadgets used by the BadUpdate exploit (byte-pattern scan)
  • XAM function addresses (via XAM export table, by ordinal)
  • BootAnimCodePageAddress (image base of bootanim.xex)

When --output is specified the script also writes a ready-to-edit
``KernelConfig_Retail_<build>.asm`` file pre-filled with every value that was
found, and with ``# TODO`` markers on every value that still needs to be filled
in manually (e.g. Category 6 hypervisor internals that require the CPU key).

Usage
-----
  # Analyse all three files and print results to the terminal:
  python3 Tools/kernel_port.py \\
      --kernel  path/to/xboxkrnl_dec.bin \\
      --xam     path/to/xam_dec.bin \\
      --bootanim path/to/bootanim_dec.bin

  # Same, but also write the KernelConfig .asm file:
  python3 Tools/kernel_port.py \\
      --kernel  path/to/xboxkrnl_dec.bin \\
      --xam     path/to/xam_dec.bin \\
      --bootanim path/to/bootanim_dec.bin \\
      --output  Common/

Prerequisites
-------------
  The XEX2 files must be *decrypted* before passing them to this tool.
  Use xextool with the public retail key (no CPU key required):

      xextool -e retail xboxkrnl.exe -o xboxkrnl_dec.bin
      xextool -e retail xam.xex      -o xam_dec.bin
      xextool -e retail bootanim.xex -o bootanim_dec.bin

  The retail key is the well-known public constant
  20B185A59D28FDF05A249AD90C8B3E2A — it is NOT your console's CPU key.
  All official system update packages use this key for their XEX2 files.

Background on XEX2 decryption
------------------------------
  Xbox 360 executables ship as XEX2-wrapped PE binaries.  The outer XEX2
  envelope carries a security certificate and (for retail builds) AES-128
  encryption over the PE image.  Microsoft distributes official update
  packages ($SystemUpdate directories) using a well-known, publicly-reversed
  AES key.  xextool applies this key and writes back the decrypted PE in-place
  inside the XEX2 file, preserving the XEX2 header so that metadata such as
  the load address and export table VA remain accessible.
"""

import argparse
import os
import struct
import sys
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# XEX2 format constants
# ---------------------------------------------------------------------------

XEX2_MAGIC = b"XEX2"  # 0x58455832

# XEX2 file header layout (all fields big-endian):
#   +0x00  DWORD  magic
#   +0x04  DWORD  module_flags
#   +0x08  DWORD  code_offset   (file offset of the encrypted/decrypted PE image)
#   +0x0C  DWORD  reserved
#   +0x10  DWORD  security_info_offset
#   +0x14  DWORD  optional_header_count
#   +0x18  optional_header_count × 8 bytes: (key, value) pairs

# XEX2 optional header key semantics (upper byte = size class):
#   upper byte == 0x00 : value IS the inline 32-bit datum
#   upper byte == 0x01 : value is a file offset to one DWORD (no size prefix)
#   upper byte >= 0x02 : value is a file offset; first DWORD at that offset
#                        is the block size (in DWORDs, including the size DWORD)
#   upper byte == 0xFF : value is a file offset to variable-length data
#                        (first DWORD = block size in DWORDs)

XEX_OPT_EXECUTION_ID  = 0x00040006   # execution / version information block
XEX_OPT_EXPORT_TABLE  = 0x00400100   # VA of the IMAGE_EXPORT_DIRECTORY (inline)
XEX_OPT_BASE_ADDRESS  = 0x00010201   # image base VA (inline; present in all retail XEX2s)

MAX_OPT_HEADERS       = 256          # sanity cap

# XEX2 security certificate layout (at security_info_offset, all big-endian):
#   +0x000  DWORD  page_descriptor_count
#   +0x004  DWORD  info_size (total byte length of this structure)
#   +0x008  BYTE[0x100]  rsa_signature
#   +0x108  DWORD  image_flags
#   +0x10C  DWORD  load_address  ← image base VA (may read 0 in encrypted files;
#                                   prefer XEX_OPT_BASE_ADDRESS optional header instead)
SECURITY_CERT_LOAD_ADDR_OFF = 0x10C


# ---------------------------------------------------------------------------
# PPC instruction encoders  (return big-endian bytes)
# ---------------------------------------------------------------------------

def _ppc(val: int) -> bytes:
    return struct.pack(">I", val & 0xFFFFFFFF)

def _addi(rD: int, rA: int, simm: int) -> bytes:
    return _ppc((14 << 26) | (rD << 21) | (rA << 16) | (simm & 0xFFFF))

def _lwz(rD: int, rA: int, d: int) -> bytes:
    return _ppc((32 << 26) | (rD << 21) | (rA << 16) | (d & 0xFFFF))

def _ld(rD: int, rA: int, d: int) -> bytes:
    return _ppc((58 << 26) | (rD << 21) | (rA << 16) | (d & 0xFFFC))

def _stw(rS: int, rA: int, d: int) -> bytes:
    return _ppc((36 << 26) | (rS << 21) | (rA << 16) | (d & 0xFFFF))

def _mtlr(rS: int) -> bytes:
    return _ppc((31 << 26) | (rS << 21) | (8 << 16) | (467 << 1))

def _mtctr(rS: int) -> bytes:
    return _ppc((31 << 26) | (rS << 21) | (9 << 16) | (467 << 1))

def _blr() -> bytes:
    return _ppc(0x4E800020)

def _bctrl() -> bytes:
    return _ppc(0x4E800421)

def _mr(rA: int, rS: int) -> bytes:
    # or rA, rS, rS
    return _ppc((31 << 26) | (rS << 21) | (rA << 16) | (rS << 11) | (444 << 1))

def _cmplwi(rA: int, UI: int) -> bytes:
    return _ppc((10 << 26) | (rA << 16) | (UI & 0xFFFF))

def _li(rD: int, simm: int) -> bytes:
    return _ppc((14 << 26) | (rD << 21) | (simm & 0xFFFF))

def _slwi(rA: int, rS: int, n: int) -> bytes:
    # rlwinm rA, rS, n, 0, 31-n
    ME = 31 - n
    return _ppc((21 << 26) | (rS << 21) | (rA << 16) | (n << 11) | (0 << 6) | (ME << 1))

def _add(rD: int, rA: int, rB: int) -> bytes:
    return _ppc((31 << 26) | (rD << 21) | (rA << 16) | (rB << 11) | (266 << 1))

def _lwzx(rD: int, rA: int, rB: int) -> bytes:
    return _ppc((31 << 26) | (rD << 21) | (rA << 16) | (rB << 11) | (23 << 1))


# ---------------------------------------------------------------------------
# Gadget pattern definitions
#
# Each gadget is a list of bytes/None values.  None = wildcard (any byte).
# Patterns are taken directly from KernelConfig_Retail_17559.asm.
# ---------------------------------------------------------------------------

def _b(data: bytes) -> list:
    """Convert bytes to list of ints (for use in patterns)."""
    return list(data)

def _W(n: int) -> list:
    """Return n wildcard slots."""
    return [None] * n


# Shared epilogue sequences (pre-computed for clarity)
_EPILOGUE_60_R31 = (       # addi r1,r1,0x60 ; lwz r12,-8(r1) ; mtlr r12 ; ld r31,-0x10(r1) ; blr
    _b(_addi(1, 1, 0x60)) +
    _b(_lwz(12, 1, -8)) +
    _b(_mtlr(12)) +
    _b(_ld(31, 1, -0x10)) +
    _b(_blr())
)
_EPILOGUE_70_R30_R31 = (   # addi r1,r1,0x70 ; lwz r12,-8(r1) ; mtlr r12 ; ld r30,-0x18(r1) ; ld r31,-0x10(r1) ; blr
    _b(_addi(1, 1, 0x70)) +
    _b(_lwz(12, 1, -8)) +
    _b(_mtlr(12)) +
    _b(_ld(30, 1, -0x18)) +
    _b(_ld(31, 1, -0x10)) +
    _b(_blr())
)
_EPILOGUE_70_R31 = (       # addi r1,r1,0x70 ; lwz r12,-8(r1) ; mtlr r12 ; ld r31,-0x10(r1) ; blr
    _b(_addi(1, 1, 0x70)) +
    _b(_lwz(12, 1, -8)) +
    _b(_mtlr(12)) +
    _b(_ld(31, 1, -0x10)) +
    _b(_blr())
)

# Each entry: (symbol_name, section, pattern_as_list)
# section = 'krnl' or 'xam'
GADGET_PATTERNS: list[tuple[str, str, list]] = [

    # -----------------------------------------------------------------------
    # Kernel gadgets
    # -----------------------------------------------------------------------

    #   addi    r1, r1, 0x70
    #   lwz     r12, -0x8(r1)
    #   mtlr    r12
    #   ld      r30, -0x18(r1)
    #   ld      r31, -0x10(r1)
    #   blr
    ("__restgprlr_30", "krnl", _EPILOGUE_70_R30_R31),

    #   addi    r1, r1, 0x60
    #   lwz     r12, -0x8(r1)
    #   mtlr    r12
    #   ld      r31, -0x10(r1)
    #   blr
    ("__restgprlr_31", "krnl", _EPILOGUE_60_R31),

    #   stw     r3, 0(r31)
    #   addi    r1, r1, 0x60
    #   lwz     r12, -0x8(r1)
    #   mtlr    r12
    #   ld      r31, -0x10(r1)
    #   blr
    ("stw_r3", "krnl",
     _b(_stw(3, 31, 0)) + _EPILOGUE_60_R31),

    #   mr      r3, r31
    #   addi    r1, r1, 0x70
    #   lwz     r12, -8(r1)
    #   mtlr    r12
    #   ld      r31, -0x10(r1)
    #   blr
    ("mr_r31_to_r3", "krnl",
     _b(_mr(3, 31)) + _EPILOGUE_70_R31),

    #   mr      r11, r31
    #   mr      r3, r11
    #   addi    r1, r1, 0x70
    #   lwz     r12, -8(r1)
    #   mtlr    r12
    #   ld      r30, -0x18(r1)
    #   ld      r31, -0x10(r1)
    #   blr
    ("mr_r31_to_r11", "krnl",
     _b(_mr(11, 31)) + _b(_mr(3, 11)) + _EPILOGUE_70_R30_R31),

    #   mtctr   r31
    #   bctrl
    #   addi    r1, r1, 0x60
    #   lwz     r12, -8(r1)
    #   mtlr    r12
    #   ld      r31, -0x10(r1)
    #   blr
    ("call_func_dispatch", "krnl",
     _b(_mtctr(31)) + _b(_bctrl()) + _EPILOGUE_60_R31),

    # -----------------------------------------------------------------------
    # XAM gadgets
    # -----------------------------------------------------------------------

    #   lwz     r1, 0(r1)
    #   lwz     r12, -8(r1)
    #   mtlr    r12
    #   blr
    ("stack_pivot", "xam",
     _b(_lwz(1, 1, 0)) + _b(_lwz(12, 1, -8)) + _b(_mtlr(12)) + _b(_blr())),

    #   lwz     r3, 0(r31)
    #   addi    r1, r1, 0x60
    #   lwz     r12, var_8(r1)
    #   mtlr    r12
    #   ld      r31, var_10(r1)
    #   blr
    ("lwz_r3", "xam",
     _b(_lwz(3, 31, 0)) + _EPILOGUE_60_R31),

    #   lwz     r11, 0(r3)
    #   stw     r11, 8(r4)
    #   li      r3, 0
    #   blr
    ("lwz_r3_stw_r4", "xam",
     _b(_lwz(11, 3, 0)) + _b(_stw(11, 4, 8)) + _b(_li(3, 0)) + _b(_blr())),

    #   lwz     r10, 0(r3)
    #   slwi    r11, r11, 2
    #   add     r3, r11, r10
    #   blr
    ("lwz_r10", "xam",
     _b(_lwz(10, 3, 0)) + _b(_slwi(11, 11, 2)) + _b(_add(3, 11, 10)) + _b(_blr())),

    #   lwz     r11, 8(r31)
    #   addi    r3, r11, -1
    #   addi    r1, r1, 0x70
    #   lwz     r12, -8(r1)
    #   mtlr    r12
    #   ld      r30, -0x18(r1)
    #   ld      r31, -0x10(r1)
    #   blr
    ("lwz_r11_off_r31", "xam",
     _b(_lwz(11, 31, 8)) + _b(_addi(3, 11, -1)) + _EPILOGUE_70_R30_R31),

    #   stw     r30, 0(r31)
    #   addi    r1, r1, 0x70
    #   lwz     r12, -8(r1)
    #   mtlr    r12
    #   ld      r30, -0x18(r1)
    #   ld      r31, -0x10(r1)
    #   blr
    ("stw_r30_on_r31", "xam",
     _b(_stw(30, 31, 0)) + _EPILOGUE_70_R30_R31),

    #   lwz     r11, 4(r31)
    #   stw     r3, 0(r11)
    #   li      r3, 0
    #   addi    r1, r1, 0x60
    #   lwz     r12, -8(r1)
    #   mtlr    r12
    #   ld      r31, -0x10(r1)
    #   blr
    ("stw_r3_onto_pointer", "xam",
     _b(_lwz(11, 31, 4)) + _b(_stw(3, 11, 0)) + _b(_li(3, 0)) + _EPILOGUE_60_R31),

    #   lwz     r10, 8(r11)
    #   add     r10, r5, r10
    #   stw     r10, 8(r11)
    #   blr
    ("load_add_store_r10_r5_on_r11", "xam",
     _b(_lwz(10, 11, 8)) + _b(_add(10, 5, 10)) + _b(_stw(10, 11, 8)) + _b(_blr())),

    #   mr      r7, r25
    #   mtctr   r30
    #   mr      r6, r26
    #   mr      r5, r27
    #   mr      r4, r28
    #   mr      r3, r29
    #   bctrl
    ("call_func_preload", "xam",
     _b(_mr(7, 25)) + _b(_mtctr(30)) + _b(_mr(6, 26)) +
     _b(_mr(5, 27)) + _b(_mr(4, 28)) + _b(_mr(3, 29)) + _b(_bctrl())),

    #   mr      r3, r1
    #   blr
    ("mr_r1_to_r3", "xam",
     _b(_mr(3, 1)) + _b(_blr())),

    #   cmplwi  r3, 0
    #   li      r3, 0
    #   beq     +8     (skip the next li)
    #   li      r3, 1
    #   addi    r1, r1, 0x60
    #   lwz     r12, -8(r1)
    #   mtlr    r12
    #   ld      r31, -0x10(r1)
    #   blr
    ("clamp_r3", "xam",
     _b(_cmplwi(3, 0)) + _b(_li(3, 0)) +
     [0x41, 0x82, 0x00, 0x08] +          # beq +8 (BI=2, BO=0xC)
     _b(_li(3, 1)) + _EPILOGUE_60_R31),

    #   lwz     r11, 0(r31)
    #   mtctr   r11
    #   bctrl
    ("call_ptr_off_r31", "xam",
     _b(_lwz(11, 31, 0)) + _b(_mtctr(11)) + _b(_bctrl())),
]


# Gadgets with a variable-displacement field (2 wildcards inside):
#
#   slwi    r10, r3, 2              (fixed)
#   addi    r11, r11, <disp>        (variable 16-bit displacement)
#   lwzx    r3, r10, r11            (fixed)
#   blr                             (fixed)
MUL_R3_4_PATTERN = (
    _b(_slwi(10, 3, 2)) +           # 54 6A 10 3A
    [0x39, 0x6B] + _W(2) +          # 39 6B ?? ??  (addi r11,r11,<disp>)
    _b(_lwzx(3, 10, 11)) +          # 7C 6A 58 2E
    _b(_blr())                      # 4E 80 00 20
)

#   lwz     r11, <disp>(r31)        (variable displacement)
#   add     r11, r30, r11
#   stw     r11, <disp>(r31)        (same displacement)
#   addi    r1, r1, 0x70
#   lwz     r12, -8(r1)
#   mtlr    r12
#   ld      r30, -0x18(r1)
#   ld      r31, -0x10(r1)
#   blr
LOAD_ADD_STORE_R11_PATTERN = (
    [0x81, 0x7F] + _W(2) +          # lwz r11, ?(r31) — keep r11/r31 fixed, disp wildcard
    _b(_add(11, 30, 11)) +          # 7D 7E 5A 14
    [0x91, 0x7F] + _W(2) +          # stw r11, ?(r31) — disp wildcard (must match above)
    _EPILOGUE_70_R30_R31
)


# ---------------------------------------------------------------------------
# __restgprlr stubs  (addi r1, r1, SIMM ; b ???)
# Each entry: (symbol_name, addi_simm)
# ---------------------------------------------------------------------------

RESTGPRLR_STUBS: list[tuple[str, int]] = [
    ("__restgprlr_24", 0xA0),
    ("__restgprlr_26", 0x90),
    ("__restgprlr_27", 0x80),  # Note: r27 and r28 stubs have the same addi encoding
    ("__restgprlr_28", 0x80),  # They must be distinguished by context / IDA
    ("__restgprlr_29", 0x70),
]


# ---------------------------------------------------------------------------
# Kernel function names to look up in the export table
# ---------------------------------------------------------------------------

KERNEL_EXPORTS_NEEDED: list[str] = [
    "DbgPrint",
    "DbgBreakPoint",
    "HalSendSMCMessage",
    "KeFlushCacheRange",
    "KeLockL2",
    "KeStallExecutionProcessor",
    "MmFreePhysicalMemory",
    "MmGetPhysicalAddress",
    "NtAllocateVirtualMemory",
    "NtClose",
    "ObCreateSymbolicLink",
    "RtlInitAnsiString",
    "VdDisplayFatalError",
    "XexLoadImage",
    "XexUnloadImage",
    "memcmp",
    "XeCryptMemDiff",  # alternative for memcmp in some builds
]

# XAM ordinals → symbol names used in the KernelConfig
XAM_ORDINALS_NEEDED: dict[int, str] = {
    1095: "CreateFileA",
    1063: "GetFileSize",
    1052: "ReadFile",
    1054: "WriteFile",
    1044: "CloseHandle",
    1084: "CreateThread",
    1085: "ResumeThread",
    1006: "GetLastError",
    420:  "XamLoaderLaunchTitle",
    425:  "XamLoaderTerminateTitle",
}

# XAM functions not in the ordinal table — need manual identification
XAM_MANUAL_NEEDED: list[str] = ["memcpy", "memset"]

# Syscall ordinals used by the exploit, with their symbol names and
# the name of the kernel stub function that wraps them.
# These ordinal numbers are stable across retail kernel versions.
SYSCALL_ORDINALS: dict[int, tuple[str, str]] = {
    0x0D: ("sc_HvxPostOutputExploit",          "HvxPostOutputExploit"),
    0x21: ("sc_HvxFlushUserModeTb",             "HvxFlushUserModeTb"),
    0x42: ("sc_HvxKeysExecute",                 "HvxKeysExecute"),
    0x49: ("sc_HvxEncryptedReserveAllocation",  "HvxEncryptedReserveAllocation"),
    0x4A: ("sc_HvxEncryptedEncryptAllocation",  "HvxEncryptedEncryptAllocation"),
    0x4C: ("sc_HvxEncryptedReleaseAllocation",  "HvxEncryptedReleaseAllocation"),
    0x65: ("sc_HvxRevokeUpdate",                "HvxRevokeUpdate"),
}

# Additional syscall stubs to scan for (ordinal unknown at design time).
# Reported in the "all syscall stubs" list so the user can identify them.
EXTRA_SYSCALL_STUBS: list[str] = [
    "HvxKeysExGetKey",
    "HvxKeysExSetKey",
    "HvxFlushDCacheRange",
]


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _r32(data: bytes, off: int) -> int:
    """Read a big-endian unsigned 32-bit integer."""
    return struct.unpack_from(">I", data, off)[0]


def _r16(data: bytes, off: int) -> int:
    """Read a big-endian unsigned 16-bit integer."""
    return struct.unpack_from(">H", data, off)[0]


def _read_cstr(data: bytes, off: int, maxlen: int = 256) -> str:
    """Read a null-terminated ASCII string at *off*."""
    end = data.find(b"\x00", off, off + maxlen)
    if end == -1:
        end = off + maxlen
    return data[off:end].decode("ascii", errors="replace")


def find_pattern(data: bytes, pattern: list, start: int = 0) -> list[int]:
    """Return all file offsets where *pattern* matches *data*.

    *pattern* is a list of ints (0-255) or None (wildcard = any byte).
    Only patterns with a non-wildcard byte at position 0 are supported
    efficiently; others still work but may be slower.
    """
    plen = len(pattern)
    if plen == 0:
        return []
    results: list[int] = []
    pos = start
    # Find a good anchor: first non-wildcard byte in the pattern
    anchor_off = 0
    anchor_byte = pattern[0]
    for i, p in enumerate(pattern):
        if p is not None:
            anchor_off = i
            anchor_byte = p
            break
    # Use bytes.find to quickly locate the anchor, then validate the full pattern
    search_bytes = bytes([anchor_byte])
    idx = data.find(search_bytes, pos - anchor_off if pos > anchor_off else 0)
    while idx != -1:
        base = idx - anchor_off
        if base >= 0 and base + plen <= len(data):
            ok = True
            for j, p in enumerate(pattern):
                if p is not None and data[base + j] != p:
                    ok = False
                    break
            if ok:
                results.append(base)
        idx = data.find(search_bytes, idx + 1)
    return results


def _is_b_instr(b0: int, b3: int) -> bool:
    """Return True if bytes b0..b3 look like a ``b`` (unconditional branch, not bl) instruction.

    ``b`` opcode = 18 (0b010010), AA=0, LK=0.
    First byte ∈ {0x48, 0x49, 0x4A, 0x4B}, last byte low 2 bits = 00.
    """
    return b0 in (0x48, 0x49, 0x4A, 0x4B) and (b3 & 0x03) == 0x00


# ---------------------------------------------------------------------------
# XEX2 parsing
# ---------------------------------------------------------------------------

def parse_xex2(data: bytes) -> Optional[dict]:
    """Parse the XEX2 header at the start of *data*.

    Returns a dict with the fields needed for address extraction, or None if
    *data* does not begin with a valid XEX2 header.

    Returned keys:
      code_offset          int  – file offset of the (decrypted) PE image
      security_info_offset int  – file offset of the security certificate
      load_address         int  – image base VA (from the security cert)
      export_table_va      int  – VA of the IMAGE_EXPORT_DIRECTORY (0 = absent)
      build_number         int  – kernel build number (from execution-ID block)
      opt_headers          dict – raw optional header key→value mapping
    """
    if len(data) < 0x20 or data[:4] != XEX2_MAGIC:
        return None

    code_offset         = _r32(data, 0x08)
    security_info_offset = _r32(data, 0x10)
    opt_count           = _r32(data, 0x14)

    if opt_count > MAX_OPT_HEADERS:
        return None

    # --- Optional headers ---
    opt: dict[int, int] = {}
    for i in range(opt_count):
        off = 0x18 + i * 8
        if off + 8 > len(data):
            break
        k = _r32(data, off)
        v = _r32(data, off + 4)
        opt[k] = v

    # --- Load address: prefer optional header 0x00010201 when present.
    #     The security-cert field (+0x10C) may contain the image_flags value
    #     rather than the load address in some encrypted retail XEX2 files, so
    #     the optional header is the authoritative source.
    load_address = opt.get(XEX_OPT_BASE_ADDRESS, 0)
    if not load_address:
        # Fall back to the security certificate field for older / decrypted files.
        if security_info_offset and security_info_offset + SECURITY_CERT_LOAD_ADDR_OFF + 4 <= len(data):
            load_address = _r32(data, security_info_offset + SECURITY_CERT_LOAD_ADDR_OFF)

    # --- Export table VA (inline in optional header 0x00400100) ---
    export_table_va = opt.get(XEX_OPT_EXPORT_TABLE, 0)

    # --- Build number from execution-ID block ---
    build_number = 0
    if XEX_OPT_EXECUTION_ID in opt:
        exec_off = opt[XEX_OPT_EXECUTION_ID]  # relative to XEX2 file start
        if exec_off + 8 <= len(data):
            data_off = exec_off + 4  # skip block-size DWORD
            if data_off + 8 <= len(data):
                ver_raw = _r32(data, data_off + 0x04)
                build_number = (ver_raw >> 8) & 0xFFFF

    return {
        "code_offset":          code_offset,
        "security_info_offset": security_info_offset,
        "load_address":         load_address,
        "export_table_va":      export_table_va,
        "build_number":         build_number,
        "opt_headers":          opt,
    }


# ---------------------------------------------------------------------------
# PE export table parsing (big-endian Xbox 360 variant)
# ---------------------------------------------------------------------------

def parse_export_table(code: bytes, export_va: int, load_address: int) -> dict[str, int]:
    """Parse the IMAGE_EXPORT_DIRECTORY at *export_va* inside *code*.

    *code* is the decrypted PE image bytes (starting at code_offset in the file).
    *export_va* is the absolute VA of the export directory.
    *load_address* is the image base (to convert VA → offset in *code*).

    Returns a dict mapping export name (str) → absolute VA (int).
    """
    exports: dict[str, int] = {}
    if load_address == 0 or export_va < load_address:
        return exports

    dir_off = export_va - load_address
    # IMAGE_EXPORT_DIRECTORY (big-endian, 10 DWORDs = 40 bytes):
    #   +0x00  Characteristics
    #   +0x04  TimeDateStamp
    #   +0x08  MajorVersion (WORD) + MinorVersion (WORD)
    #   +0x0C  Name (VA of module name)
    #   +0x10  Base (ordinal base)
    #   +0x14  NumberOfFunctions
    #   +0x18  NumberOfNames
    #   +0x1C  AddressOfFunctions  (VA of DWORD array of function VAs)
    #   +0x20  AddressOfNames      (VA of DWORD array of name VAs)
    #   +0x24  AddressOfNameOrdinals (VA of WORD array of name ordinals)
    if dir_off + 0x28 > len(code):
        return exports

    num_funcs  = _r32(code, dir_off + 0x14)
    num_names  = _r32(code, dir_off + 0x18)
    funcs_va   = _r32(code, dir_off + 0x1C)
    names_va   = _r32(code, dir_off + 0x20)
    ordinals_va = _r32(code, dir_off + 0x24)
    ordinal_base = _r32(code, dir_off + 0x10)

    # Sanity caps
    if num_names > 0x4000 or num_funcs > 0x8000:
        return exports

    funcs_off    = funcs_va    - load_address
    names_off    = names_va    - load_address
    ordinals_off = ordinals_va - load_address

    for i in range(num_names):
        if names_off + i * 4 + 4 > len(code):
            break
        if ordinals_off + i * 2 + 2 > len(code):
            break
        name_va  = _r32(code, names_off + i * 4)
        ord_idx  = _r16(code, ordinals_off + i * 2)  # index into funcs array
        name_off = name_va - load_address
        if name_off < 0 or name_off >= len(code):
            continue
        name = _read_cstr(code, name_off)
        if funcs_off + ord_idx * 4 + 4 > len(code):
            continue
        func_va = _r32(code, funcs_off + ord_idx * 4)
        if name:
            exports[name] = func_va

    return exports


def parse_export_table_by_ordinal(code: bytes, export_va: int,
                                  load_address: int) -> dict[int, int]:
    """Like parse_export_table, but returns ordinal → absolute VA mapping.

    Used for XAM, which exposes many functions only by ordinal (no name).
    """
    by_ordinal: dict[int, int] = {}
    if load_address == 0 or export_va < load_address:
        return by_ordinal

    dir_off = export_va - load_address
    if dir_off + 0x28 > len(code):
        return by_ordinal

    num_funcs    = _r32(code, dir_off + 0x14)
    funcs_va     = _r32(code, dir_off + 0x1C)
    ordinal_base = _r32(code, dir_off + 0x10)

    if num_funcs > 0x8000:
        return by_ordinal

    funcs_off = funcs_va - load_address
    for i in range(num_funcs):
        if funcs_off + i * 4 + 4 > len(code):
            break
        func_va = _r32(code, funcs_off + i * 4)
        if func_va != 0:
            by_ordinal[ordinal_base + i] = func_va

    return by_ordinal


# ---------------------------------------------------------------------------
# Syscall stub scanner
# ---------------------------------------------------------------------------

def scan_syscall_stubs(code: bytes, load_address: int) -> dict[int, int]:
    """Scan *code* for all ``li r0, <ordinal> ; sc`` pairs.

    Returns a dict mapping ordinal (int) → stub VA (int).
    The stub VA is the address of the ``li r0`` instruction.
    """
    #  li  r0, N  =  0x38000000 | (N & 0xFFFF)  →  bytes: 38 00 HH LL
    #  sc          =  0x44000002                 →  bytes: 44 00 00 02
    stubs: dict[int, int] = {}
    i = 0
    while i + 8 <= len(code):
        # Quick check: first byte of li r0 = 0x38, second byte = 0x00
        if code[i] == 0x38 and code[i + 1] == 0x00:
            ordinal = (code[i + 2] << 8) | code[i + 3]
            # Check for sc immediately after
            if code[i + 4:i + 8] == b"\x44\x00\x00\x02":
                va = load_address + i
                # Keep the first match for each ordinal
                if ordinal not in stubs:
                    stubs[ordinal] = va
        i += 4  # instructions are always 4-byte aligned
    return stubs


# ---------------------------------------------------------------------------
# Gadget scanner
# ---------------------------------------------------------------------------

def scan_gadgets(code: bytes, load_address: int,
                 section_name: str) -> dict[str, list[int]]:
    """Scan *code* for all known gadget patterns in the given section.

    Returns a dict mapping gadget symbol name → list of matching VAs.
    """
    results: dict[str, list[int]] = {}

    # Fixed patterns
    for name, section, pattern in GADGET_PATTERNS:
        if section != section_name:
            continue
        offsets = find_pattern(code, pattern)
        results[name] = [load_address + off for off in offsets]

    # mul_r3_4_lwzx_r11 (variable displacement)
    if section_name == "xam":
        offsets = find_pattern(code, MUL_R3_4_PATTERN)
        results["mul_r3_4_lwzx_r11"] = []
        for off in offsets:
            results["mul_r3_4_lwzx_r11"].append(load_address + off)

    # load_add_store_r11_r30_on_r31 (variable displacement)
    if section_name == "xam":
        offsets = find_pattern(code, LOAD_ADD_STORE_R11_PATTERN)
        # Validate: lwz displacement must match stw displacement
        valid_offsets = []
        for off in offsets:
            lwz_disp = _r16(code, off + 2) if off + 4 <= len(code) else 0xFFFF
            stw_disp = _r16(code, off + 10) if off + 12 <= len(code) else 0xFFFE
            if lwz_disp == stw_disp:
                valid_offsets.append(load_address + off)
        results["load_add_store_r11_r30_on_r31"] = valid_offsets

    return results


def scan_restgprlr_stubs(code: bytes, load_address: int) -> dict[str, list[int]]:
    """Scan for __restgprlr stubs: ``addi r1, r1, SIMM ; b ???``.

    Returns a dict mapping stub name → list of matching VAs.
    Note: __restgprlr_27 and __restgprlr_28 share the same SIMM (0x80)
    so both map to the same list of candidates.
    """
    results: dict[str, list[int]] = {}
    for name, simm in RESTGPRLR_STUBS:
        addi_bytes = _addi(1, 1, simm)
        candidates: list[int] = []
        pos = 0
        while True:
            idx = code.find(addi_bytes, pos)
            if idx == -1:
                break
            if idx + 8 <= len(code):
                b0 = code[idx + 4]
                b3 = code[idx + 7]
                if _is_b_instr(b0, b3):
                    candidates.append(load_address + idx)
            pos = idx + 4
        results[name] = candidates
    return results


# ---------------------------------------------------------------------------
# High-level analysis functions
# ---------------------------------------------------------------------------

def analyse_kernel(path: str) -> dict:
    """Load and analyse a decrypted xboxkrnl.exe XEX2 file.

    Returns a dict with keys: build, load_address, exports, syscalls,
    gadgets, stubs, raw_code.
    """
    print(f"\n[KERNEL] Loading: {path}")
    with open(path, "rb") as fh:
        data = fh.read()

    hdr = parse_xex2(data)
    if hdr is None:
        print("[KERNEL] ERROR: not a valid XEX2 file")
        return {}

    build        = hdr["build_number"]
    load_addr    = hdr["load_address"]
    code_off     = hdr["code_offset"]
    export_va    = hdr["export_table_va"]
    code         = data[code_off:]

    print(f"  Build number   : {build}  (0x{build:04X})")
    print(f"  Load address   : 0x{load_addr:08X}")
    print(f"  Export table VA: 0x{export_va:08X}" if export_va else
          "  Export table VA: (none in XEX2 header)")

    exports_by_name = parse_export_table(code, export_va, load_addr)
    print(f"  Exported names : {len(exports_by_name)}")

    syscall_map = scan_syscall_stubs(code, load_addr)
    print(f"  Syscall stubs  : {len(syscall_map)} ordinals found")

    gadgets = scan_gadgets(code, load_addr, "krnl")
    stubs   = scan_restgprlr_stubs(code, load_addr)

    return {
        "build":        build,
        "load_address": load_addr,
        "exports":      exports_by_name,
        "syscalls":     syscall_map,
        "gadgets":      gadgets,
        "stubs":        stubs,
        "raw_code":     code,
    }


def analyse_xam(path: str) -> dict:
    """Load and analyse a decrypted xam.xex XEX2 file."""
    print(f"\n[XAM] Loading: {path}")
    with open(path, "rb") as fh:
        data = fh.read()

    hdr = parse_xex2(data)
    if hdr is None:
        print("[XAM] ERROR: not a valid XEX2 file")
        return {}

    load_addr  = hdr["load_address"]
    code_off   = hdr["code_offset"]
    export_va  = hdr["export_table_va"]
    code       = data[code_off:]

    print(f"  Load address   : 0x{load_addr:08X}")
    print(f"  Export table VA: 0x{export_va:08X}" if export_va else
          "  Export table VA: (none in XEX2 header)")

    by_ordinal = parse_export_table_by_ordinal(code, export_va, load_addr)
    print(f"  Exported ordinals: {len(by_ordinal)}")

    gadgets = scan_gadgets(code, load_addr, "xam")

    return {
        "load_address": load_addr,
        "by_ordinal":   by_ordinal,
        "gadgets":      gadgets,
        "raw_code":     code,
    }


def analyse_bootanim(path: str) -> dict:
    """Load and analyse a decrypted bootanim.xex XEX2 file."""
    print(f"\n[BOOTANIM] Loading: {path}")
    with open(path, "rb") as fh:
        data = fh.read()

    hdr = parse_xex2(data)
    if hdr is None:
        print("[BOOTANIM] ERROR: not a valid XEX2 file")
        return {}

    load_addr = hdr["load_address"]
    print(f"  Load address (BootAnimCodePageAddress): 0x{load_addr:08X}")

    return {"load_address": load_addr}


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

def _fmt(va: int) -> str:
    """Format a VA as '0x{VA:08X}' or 'NOT FOUND'."""
    return f"0x{va:08X}" if va else "NOT FOUND  # TODO"


def print_report(krnl: dict, xam: dict, bootanim: dict) -> None:
    """Print a human-readable extraction report to stdout."""
    print("\n" + "=" * 72)
    print("  EXTRACTION REPORT")
    print("=" * 72)

    build = krnl.get("build", 0)
    if build:
        print(f"\n  Kernel build : {build}  (0x{build:04X})")
        print(f"  KernelConfig : Common/KernelConfig_Retail_{build}.asm")

    # --- Kernel functions ---
    print("\n  ── Category 1: Kernel function addresses ────────────────────────")
    exports = krnl.get("exports", {})
    for sym in KERNEL_EXPORTS_NEEDED:
        va = exports.get(sym, 0)
        print(f"    {sym:<36} {_fmt(va)}")
    if "memcmp" not in exports and "XeCryptMemDiff" not in exports:
        print("    NOTE: neither memcmp nor XeCryptMemDiff found in exports.")
        print("          Search the kernel code for 'mfcr r0; blr' or similar.")

    # --- XAM functions ---
    print("\n  ── Category 2: XAM function addresses ──────────────────────────")
    by_ordinal = xam.get("by_ordinal", {})
    for ordinal, sym in sorted(XAM_ORDINALS_NEEDED.items()):
        va = by_ordinal.get(ordinal, 0)
        comment = f"Export {ordinal}"
        print(f"    {sym:<36} {_fmt(va)}  # {comment}")
    for sym in XAM_MANUAL_NEEDED:
        print(f"    {sym:<36} NOT FOUND  # TODO: manual search in IDA/Ghidra")

    # --- Syscall ordinals (stable) ---
    print("\n  ── Category 3: Syscall ordinals (stable across versions) ───────")
    for ordinal, (sc_sym, _fn_sym) in sorted(SYSCALL_ORDINALS.items()):
        print(f"    {sc_sym:<44} 0x{ordinal:02X}")

    # --- Syscall stub addresses ---
    print("\n  ── Category 3: Syscall stub function addresses ──────────────────")
    syscalls = krnl.get("syscalls", {})
    for ordinal, (_sc_sym, fn_sym) in sorted(SYSCALL_ORDINALS.items()):
        va = syscalls.get(ordinal, 0)
        print(f"    {fn_sym:<44} {_fmt(va)}  # ordinal 0x{ordinal:02X}")
    print()
    print("    Additional syscall stubs found (identify by ordinal in IDA):")
    for ordinal in sorted(syscalls):
        if ordinal not in SYSCALL_ORDINALS:
            va = syscalls[ordinal]
            print(f"      ordinal 0x{ordinal:02X}  →  0x{va:08X}")

    # --- Kernel ROP gadgets ---
    print("\n  ── Category 4: Kernel ROP gadgets ──────────────────────────────")
    gadgets = krnl.get("gadgets", {})
    stubs = krnl.get("stubs", {})

    for name, simm in RESTGPRLR_STUBS:
        matches = stubs.get(name, [])
        if len(matches) == 1:
            print(f"    {name:<36} 0x{matches[0]:08X}")
        elif len(matches) > 1:
            for i, va in enumerate(matches):
                note = " ← pick the one matching .fill 0x58/0x50"
                print(f"    {name} [{i}]{' ' * max(0, 29 - len(name))} 0x{va:08X}{note if i == 0 else ''}")
        else:
            print(f"    {name:<36} NOT FOUND  # TODO")

    for name, section, _ in GADGET_PATTERNS:
        if section != "krnl":
            continue
        matches = gadgets.get(name, [])
        if len(matches) == 1:
            print(f"    {name:<36} 0x{matches[0]:08X}")
        elif len(matches) > 1:
            for i, va in enumerate(matches):
                print(f"    {name} [{i}]{' ' * max(0, 29 - len(name))} 0x{va:08X}")
        else:
            print(f"    {name:<36} NOT FOUND  # TODO")

    # --- XAM ROP gadgets ---
    print("\n  ── Category 4: XAM ROP gadgets ─────────────────────────────────")
    xam_gadgets = xam.get("gadgets", {})
    for name, section, _ in GADGET_PATTERNS:
        if section != "xam":
            continue
        matches = xam_gadgets.get(name, [])
        if len(matches) == 1:
            print(f"    {name:<36} 0x{matches[0]:08X}")
        elif len(matches) > 1:
            for i, va in enumerate(matches):
                print(f"    {name} [{i}]{' ' * max(0, 29 - len(name))} 0x{va:08X}")
        else:
            print(f"    {name:<36} NOT FOUND  # TODO")
    for name in ("mul_r3_4_lwzx_r11", "load_add_store_r11_r30_on_r31"):
        matches = xam_gadgets.get(name, [])
        if len(matches) == 1:
            print(f"    {name:<36} 0x{matches[0]:08X}")
        elif len(matches) > 1:
            for i, va in enumerate(matches):
                print(f"    {name} [{i}]{' ' * max(0, 29 - len(name))} 0x{va:08X}")
        else:
            print(f"    {name:<36} NOT FOUND  # TODO")

    # --- blr_nop is mr_r1_to_r3 + 4 ---
    mr_r1 = xam_gadgets.get("mr_r1_to_r3", [])
    if mr_r1:
        print(f"    {'blr_nop':<36} 0x{mr_r1[0] + 4:08X}  # = mr_r1_to_r3 + 4")

    # --- BootAnim ---
    print("\n  ── Category 5: Boot animation ───────────────────────────────────")
    ba_va = bootanim.get("load_address", 0)
    print(f"    {'BootAnimCodePageAddress':<36} {_fmt(ba_va)}")

    # --- Category 6 reminder ---
    print("\n  ── Category 6: Hypervisor internals (requires CPU key) ──────────")
    print("    HvpRelocateCacheLines: NOT FOUND  # TODO: see Stage4 comment")
    print("    HvpSetRMCI:            NOT FOUND  # TODO: see Stage4 comment")
    print("    hv_rsa_patch_address:             # TODO")
    print("    kernel_rsa_patch_address:         # TODO")
    print("    Stage4_CleanHvData binary:        # TODO: dump from your NAND")


# ---------------------------------------------------------------------------
# KernelConfig .asm file generator
# ---------------------------------------------------------------------------

def _first(lst: list[int], fallback: int = 0) -> int:
    return lst[0] if lst else fallback


def generate_kernelconfig(krnl: dict, xam: dict, bootanim: dict,
                          out_path: str) -> None:
    """Write a ``KernelConfig_Retail_<build>.asm`` file to *out_path*."""
    build       = krnl.get("build", 0)
    exports     = krnl.get("exports", {})
    syscalls    = krnl.get("syscalls", {})
    kgadgets    = krnl.get("gadgets", {})
    kstubs      = krnl.get("stubs", {})
    by_ordinal  = xam.get("by_ordinal", {})
    xgadgets    = xam.get("gadgets", {})
    ba_va       = bootanim.get("load_address", 0)

    def _v(va: int, todo_comment: str = "") -> str:
        if va:
            return f"0x{va:08X}"
        if todo_comment:
            return f"0x00000000  # TODO: {todo_comment}"
        return "0x00000000  # TODO"

    def _kexp(name: str, alt: str = "") -> str:
        va = exports.get(name, 0) or (exports.get(alt, 0) if alt else 0)
        if va:
            return f"0x{va:08X}"
        return f"0x00000000  # TODO: find '{name}' in export table"

    def _sc(ordinal: int) -> str:
        va = syscalls.get(ordinal, 0)
        if va:
            return f"0x{va:08X}"
        return f"0x00000000  # TODO: scan for 'li r0, 0x{ordinal:02X} ; sc'"

    def _kgad(name: str) -> str:
        lst = kgadgets.get(name, kstubs.get(name, []))
        va = _first(lst)
        if va:
            return f"0x{va:08X}"
        return f"0x00000000  # TODO: byte-pattern scan"

    def _xgad(name: str) -> str:
        lst = xgadgets.get(name, [])
        va = _first(lst)
        if va:
            return f"0x{va:08X}"
        return f"0x00000000  # TODO: byte-pattern scan"

    def _xord(ordinal: int, sym: str) -> str:
        va = by_ordinal.get(ordinal, 0)
        if va:
            return f"0x{va:08X}"
        return f"0x00000000  # TODO: XAM export {ordinal} ({sym})"

    # mul_r3_4_lwzx_r11 displacement
    mul_va   = _first(xgadgets.get("mul_r3_4_lwzx_r11", []))
    mul_code = xam.get("raw_code", b"")
    mul_disp = 0
    if mul_va and xam.get("load_address", 0):
        off = mul_va - xam["load_address"]
        # addi r11, r11, disp is at offset+4; disp is last 2 bytes of that instruction
        if off + 8 <= len(mul_code):
            mul_disp = _r16(mul_code, off + 6)  # low 16 bits (big-endian)

    # load_add_store_r11_r30_on_r31 displacement
    las_va   = _first(xgadgets.get("load_add_store_r11_r30_on_r31", []))
    las_code = xam.get("raw_code", b"")
    las_disp = 0x18  # default from 17559
    if las_va and xam.get("load_address", 0):
        off = las_va - xam["load_address"]
        if off + 4 <= len(las_code):
            las_disp = _r16(las_code, off + 2)  # displacement from lwz r11, d(r31)

    # blr_nop = mr_r1_to_r3 + 4
    mr_r1_va = _first(xgadgets.get("mr_r1_to_r3", []))
    blr_nop_va = mr_r1_va + 4 if mr_r1_va else 0

    # call_func_preload register offsets (stable: layout is fixed in the epilogue)
    # Values come from KernelConfig_Retail_17559.asm — should be stable
    cf_r3_def    = 0x29292929
    cf_r4_def    = 0x28282828
    cf_r5_def    = 0x27272727
    cf_r6_def    = 0x26262626
    cf_r7_def    = 0x25252525
    cf_r3_offset = 0x2C
    cf_r4_offset = 0x24
    cf_r5_offset = 0x1C
    cf_r6_offset = 0x14
    cf_r7_offset = 0x0C

    lines = [
        f"# KernelConfig_Retail_{build}.asm",
        f"# Auto-generated by Tools/kernel_port.py",
        f"# Kernel build: {build}  (0x{build:04X})",
        f"#",
        f"# Values marked '# TODO' were NOT found automatically and must be",
        f"# filled in manually using IDA Pro / Ghidra (PowerPC 64-bit, BE).",
        f"# See README section 'Portando para outro kernel' for guidance.",
        f"#",
        f"# Category 6 values (HvpRelocateCacheLines, HvpSetRMCI, hv_rsa_patch_address,",
        f"# kernel_rsa_patch_address, Stage4_CleanHvData) are NEVER auto-detected here —",
        f"# they require the CPU key and manual HV binary analysis.",
        "",
        f"# Specify the kernel version so the build config file knows the kernel addresses have been defined.",
        f".set KRNL_VER,              {build}",
        "",
        f"# Kernel function addresses:",
        f".set DbgPrint,                          {_kexp('DbgPrint')}",
        f".set DbgBreakPoint,                     {_kexp('DbgBreakPoint')}",
        f".set HalSendSMCMessage,                 {_kexp('HalSendSMCMessage')}",
        f".set KeFlushCacheRange,                 {_kexp('KeFlushCacheRange')}",
        f".set KeLockL2,                          {_kexp('KeLockL2')}",
        f".set KeStallExecutionProcessor,         {_kexp('KeStallExecutionProcessor')}",
        f".set MmFreePhysicalMemory,              {_kexp('MmFreePhysicalMemory')}",
        f".set MmGetPhysicalAddress,              {_kexp('MmGetPhysicalAddress')}",
        f".set NtAllocateVirtualMemory,           {_kexp('NtAllocateVirtualMemory')}",
        f".set NtClose,                           {_kexp('NtClose')}",
        f".set ObCreateSymbolicLink,              {_kexp('ObCreateSymbolicLink')}",
        f".set RtlInitAnsiString,                 {_kexp('RtlInitAnsiString')}",
        f".set VdDisplayFatalError,               {_kexp('VdDisplayFatalError')}",
        f".set XexLoadImage,                      {_kexp('XexLoadImage')}",
        f".set XexUnloadImage,                    {_kexp('XexUnloadImage')}",
        "",
        f".set memcmp,                            {_kexp('memcmp', 'XeCryptMemDiff')}"
        f"  # Can be substituted for XeCryptMemDiff if memcmp is not available"
        f" (do NOT use RtlCompareMemory, it doesn't return 0 on matching data)",
        "",
        f"# System call functions:",
        f".set HvxKeysExGetKey,                   0x00000000  # TODO: scan for 'li r0, <ord> ; sc' where ord = HvxKeysExGetKey ordinal",
        f".set HvxKeysExSetKey,                   0x00000000  # TODO: scan for 'li r0, <ord> ; sc' where ord = HvxKeysExSetKey ordinal",
        f".set HvxEncryptedReserveAllocation,     {_sc(0x49)}",
        f".set HvxEncryptedReleaseAllocation,     {_sc(0x4C)}",
        f".set HvxEncryptedEncryptAllocation,     {_sc(0x4A)}",
        f".set HvxFlushDCacheRange,               0x00000000  # TODO: scan for 'li r0, <ord> ; sc' where ord = HvxFlushDCacheRange ordinal",
        "",
        f"# System call ordinals:",
        f".set sc_HvxPostOutputExploit,           0x0D",
        f".set sc_HvxFlushUserModeTb,             0x21",
        f".set sc_HvxKeysExecute,                 0x42",
        f".set sc_HvxEncryptedReserveAllocation,  0x49",
        f".set sc_HvxEncryptedEncryptAllocation,  0x4A",
        f".set sc_HvxEncryptedReleaseAllocation,  0x4C",
        f".set sc_HvxRevokeUpdate,                0x65",
        "",
        f".set sc_HvxArbWriteSyscall,             sc_HvxFlushUserModeTb",
        "",
        f"# Boot animation addresses:",
        f".set BootAnimCodePageAddress,           {_v(ba_va, 'bootanim.xex load address')}",
        "",
        f"# Xam function addresses:",
        f".set CreateFileA,                       {_xord(1095, 'CreateFileA')}  # Export 1095",
        f".set GetFileSize,                       {_xord(1063, 'GetFileSize')}  # Export 1063",
        f".set ReadFile,                          {_xord(1052, 'ReadFile')}  # Export 1052",
        f".set WriteFile,                         {_xord(1054, 'WriteFile')}  # Export 1054",
        f".set CloseHandle,                       {_xord(1044, 'CloseHandle')}  # Export 1044",
        "",
        f".set CreateThread,                      {_xord(1084, 'CreateThread')}  # Export 1084",
        f".set ResumeThread,                      {_xord(1085, 'ResumeThread')}  # Export 1085",
        f".set GetLastError,                      {_xord(1006, 'GetLastError')}  # Export 1006",
        "",
        f".set memcpy,                            0x00000000  # TODO: manual search in IDA/Ghidra",
        f".set memset,                            0x00000000  # TODO: manual search in IDA/Ghidra",
        "",
        f".set XamLoaderLaunchTitle,              {_xord(420, 'XamLoaderLaunchTitle')}  # Export 420",
        f".set XamLoaderTerminateTitle,           {_xord(425, 'XamLoaderTerminateTitle')}  # Export 425",
        f".set XLaunchNewImage,                   XamLoaderLaunchTitle",
        "",
        "",
        f"###########################################################",
        f"# Kernel gadget address.",
        "",
        f"#   addi    r1, r1, 0xA0",
        f"#   b       __restgprlr_24",
        f".set    __restgprlr_24,                 {_kgad('__restgprlr_24')}      # .fill 0x58, 1, 0x00",
        "",
        f"#   addi    r1, r1, 0x90",
        f"#   b       __restgprlr_26",
        f".set    __restgprlr_26,                 {_kgad('__restgprlr_26')}      # .fill 0x58, 1, 0x00",
        "",
        f"#   addi    r1, r1, 0x80",
        f"#   b       __restgprlr_27",
        f".set    __restgprlr_27,                 {_kgad('__restgprlr_27')}      # .fill 0x50, 1, 0x00",
        "",
        f"#   addi    r1, r1, 0x80",
        f"#   b       __restgprlr_28",
        f".set    __restgprlr_28,                 {_kgad('__restgprlr_28')}      # .fill 0x58, 1, 0x00",
        "",
        f"#   addi    r1, r1, 0x70",
        f"#   b       __restgprlr_29",
        f".set    __restgprlr_29,                 {_kgad('__restgprlr_29')}      # .fill 0x50, 1, 0x00",
        "",
        f"#   addi    r1, r1, 0x70",
        f"#   lwz     r12, -0x8(r1)",
        f"#   mtlr    r12",
        f"#   ld      r30, -0x18(r1)",
        f"#   ld      r31, -0x10(r1)",
        f"#   blr",
        f".set    __restgprlr_30,                 {_kgad('__restgprlr_30')}      # .fill 0x58, 1, 0x00",
        "",
        f"#   addi    r1, r1, 0x60",
        f"#   lwz     r12, -0x8(r1)",
        f"#   mtlr    r12",
        f"#   ld      r31, -0x10(r1)",
        f"#   blr",
        f".set    __restgprlr_31,                 {_kgad('__restgprlr_31')}      # .fill 0x50, 1, 0x00",
        "",
        f"#   stw     r3, 0(r31)",
        f"#   addi    r1, r1, 0x60",
        f"#   lwz     r12, -0x8(r1)",
        f"#   mtlr    r12",
        f"#   ld      r31, -0x10(r1)",
        f"#   blr",
        f".set    stw_r3,                         {_kgad('stw_r3')}      # .fill 0x50, 1, 0x00",
        "",
        f"#   mr      r3, r31",
        f"#   addi    r1, r1, 0x70",
        f"#   lwz     r12, -8(r1)",
        f"#   mtlr    r12",
        f"#   ld      r31, -0x10(r1)",
        f"#   blr",
        f".set    mr_r31_to_r3,                   {_kgad('mr_r31_to_r3')}      # .fill 0x60, 1, 0x00",
        "",
        f"#   mr      r11, r31",
        f"#   mr      r3, r11",
        f"#   addi    r1, r1, 0x70",
        f"#   lwz     r12, -8(r1)",
        f"#   mtlr    r12",
        f"#   ld      r30, -0x18(r1)",
        f"#   ld      r31, -0x10(r1)",
        f"#   blr",
        f".set    mr_r31_to_r11,                  {_kgad('mr_r31_to_r11')}      # .fill 0x58, 1, 0x00",
        "",
        f"#   mtctr   r31",
        f"#   bctrl",
        f"#   addi    r1, r1, 0x60",
        f"#   lwz     r12, -8(r1)",
        f"#   mtlr    r12",
        f"#   ld      r31, -0x10(r1)",
        f"#   blr",
        f".set    call_func_dispatch,             {_kgad('call_func_dispatch')}      # .fill 0x50, 1, 0x00",
        "",
        "",
        f"###########################################################",
        f"# Xam gadget address.",
        "",
        f"#   lwz     r1, 0(r1)",
        f"#   lwz     r12, -8(r1)",
        f"#   mtlr    r12",
        f"#   blr",
        f".set    stack_pivot,                    {_xgad('stack_pivot')}",
        "",
        f"#   lwz     r3, 0(r31)",
        f"#   addi    r1, r1, 0x60",
        f"#   lwz     r12, var_8(r1)",
        f"#   mtlr    r12",
        f"#   ld      r31, var_10(r1)",
        f"#   blr",
        f".set    lwz_r3,                         {_xgad('lwz_r3')}      # .fill 0x50, 1, 0x00",
        "",
        f"#   lwz     r11, 0(r3)",
        f"#   stw     r11, 8(r4)",
        f"#   li      r3, 0",
        f"#   blr",
        f".set    lwz_r3_stw_r4,                  {_xgad('lwz_r3_stw_r4')}",
        f".set    lwz_r3_stw_r4__r3_disp,         0               # Displacement for r3 load",
        f".set    lwz_r3_stw_r4__r4_disp,         8               # Displacement for r4 store",
        "",
        f"#   lwz     r10, 0(r3)",
        f"#   slwi    r11, r11, 2",
        f"#   add     r3, r11, r10",
        f"#   blr",
        f".set    lwz_r10,                        {_xgad('lwz_r10')}",
        "",
        f"#   lwz     r11, 8(r31)",
        f"#   addi    r3, r11, -1",
        f"#   addi    r1, r1, 0x70",
        f"#   lwz     r12, -8(r1)",
        f"#   mtlr    r12",
        f"#   ld      r30, -0x18(r1)",
        f"#   ld      r31, -0x10(r1)",
        f"#   blr",
        f".set    lwz_r11_off_r31,                {_xgad('lwz_r11_off_r31')}      # .fill 0x58, 1, 0x00",
        "",
        f"#   stw     r30, 0(r31)",
        f"#   addi    r1, r1, 0x70",
        f"#   lwz     r12, -8(r1)",
        f"#   mtlr    r12",
        f"#   ld      r30, -0x18(r1)",
        f"#   ld      r31, -0x10(r1)",
        f"#   blr",
        f".set    stw_r30_on_r31,                 {_xgad('stw_r30_on_r31')}      # .fill 0x58, 1, 0x00",
        "",
        f"#   lwz     r11, 4(r31)",
        f"#   stw     r3, 0(r11)",
        f"#   li      r3, 0",
        f"#   addi    r1, r1, 0x60",
        f"#   lwz     r12, -8(r1)",
        f"#   mtlr    r12",
        f"#   ld      r31, -0x10(r1)",
        f"#   blr",
        f".set    stw_r3_onto_pointer,            {_xgad('stw_r3_onto_pointer')}      # .fill 0x50, 1, 0x00",
        "",
        f"#   lwz     r10, 8(r11)",
        f"#   add     r10, r5, r10",
        f"#   stw     r10, 8(r11)",
        f"#   blr",
        f".set    load_add_store_r10_r5_on_r11,   {_xgad('load_add_store_r10_r5_on_r11')}",
        "",
        f"#   mr      r7, r25",
        f"#   mtctr   r30",
        f"#   mr      r6, r26",
        f"#   mr      r5, r27",
        f"#   mr      r4, r28",
        f"#   mr      r3, r29",
        f"#   bctrl",
        f".set    call_func_preload,              {_xgad('call_func_preload')}",
        "",
        f"# Default register values for unused parameters to call_func_preload:",
        f".set    cf_r3_def,                      0x{cf_r3_def:08X}",
        f".set    cf_r4_def,                      0x{cf_r4_def:08X}",
        f".set    cf_r5_def,                      0x{cf_r5_def:08X}",
        f".set    cf_r6_def,                      0x{cf_r6_def:08X}",
        f".set    cf_r7_def,                      0x{cf_r7_def:08X}",
        "",
        f"# Offsets for low half of argument registers in CALL_FUNC_LABEL macro:",
        f".set    cf_r3_offset,                   0x{cf_r3_offset:02X}",
        f".set    cf_r4_offset,                   0x{cf_r4_offset:02X}",
        f".set    cf_r5_offset,                   0x{cf_r5_offset:02X}",
        f".set    cf_r6_offset,                   0x{cf_r6_offset:02X}",
        f".set    cf_r7_offset,                   0x{cf_r7_offset:02X}",
        "",
        f"#   mr      r3, r1",
        f"#   blr",
        f".set    mr_r1_to_r3,                    {_xgad('mr_r1_to_r3')}",
        "",
        f"#   blr",
        f".set    blr_nop,                        {_v(blr_nop_va, 'mr_r1_to_r3 + 4')}",
        "",
        f"#   cmplwi  r3, 0",
        f"#   li      r3, 0",
        f"#   beq     <skip>",
        f"#       li      r3, 1",
        f"#",
        f"#   addi    r1, r1, 0x60",
        f"#   lwz     r12, -8(r1)",
        f"#   mtlr    r12",
        f"#   ld      r31, -0x10(r1)",
        f"#   blr",
        f".set    clamp_r3,                       {_xgad('clamp_r3')}      # .fill 0x50, 1, 0x00",
        "",
        f"#   slwi    r10, r3, 2",
        f"#   addi    r11, r11, 0x{mul_disp:04X}",
        f"#   lwzx    r3, r10, r11",
        f"#   blr",
        f".set    mul_r3_4_lwzx_r11,              {_xgad('mul_r3_4_lwzx_r11')}",
        f".set    mul_r3_4_lwzx_r11__disp,        0x{mul_disp:04X}",
        "",
        f"#   lwz     r11, 0x{las_disp:02X}(r31)",
        f"#   add     r11, r30, r11",
        f"#   stw     r11, 0x{las_disp:02X}(r31)",
        f"#   addi    r1, r1, 0x70",
        f"#   lwz     r12, -8(r1)",
        f"#   mtlr    r12",
        f"#   ld      r30, -0x18(r1)",
        f"#   ld      r31, -0x10(r1)",
        f"#   blr",
        f".set    load_add_store_r11_r30_on_r31,          {_xgad('load_add_store_r11_r30_on_r31')}      # .fill 0x58, 1, 0x00",
        f".set    load_add_store_r11_r30_on_r31__disp,    0x{las_disp:02X}",
        "",
        f"#   lwz     r11, 0(r31)",
        f"#   mtctr   r11",
        f"#   bctrl",
        f".set    call_ptr_off_r31,                       {_xgad('call_ptr_off_r31')}",
        "",
        "",
        f"# Note these addresses must be in the first segment of the hv or else a 64-bit address is required!",
        "",
        f".ifdef RETAIL_BUILD",
        "",
        f"# Hypervisor function addresses for retail {build}:",
        f"# TODO: These REQUIRE the CPU key and manual HV binary analysis.",
        f"# See README section 'Extraindo a CPU key via BadUpdate'.",
        f".set HvpRelocateCacheLines,                 0x00000000  # TODO: HV offset (not VA)",
        f".set HvpSetRMCI,                            0x00000000  # TODO: HV offset (not VA)",
        "",
        f".else",
        f"    .error \"Stage 4 support for debug builds not implemented\"",
        f".endif",
    ]

    with open(out_path, "w", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")

    print(f"\n[OUTPUT] Wrote: {out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Xbox 360 kernel address extractor for BadUpdate exploit porting.\n\n"
            "Parses decrypted XEX2 files to auto-fill a KernelConfig_Retail_<build>.asm."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--kernel",   metavar="FILE",
                        help="Decrypted xboxkrnl.exe XEX2 (run: xextool -e retail xboxkrnl.exe)")
    parser.add_argument("--xam",      metavar="FILE",
                        help="Decrypted xam.xex XEX2 (run: xextool -e retail xam.xex)")
    parser.add_argument("--bootanim", metavar="FILE",
                        help="Decrypted bootanim.xex XEX2 (run: xextool -e retail bootanim.xex)")
    parser.add_argument("--output",   metavar="DIR",
                        help="Directory to write KernelConfig_Retail_<build>.asm into")
    args = parser.parse_args()

    if not any([args.kernel, args.xam, args.bootanim]):
        parser.print_help()
        return 1

    krnl     = analyse_kernel(args.kernel)     if args.kernel   else {}
    xam_data = analyse_xam(args.xam)           if args.xam      else {}
    bootanim = analyse_bootanim(args.bootanim) if args.bootanim else {}

    print_report(krnl, xam_data, bootanim)

    if args.output:
        build = krnl.get("build", 0) or 0
        if build == 0:
            print("[!] Cannot determine build number — --output skipped")
        else:
            out_dir = args.output.rstrip("/\\")
            os.makedirs(out_dir, exist_ok=True)
            out_file = os.path.join(out_dir, f"KernelConfig_Retail_{build}.asm")
            generate_kernelconfig(krnl, xam_data, bootanim, out_file)

    return 0


if __name__ == "__main__":
    sys.exit(main())
