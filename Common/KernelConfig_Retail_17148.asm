# KernelConfig_Retail_17148.asm
# Kernel version: 17148  (0x42DC)
#
# HOW TO FILL THIS IN
# ===================
# Run Tools/kernel_port.py on the decrypted XEX2 files from the 17148 $SystemUpdate:
#
#   xextool -e retail xboxkrnl.exe -o xboxkrnl_dec.bin
#   xextool -e retail xam.xex      -o xam_dec.bin
#   xextool -e retail bootanim.xex -o bootanim_dec.bin
#
#   python3 Tools/kernel_port.py \
#       --kernel  xboxkrnl_dec.bin \
#       --xam     xam_dec.bin      \
#       --bootanim bootanim_dec.bin \
#       --output  Common/
#
# That command will:
#   1. Parse the XEX2 export tables to find all kernel/XAM function addresses
#   2. Scan for 'li r0, <ordinal> ; sc' patterns to find syscall stub addresses
#   3. Scan for every ROP gadget byte pattern used by the exploit
#   4. Write out this file pre-filled with everything that could be auto-detected
#
# Values that CANNOT be auto-detected are marked '# TODO' and must be found
# with IDA Pro / Ghidra (PowerPC 64-bit, big-endian) as described in the README.
#
# Category 6 values (HvpRelocateCacheLines, HvpSetRMCI, and the two RSA patch
# addresses) require the CPU key and manual analysis of the HV binary —
# see README section 'Extraindo a CPU key via BadUpdate'.

# Specify the kernel version so the build config file knows the kernel addresses have been defined.
.set KRNL_VER,              17148

# Kernel function addresses:
.set DbgPrint,                          0x00000000  # TODO
.set DbgBreakPoint,                     0x00000000  # TODO
.set HalSendSMCMessage,                 0x00000000  # TODO
.set KeFlushCacheRange,                 0x00000000  # TODO
.set KeLockL2,                          0x00000000  # TODO
.set KeStallExecutionProcessor,         0x00000000  # TODO
.set MmFreePhysicalMemory,              0x00000000  # TODO
.set MmGetPhysicalAddress,              0x00000000  # TODO
.set NtAllocateVirtualMemory,           0x00000000  # TODO
.set NtClose,                           0x00000000  # TODO
.set ObCreateSymbolicLink,              0x00000000  # TODO
.set RtlInitAnsiString,                 0x00000000  # TODO
.set VdDisplayFatalError,               0x00000000  # TODO
.set XexLoadImage,                      0x00000000  # TODO
.set XexUnloadImage,                    0x00000000  # TODO

.set memcmp,                            0x00000000  # TODO: Can be substituted for XeCryptMemDiff if memcmp is not available (do NOT use RtlCompareMemory, it doesn't return 0 on matching data)

# System call functions:
.set HvxKeysExGetKey,                   0x00000000  # TODO: scan for 'li r0, <ord> ; sc' where ord = HvxKeysExGetKey ordinal
.set HvxKeysExSetKey,                   0x00000000  # TODO: scan for 'li r0, <ord> ; sc' where ord = HvxKeysExSetKey ordinal
.set HvxEncryptedReserveAllocation,     0x00000000  # TODO: scan for 'li r0, 0x49 ; sc'
.set HvxEncryptedReleaseAllocation,     0x00000000  # TODO: scan for 'li r0, 0x4C ; sc'
.set HvxEncryptedEncryptAllocation,     0x00000000  # TODO: scan for 'li r0, 0x4A ; sc'
.set HvxFlushDCacheRange,               0x00000000  # TODO: scan for 'li r0, <ord> ; sc' where ord = HvxFlushDCacheRange ordinal

# System call ordinals:
# These are stable across retail kernel versions and are unlikely to change
# between 17147, 17148, and 17559.
.set sc_HvxPostOutputExploit,           0x0D
.set sc_HvxFlushUserModeTb,             0x21
.set sc_HvxKeysExecute,                 0x42
.set sc_HvxEncryptedReserveAllocation,  0x49
.set sc_HvxEncryptedEncryptAllocation,  0x4A
.set sc_HvxEncryptedReleaseAllocation,  0x4C
.set sc_HvxRevokeUpdate,                0x65

.set sc_HvxArbWriteSyscall,             sc_HvxFlushUserModeTb

# Boot animation addresses:
.set BootAnimCodePageAddress,           0x00000000  # TODO: load address of bootanim.xex (run kernel_port.py --bootanim)

# Xam function addresses:
.set CreateFileA,                       0x00000000  # TODO: Export 1095
.set GetFileSize,                       0x00000000  # TODO: Export 1063
.set ReadFile,                          0x00000000  # TODO: Export 1052
.set WriteFile,                         0x00000000  # TODO: Export 1054
.set CloseHandle,                       0x00000000  # TODO: Export 1044

.set CreateThread,                      0x00000000  # TODO: Export 1084
.set ResumeThread,                      0x00000000  # TODO: Export 1085
.set GetLastError,                      0x00000000  # TODO: Export 1006

.set memcpy,                            0x00000000  # TODO: manual search in IDA/Ghidra
.set memset,                            0x00000000  # TODO: manual search in IDA/Ghidra

.set XamLoaderLaunchTitle,              0x00000000  # TODO: Export 420
.set XamLoaderTerminateTitle,           0x00000000  # TODO: Export 425
.set XLaunchNewImage,                   XamLoaderLaunchTitle


###########################################################
# Kernel gadget address.

#   addi    r1, r1, 0xA0
#   b       __restgprlr_24
.set    __restgprlr_24,                 0x00000000  # TODO  .fill 0x58, 1, 0x00

#   addi    r1, r1, 0x90
#   b       __restgprlr_26
.set    __restgprlr_26,                 0x00000000  # TODO  .fill 0x58, 1, 0x00

#   addi    r1, r1, 0x80
#   b       __restgprlr_27
.set    __restgprlr_27,                 0x00000000  # TODO  .fill 0x50, 1, 0x00

#   addi    r1, r1, 0x80
#   b       __restgprlr_28
.set    __restgprlr_28,                 0x00000000  # TODO  .fill 0x58, 1, 0x00

#   addi    r1, r1, 0x70
#   b       __restgprlr_29
.set    __restgprlr_29,                 0x00000000  # TODO  .fill 0x50, 1, 0x00

#   addi    r1, r1, 0x70
#   lwz     r12, -0x8(r1)
#   mtlr    r12
#   ld      r30, -0x18(r1)
#   ld      r31, -0x10(r1)
#   blr
.set    __restgprlr_30,                 0x00000000  # TODO  .fill 0x58, 1, 0x00

#   addi    r1, r1, 0x60
#   lwz     r12, -0x8(r1)
#   mtlr    r12
#   ld      r31, -0x10(r1)
#   blr
.set    __restgprlr_31,                 0x00000000  # TODO  .fill 0x50, 1, 0x00

#   stw     r3, 0(r31)
#   addi    r1, r1, 0x60
#   lwz     r12, -0x8(r1)
#   mtlr    r12
#   ld      r31, -0x10(r1)
#   blr
.set    stw_r3,                         0x00000000  # TODO  .fill 0x50, 1, 0x00

#   mr      r3, r31
#   addi    r1, r1, 0x70
#   lwz     r12, -8(r1)
#   mtlr    r12
#   ld      r31, -0x10(r1)
#   blr
.set    mr_r31_to_r3,                   0x00000000  # TODO  .fill 0x60, 1, 0x00

#   mr      r11, r31
#   mr      r3, r11
#   addi    r1, r1, 0x70
#   lwz     r12, -8(r1)
#   mtlr    r12
#   ld      r30, -0x18(r1)
#   ld      r31, -0x10(r1)
#   blr
.set    mr_r31_to_r11,                  0x00000000  # TODO  .fill 0x58, 1, 0x00

#   mtctr   r31
#   bctrl
#   addi    r1, r1, 0x60
#   lwz     r12, -8(r1)
#   mtlr    r12
#   ld      r31, -0x10(r1)
#   blr
.set    call_func_dispatch,             0x00000000  # TODO  .fill 0x50, 1, 0x00


###########################################################
# Xam gadget address.

#   lwz     r1, 0(r1)
#   lwz     r12, -8(r1)
#   mtlr    r12
#   blr
.set    stack_pivot,                    0x00000000  # TODO

#   lwz     r3, 0(r31)
#   addi    r1, r1, 0x60
#   lwz     r12, var_8(r1)
#   mtlr    r12
#   ld      r31, var_10(r1)
#   blr
.set    lwz_r3,                         0x00000000  # TODO  .fill 0x50, 1, 0x00

#   lwz     r11, 0(r3)
#   stw     r11, 8(r4)
#   li      r3, 0
#   blr
.set    lwz_r3_stw_r4,                  0x00000000  # TODO
.set    lwz_r3_stw_r4__r3_disp,         0               # Displacement for r3 load
.set    lwz_r3_stw_r4__r4_disp,         8               # Displacement for r4 store

#   lwz     r10, 0(r3)
#   slwi    r11, r11, 2
#   add     r3, r11, r10
#   blr
.set    lwz_r10,                        0x00000000  # TODO

#   lwz     r11, 8(r31)
#   addi    r3, r11, -1
#   addi    r1, r1, 0x70
#   lwz     r12, -8(r1)
#   mtlr    r12
#   ld      r30, -0x18(r1)
#   ld      r31, -0x10(r1)
#   blr
.set    lwz_r11_off_r31,                0x00000000  # TODO  .fill 0x58, 1, 0x00

#   stw     r30, 0(r31)
#   addi    r1, r1, 0x70
#   lwz     r12, -8(r1)
#   mtlr    r12
#   ld      r30, -0x18(r1)
#   ld      r31, -0x10(r1)
#   blr
.set    stw_r30_on_r31,                 0x00000000  # TODO  .fill 0x58, 1, 0x00

#   lwz     r11, 4(r31)
#   stw     r3, 0(r11)
#   li      r3, 0
#   addi    r1, r1, 0x60
#   lwz     r12, -8(r1)
#   mtlr    r12
#   ld      r31, -0x10(r1)
#   blr
.set    stw_r3_onto_pointer,            0x00000000  # TODO  .fill 0x50, 1, 0x00

#   lwz     r10, 8(r11)
#   add     r10, r5, r10
#   stw     r10, 8(r11)
#   blr
.set    load_add_store_r10_r5_on_r11,   0x00000000  # TODO

#   mr      r7, r25
#   mtctr   r30
#   mr      r6, r26
#   mr      r5, r27
#   mr      r4, r28
#   mr      r3, r29
#   bctrl
.set    call_func_preload,              0x00000000  # TODO

# Default register values for unused parameters to call_func_preload:
.set    cf_r3_def,                      0x29292929
.set    cf_r4_def,                      0x28282828
.set    cf_r5_def,                      0x27272727
.set    cf_r6_def,                      0x26262626
.set    cf_r7_def,                      0x25252525

# Offsets for low half of argument registers in CALL_FUNC_LABEL macro:
.set    cf_r3_offset,                   0x2C
.set    cf_r4_offset,                   0x24
.set    cf_r5_offset,                   0x1C
.set    cf_r6_offset,                   0x14
.set    cf_r7_offset,                   0x0C

#   mr      r3, r1
#   blr
.set    mr_r1_to_r3,                    0x00000000  # TODO

#   blr
.set    blr_nop,                        0x00000000  # TODO: = mr_r1_to_r3 + 4

#   cmplwi  r3, 0
#   li      r3, 0
#   beq     <skip>
#       li      r3, 1
#
#   addi    r1, r1, 0x60
#   lwz     r12, -8(r1)
#   mtlr    r12
#   ld      r31, -0x10(r1)
#   blr
.set    clamp_r3,                       0x00000000  # TODO  .fill 0x50, 1, 0x00

#   slwi    r10, r3, 2
#   addi    r11, r11, <disp>
#   lwzx    r3, r10, r11
#   blr
.set    mul_r3_4_lwzx_r11,              0x00000000  # TODO
.set    mul_r3_4_lwzx_r11__disp,        0x0000      # TODO: displacement (varies per build)

#   lwz     r11, <disp>(r31)
#   add     r11, r30, r11
#   stw     r11, <disp>(r31)
#   addi    r1, r1, 0x70
#   lwz     r12, -8(r1)
#   mtlr    r12
#   ld      r30, -0x18(r1)
#   ld      r31, -0x10(r1)
#   blr
.set    load_add_store_r11_r30_on_r31,          0x00000000  # TODO  .fill 0x58, 1, 0x00
.set    load_add_store_r11_r30_on_r31__disp,    0x18        # TODO: displacement (check in IDA)

#   lwz     r11, 0(r31)
#   mtctr   r11
#   bctrl
.set    call_ptr_off_r31,                       0x00000000  # TODO


# Note these addresses must be in the first segment of the hv or else a 64-bit address is required!

.ifdef RETAIL_BUILD

# Hypervisor function addresses for retail 17148:
# TODO: These REQUIRE the CPU key and manual HV binary analysis.
# See README section 'Extraindo a CPU key via BadUpdate'.
.set HvpRelocateCacheLines,                 0x00000000  # TODO: HV offset (not VA)
.set HvpSetRMCI,                            0x00000000  # TODO: HV offset (not VA)

.else
    .error "Stage 4 support for debug builds not implemented"
.endif
