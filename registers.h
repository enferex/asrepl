/*******************************************************************************
 * BSD 3-Clause License
 *
 * Copyright (c) 2017, Matt Davis (enferex) https://github.com/enferex
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
#ifndef __REGISTERS_H
#define __REGISTERS_H

#include <stdint.h>

/* Instruction Set Architecture tags */
typedef enum _isa_e
{
    ISA_UNKNOWN,
    ISA_X8632,
    ISA_X8664,
    ISA_ARM,
    ISA_ARM64,
    ISA_MIPS32,
} isa_e;

/* Names accepted from the '-a' command line option. */
static const char *isa_names[] __attribute__((unused)) =
{
    [ISA_X8632]  = "x8632",
    [ISA_X8664]  = "x8664",
    [ISA_ARM]    = "arm",
    [ISA_ARM64]  = "aarch64",
    [ISA_MIPS32] = "mips32",
};

extern isa_e isa_from_string(const char *string);
extern const char *isa_all_names(void);

typedef struct _x8632_regs_t
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t ebp, esp, edi, esi;
    uint32_t cs, ds, es, fs, gs, ss;
    uint32_t eip, eflags;
} x8632_regs_t;

typedef struct _x8664_regs_t
{
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rbp, rsp, rdi, rsi;
    uint64_t cs, ds, es, fs, gs, ss;
    uint64_t rip, eflags;
} x8664_regs_t;

typedef struct _arm_regs_t
{
    uint32_t cpsr, pc, sp, lr;
    uint32_t r0, r1, r2, r3, r4, r5;
    uint32_t r6, r7, r8, r9, r10, r11, r12;
} arm_regs_t;

typedef struct _mips32_regs_t
{
    uint32_t gp, sp, fp, ra;
    uint32_t zero, at, v0, v1;
    uint32_t a0, a1, a2, a3;
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
    uint32_t s0, s1, s2, s3, s4, s5, s6, s7;
    uint32_t k0, k1;
} mips32_regs_t;

/* Mmmm fake algebraic data type */
typedef union _registers_t
{
    union {
        x8632_regs_t  x8632;
        x8664_regs_t  x8664;
        arm_regs_t    arm;
        mips32_regs_t mips32;
    } u;

    isa_e tag; /* Which union variant is represented by 'u' */
} registers_u;

/* Accessors */
#define REGS_X8632(_eng)  ((_eng)->registers.u.x8632)
#define REGS_X8664(_eng)  ((_eng)->registers.u.x8664)
#define REGS_ARM(_eng)    ((_eng)->registers.u.arm)
#define REGS_MIPS32(_eng) ((_eng)->registers.u.mips32)

#endif /* __REGISTERS_H */
