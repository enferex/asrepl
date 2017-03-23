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
#include <stdio.h>
#include "../asrepl_types.h"
#include "common.h"

#define REG32(_eng, _reg, _acc) \
    printf("%s\t 0x%x\n", #_reg, _acc(_eng)._reg)

#define REG64(_eng, _reg, _acc) \
    printf("%s\t 0x%lx\n", #_reg, _acc(_eng)._reg)

void common_x8664_dump_registers(engine_t *eng)
{
    REG64(eng, eflags, REGS_X8664);
    REG64(eng, rip,    REGS_X8664);
    REG64(eng, cs,     REGS_X8664);
    REG64(eng, ds,     REGS_X8664);
    REG64(eng, es,     REGS_X8664);
    REG64(eng, fs,     REGS_X8664);
    REG64(eng, gs,     REGS_X8664);
    REG64(eng, ss,     REGS_X8664);
    REG64(eng, rbp,    REGS_X8664);
    REG64(eng, rsp,    REGS_X8664);
    REG64(eng, rax,    REGS_X8664);
    REG64(eng, rbx,    REGS_X8664);
    REG64(eng, rcx,    REGS_X8664);
    REG64(eng, rdx,    REGS_X8664);
    REG64(eng, rdi,    REGS_X8664);
    REG64(eng, rsi,    REGS_X8664);
    REG64(eng, r8,     REGS_X8664);
    REG64(eng, r9,     REGS_X8664);
    REG64(eng, r10,    REGS_X8664);
    REG64(eng, r11,    REGS_X8664);
    REG64(eng, r12,    REGS_X8664);
    REG64(eng, r13,    REGS_X8664);
    REG64(eng, r14,    REGS_X8664);
    REG64(eng, r15,    REGS_X8664);
}

void common_x8632_dump_registers(engine_t *eng)
{
	REG32(eng, eflags, REGS_X8632);
	REG32(eng, eip,    REGS_X8632);
	REG32(eng, cs,     REGS_X8632);
	REG32(eng, ds,     REGS_X8632);
	REG32(eng, es,     REGS_X8632);
	REG32(eng, fs,     REGS_X8632);
	REG32(eng, gs,     REGS_X8632);
	REG32(eng, ss,     REGS_X8632);
	REG32(eng, ebp,    REGS_X8632);
	REG32(eng, esp,    REGS_X8632);
	REG32(eng, eax,    REGS_X8632);
	REG32(eng, ebx,    REGS_X8632);
	REG32(eng, ecx,    REGS_X8632);
	REG32(eng, edx,    REGS_X8632);
	REG32(eng, edi,    REGS_X8632);
	REG32(eng, esi,    REGS_X8632);
}

void common_arm_dump_registers(engine_t *eng)
{
	REG32(eng, cpsr, REGS_ARM);
	REG32(eng, pc,   REGS_ARM);
	REG32(eng, sp,   REGS_ARM);
	REG32(eng, lr,   REGS_ARM);
	REG32(eng, r0,   REGS_ARM);
	REG32(eng, r1,   REGS_ARM);
	REG32(eng, r2,   REGS_ARM);
	REG32(eng, r3,   REGS_ARM);
	REG32(eng, r4,   REGS_ARM);
	REG32(eng, r5,   REGS_ARM);
	REG32(eng, r6,   REGS_ARM);
	REG32(eng, r7,   REGS_ARM);
	REG32(eng, r8,   REGS_ARM);
	REG32(eng, r9,   REGS_ARM);
	REG32(eng, r10,  REGS_ARM);
	REG32(eng, r11,  REGS_ARM);
	REG32(eng, r12,  REGS_ARM);
}

void common_mips32_dump_registers(engine_t *eng)
{
	REG32(eng, gp,   REGS_MIPS32);
	REG32(eng, sp,   REGS_MIPS32);
	REG32(eng, fp,   REGS_MIPS32);
	REG32(eng, ra,   REGS_MIPS32);

	REG32(eng, zero, REGS_MIPS32);
	REG32(eng, at,   REGS_MIPS32);
	REG32(eng, v0,   REGS_MIPS32);
	REG32(eng, v1,   REGS_MIPS32);

	REG32(eng, a0,   REGS_MIPS32);
	REG32(eng, a1,   REGS_MIPS32);
	REG32(eng, a2,   REGS_MIPS32);
	REG32(eng, a3,   REGS_MIPS32);

	REG32(eng, t0,   REGS_MIPS32);
	REG32(eng, t1,   REGS_MIPS32);
	REG32(eng, t2,   REGS_MIPS32);
	REG32(eng, t3,   REGS_MIPS32);
	REG32(eng, t4,   REGS_MIPS32);
	REG32(eng, t5,   REGS_MIPS32);
	REG32(eng, t6,   REGS_MIPS32);
	REG32(eng, t7,   REGS_MIPS32);
	REG32(eng, t8,   REGS_MIPS32);
	REG32(eng, t9,   REGS_MIPS32);

	REG32(eng, s0,   REGS_MIPS32);
	REG32(eng, s1,   REGS_MIPS32);
	REG32(eng, s2,   REGS_MIPS32);
	REG32(eng, s3,   REGS_MIPS32);
	REG32(eng, s4 ,  REGS_MIPS32);
	REG32(eng, s5,   REGS_MIPS32);
	REG32(eng, s6,   REGS_MIPS32);
	REG32(eng, s7,   REGS_MIPS32);

	REG32(eng, k0,   REGS_MIPS32);
	REG32(eng, k1,   REGS_MIPS32);
}
