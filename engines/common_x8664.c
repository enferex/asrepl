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

#define REG64(_eng, _reg) \
    printf("%s\t 0x%lx\n", #_reg, REGS_X8664(_eng)._reg)

void common_x8664_dump_registers(engine_t *eng)
{
    REG64(eng, eflags);
    REG64(eng, rip);
    REG64(eng, cs);
    REG64(eng, ds);
    REG64(eng, es);
    REG64(eng, fs);
    REG64(eng, gs);
    REG64(eng, ss);
    REG64(eng, rbp);
    REG64(eng, rsp);
    REG64(eng, rax);
    REG64(eng, rbx);
    REG64(eng, rcx);
    REG64(eng, rdx);
    REG64(eng, rdi);
    REG64(eng, rsi);
    REG64(eng, r8);
    REG64(eng, r9);
    REG64(eng, r10);
    REG64(eng, r11);
    REG64(eng, r12);
    REG64(eng, r13);
    REG64(eng, r14);
    REG64(eng, r15);
}
