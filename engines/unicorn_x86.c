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
#include "common.h"
#include "unicorn.h"
#include "../asrepl.h"
#include "../config.h"

#ifdef HAVE_LIBUNICORN
#include <unicorn/unicorn.h>

static void unicorn_x8632_read_registers(engine_t *eng)
{
#define R32(_eng, _reg) (&(REGS_X8632(_eng)._reg))
	uc_reg_read(eng->handle, UC_X86_REG_EFLAGS, R32(eng, eflags));
	uc_reg_read(eng->handle, UC_X86_REG_EIP,    R32(eng, eip));
	uc_reg_read(eng->handle, UC_X86_REG_CS,     R32(eng, cs));
	uc_reg_read(eng->handle, UC_X86_REG_DS,     R32(eng, ds));
	uc_reg_read(eng->handle, UC_X86_REG_ES,     R32(eng, es));
	uc_reg_read(eng->handle, UC_X86_REG_FS,     R32(eng, fs));
	uc_reg_read(eng->handle, UC_X86_REG_GS,     R32(eng, gs));
	uc_reg_read(eng->handle, UC_X86_REG_SS,     R32(eng, ss));
	uc_reg_read(eng->handle, UC_X86_REG_EBP,    R32(eng, ebp));
	uc_reg_read(eng->handle, UC_X86_REG_ESP,    R32(eng, esp));
	uc_reg_read(eng->handle, UC_X86_REG_EAX,    R32(eng, eax));
	uc_reg_read(eng->handle, UC_X86_REG_EBX,    R32(eng, ebx));
	uc_reg_read(eng->handle, UC_X86_REG_ECX,    R32(eng, ecx));
	uc_reg_read(eng->handle, UC_X86_REG_EDX,    R32(eng, edx));
	uc_reg_read(eng->handle, UC_X86_REG_EDI,    R32(eng, edi));
	uc_reg_read(eng->handle, UC_X86_REG_ESI,    R32(eng, esi));
}

static void unicorn_x8664_read_registers(engine_t *eng)
{
#define R(_eng, _reg) (&(REGS_X8664(_eng)._reg))
    engine_h handle = eng->handle;

    uc_reg_read(handle, UC_X86_REG_EFLAGS, R(eng, eflags));
    uc_reg_read(handle, UC_X86_REG_RIP,    R(eng, rip));
    uc_reg_read(handle, UC_X86_REG_CS,     R(eng, cs));
    uc_reg_read(handle, UC_X86_REG_DS,     R(eng, ds));
    uc_reg_read(handle, UC_X86_REG_ES,     R(eng, es));
    uc_reg_read(handle, UC_X86_REG_FS,     R(eng, fs));
    uc_reg_read(handle, UC_X86_REG_GS,     R(eng, gs));
    uc_reg_read(handle, UC_X86_REG_SS,     R(eng, ss));
    uc_reg_read(handle, UC_X86_REG_RBP,    R(eng, rbp));
    uc_reg_read(handle, UC_X86_REG_RSP,    R(eng, rsp));
    uc_reg_read(handle, UC_X86_REG_RAX,    R(eng, rax));
    uc_reg_read(handle, UC_X86_REG_RBX,    R(eng, rbx));
    uc_reg_read(handle, UC_X86_REG_RCX,    R(eng, rcx));
    uc_reg_read(handle, UC_X86_REG_RDX,    R(eng, rdx));
    uc_reg_read(handle, UC_X86_REG_RDI,    R(eng, rdi));
    uc_reg_read(handle, UC_X86_REG_RSI,    R(eng, rsi));
    uc_reg_read(handle, UC_X86_REG_R8,     R(eng, r8));
    uc_reg_read(handle, UC_X86_REG_R9,     R(eng, r9));
    uc_reg_read(handle, UC_X86_REG_R10,    R(eng, r10));
    uc_reg_read(handle, UC_X86_REG_R11,    R(eng, r11));
    uc_reg_read(handle, UC_X86_REG_R12,    R(eng, r12));
    uc_reg_read(handle, UC_X86_REG_R13,    R(eng, r13));
    uc_reg_read(handle, UC_X86_REG_R14,    R(eng, r14));
    uc_reg_read(handle, UC_X86_REG_R15,    R(eng, r15));
}

/*
 * REGISTRATION
 */
const engine_desc_t *unicorn_x8632_registration(void)
{
    static const engine_desc_t desc = {
        .type           = ENGINE_UNICORN_X8632,
        .init           = unicorn_init,
        .execute        = unicorn_execute,
        .shutdown       = unicorn_shutdown,
        .read_registers = unicorn_x8632_read_registers,
        .dump_registers = common_x8632_dump_registers
    };

    return &desc;
}

const engine_desc_t *unicorn_x8664_registration(void)
{
    static const engine_desc_t desc = {
        .type           = ENGINE_UNICORN_X8664,
        .init           = unicorn_init,
        .execute        = unicorn_execute,
        .shutdown       = unicorn_shutdown,
        .read_registers = unicorn_x8664_read_registers,
        .dump_registers = common_x8664_dump_registers
    };

    return &desc;
}

#endif /* HAVE_LIBUNICORN */
