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
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "common.h"
#include "../asrepl.h"
#include "../config.h"

#ifdef HAVE_LIBUNICORN
#include <unicorn/unicorn.h>

#define UC_TEXT_ADDR 0x10000000

#define REG64(_eng, _reg) \
    printf("%s\t 0x%llx\n", #_reg, REGS_X8664(_eng)._reg)

static _Bool unicorn_x8664_init(engine_t *eng)
{
    uc_engine *uc;
    uc_err err;
    uc_context *context = NULL;

    /* TODO: parameterize execution mode via engine_t Arch/Mode flags */
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        ERR("Error opening unicorn engine [uc_open()]: %s", uc_strerror(err));
        return false;
    }

    /* TODO: parametrize UC_TEXT_ADDR based upon the Arch being emulated */
    err = uc_mem_map(uc, UC_TEXT_ADDR, 2*1024*1024, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        ERR("Error mapping executable page [uc_mem_map()]: %s",
            uc_strerror(err));
        return false;
    }

    eng->handle = (engine_h)uc;
    eng->state  = (engine_h)context;
    return true;
}

static _Bool unicorn_x8664_shutdown(engine_t *eng)
{
    uc_engine *uc = (uc_engine *)eng->handle;
    uc_context *context = (uc_context *)eng->state;

    if (!uc)
      return false;

    /* A Unicorn context may or may not have been allocated */
    if (context)
      uc_free(context);

    uc_close(uc);
    return true;
}

void unicorn_x8664_execute(engine_t *eng, const ctx_t *ctx)
{
    uc_err err;
    uc_engine *uc = (uc_engine *)eng->handle;
    uc_context *context = (uc_context*)eng->state;

    err = uc_mem_write(uc, UC_TEXT_ADDR, ctx->text, ctx->length);
    if (err != UC_ERR_OK) {
        ERR("Failed to write ops to execution memory [uc_mem_write()]: %s",
            uc_strerror(err));
        return;
    }

    /* Use the existing uc state, or allocate a fresh one. */
    if (context) {
        err = uc_context_restore(uc, context);
        if (err != UC_ERR_OK) {
            ERR("Failed to restore unicorn execution "
                "context [uc_context_restore()]: %s",
                uc_strerror(err));
            return;
        }
    } 
    else {
        err = uc_context_alloc(uc, &context);
        if (err != UC_ERR_OK) {
            ERR("Failed to allocat Unicorn context "
                "struct [uc_context_alloc()]: %s",
                uc_strerror(err));
            return;
        }
        eng->state = (engine_h)context;
    }

    err = uc_emu_start(uc, UC_TEXT_ADDR, UC_TEXT_ADDR+ctx->length, 0, 0);
    if (err) {
        ERR("Failed to start emulation [uc_emu_start()]: %s", uc_strerror(err));
        return;
    }

    err = uc_context_save(uc, context);
    if (err != UC_ERR_OK) {
        ERR("Failed to save the unicorn context [uc_context_save()]: %s", uc_strerror(err));
        return;
    }

}

static void unicorn_x8664_read_registers(engine_t *eng)
{
#define R(_eng, _reg) (&(REGS_X8664(_eng)._reg))
    uc_reg_read(eng->handle, UC_X86_REG_EFLAGS, R(eng, eflags));
    uc_reg_read(eng->handle, UC_X86_REG_RIP,    R(eng, rip));
    uc_reg_read(eng->handle, UC_X86_REG_CS,     R(eng, cs));
    uc_reg_read(eng->handle, UC_X86_REG_DS,     R(eng, ds));
    uc_reg_read(eng->handle, UC_X86_REG_ES,     R(eng, es));
    uc_reg_read(eng->handle, UC_X86_REG_FS,     R(eng, fs));
    uc_reg_read(eng->handle, UC_X86_REG_GS,     R(eng, gs));
    uc_reg_read(eng->handle, UC_X86_REG_SS,     R(eng, ss));
    uc_reg_read(eng->handle, UC_X86_REG_RBP,    R(eng, rbp));
    uc_reg_read(eng->handle, UC_X86_REG_RSP,    R(eng, rsp));
    uc_reg_read(eng->handle, UC_X86_REG_RAX,    R(eng, rax));
    uc_reg_read(eng->handle, UC_X86_REG_RBX,    R(eng, rbx));
    uc_reg_read(eng->handle, UC_X86_REG_RCX,    R(eng, rcx));
    uc_reg_read(eng->handle, UC_X86_REG_RDX,    R(eng, rdx));
    uc_reg_read(eng->handle, UC_X86_REG_RDI,    R(eng, rdi));
    uc_reg_read(eng->handle, UC_X86_REG_RSI,    R(eng, rsi));
    uc_reg_read(eng->handle, UC_X86_REG_R8,     R(eng, r8));
    uc_reg_read(eng->handle, UC_X86_REG_R9,     R(eng, r9));
    uc_reg_read(eng->handle, UC_X86_REG_R10,    R(eng, r10));
    uc_reg_read(eng->handle, UC_X86_REG_R11,    R(eng, r11));
    uc_reg_read(eng->handle, UC_X86_REG_R12,    R(eng, r12));
    uc_reg_read(eng->handle, UC_X86_REG_R13,    R(eng, r13));
    uc_reg_read(eng->handle, UC_X86_REG_R14,    R(eng, r14));
    uc_reg_read(eng->handle, UC_X86_REG_R15,    R(eng, r15));
}

/*
 * REGISTRATION
 */
const engine_desc_t *unicorn_x8664_registration(void)
{
    static const engine_desc_t desc = {
        .type           = ENGINE_UNICORN,
        .init           = unicorn_x8664_init,
        .execute        = unicorn_x8664_execute,
        .shutdown       = unicorn_x8664_shutdown,
        .read_registers = unicorn_x8664_read_registers,
        .dump_registers = common_x8664_dump_registers
    };

    return &desc;
}

#endif /* HAVE_LIBUNICORN */
