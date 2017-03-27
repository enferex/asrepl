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
#include "../config.h"
#ifdef HAVE_LIBUNICORN

#include <stdbool.h>
#include <stdint.h>
#include <unicorn/unicorn.h>
#include "unicorn.h"
#include "../asrepl.h"
#include "../asrepl_types.h"

/* ISA is chosen via (-a) command line read from main.c
 *
 * XXX If this is updated, also update assembler.c
 */
static void unicorn_set_config(engine_t *eng, isa_e isa)
{
    switch (isa) {
    case ISA_ARM:
        eng->march = UC_ARCH_ARM;
        eng->mmode = UC_MODE_ARM;
        break;

    case ISA_ARM64:
        eng->march = UC_ARCH_ARM64;
        eng->mmode = UC_MODE_ARM;
        break;

    /* x86 */
    case ISA_X8632:
        eng->march = UC_ARCH_X86;
        eng->mmode = UC_MODE_32;
        break;

    /* x86-64 */
    case ISA_X8664:
        eng->march = UC_ARCH_X86;
        eng->mmode = UC_MODE_64;
        break;

    case ISA_MIPS32:
        eng->march = UC_ARCH_MIPS;
        eng->mmode = UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN;
        break;

    default:
         ERF("Invalid arch (-a) specified.");
    }
}

_Bool unicorn_init(asrepl_t *asr, engine_t *eng)
{
    uc_engine *uc;
    uc_err err;
    uint32_t r_sp;
    uc_context *context;

    /* Figure out what configuration of unicorn to use. */
    unicorn_set_config(eng, asr->isa);

    err = uc_open(eng->march, eng->mmode, &uc);
    if (err != UC_ERR_OK) {
        ERR("Error opening Unicorn engine [uc_open()]: %s", uc_strerror(err));
        return false;
    }

    /*TODO: parametrize UC_TEXT_ADDR based upon the Arch being emulated */
    err = uc_mem_map(uc, UC_TEXT_ADDR, 2*1024*1024, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        ERR("Error mapping executable page [uc_mem_map()]: %s",
            uc_strerror(err));
        return false;
    }

    err = uc_context_alloc(uc, &context);
    if (err != UC_ERR_OK) {
        ERR("Failed to allocate Unicorn context struct "
            "[uc_context_alloc()]: %s",
            uc_strerror(err));
        return false;
    }
    eng->state = (engine_h)context;

    /* Base address to bottom of 2MB alloc, less 1KB for padding. */
    r_sp = UC_TEXT_ADDR + 0x200000 - 0x400;
    switch(eng->march) {
    case UC_ARCH_X86:   uc_reg_write(uc, UC_X86_REG_ESP, &r_sp); break;
    case UC_ARCH_ARM:   uc_reg_write(uc, UC_ARM_REG_SP,  &r_sp); break;
    case UC_ARCH_ARM64: uc_reg_write(uc, UC_ARM_REG_SP,  &r_sp); break;
    case UC_ARCH_MIPS:  uc_reg_write(uc, UC_MIPS_REG_SP, &r_sp); break;
    default: ERF("Invalid march specified.");
    }

    err = uc_context_save(uc, context);
    if (err != UC_ERR_OK) {
        ERR("Failed to save the Unicorn context [uc_context_save()]: %s",
            uc_strerror(err));
        return false;
    }

    eng->handle = (engine_h)uc;
    eng->state  = (engine_h)context;
    return true;
}

_Bool unicorn_shutdown(engine_t *eng)
{
    uc_engine *uc       = (uc_engine *)eng->handle;
    uc_context *context = (uc_context *)eng->state;

    if (!uc)
      return false;

    /* A Unicorn context may or may not have been allocated. */
    if (context)
      uc_free(context);

    uc_close(uc);
    return true;
}

void unicorn_execute(engine_t *eng, const ctx_t *ctx)
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

    if (context) {
        err = uc_context_restore(uc, context);
        if (err != UC_ERR_OK) {
            ERR("Failed to restore unicorn execution context "
                "[uc_context_restore()]: %s",
                uc_strerror(err));
            return;
        }
    }

    err = uc_emu_start(uc, UC_TEXT_ADDR, UC_TEXT_ADDR+ctx->length, 0, 0);
    if (err != UC_ERR_OK) {
        ERR("Failed to start emulation [uc_emu_start()]: %s", uc_strerror(err));
        return;
    }

    err = uc_context_save(uc, context);
    if (err != UC_ERR_OK) {
        ERR("Failed to save the unicorn context [uc_context_save()]: %s",
            uc_strerror(err));
        return;
    }
}

engine_e unicorn_engine_from_isa(isa_e isa)
{
    switch (isa)
    {
        case ISA_X8632:   return ENGINE_UNICORN_X8632;
        case ISA_X8664:   return ENGINE_UNICORN_X8664;
        case ISA_ARM:     return ENGINE_UNICORN_ARM;
        case ISA_ARM64:   return ENGINE_UNICORN_ARM;
        case ISA_MIPS32:  return ENGINE_UNICORN_MIPS32;
        case ISA_UNKNOWN: return ENGINE_INVALID;
    }

    return ENGINE_INVALID;
}

#endif /* HAVE_LIBUNICORN */
