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
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include "asrepl.h"
#include "assembler.h"

#define REG64(_regs, _reg) \
    printf("%s\t 0x%llx\n", #_reg, (_regs)->_reg)

asrepl_t *asrepl_init(assembler_e assembler_type)
{
    asrepl_t *asr = calloc(1, sizeof(asrepl_t));

    if (!asr)
      ERF("Error allocating memory for the asrepl handle.");

    /* Choose and initialize the assembler */
    if (!(asr->assembler = assembler_init(assembler_type)))
      ERF("Error locating an assembler to use.");

    return asr;
}

ctx_t *asrepl_new_ctx(const char *asm_line)
{
    ctx_t *ctx;
    const size_t len = strnlen(asm_line, MAX_ASM_LINE);

    if (len == 0 || len == MAX_ASM_LINE) {
        ERR("Invalid asm statement or command.");
        return NULL;
    }

   if (!(ctx = calloc(1, sizeof(ctx_t))))
     return NULL;

   if (!(ctx->asm_line = strdup(asm_line)))
     return NULL;

   return ctx;
}

void asrepl_delete_ctx(ctx_t *ctx)
{
    if (!ctx)
      return;

    free(ctx->text);
}

void asrepl_version(void)
{
    printf("%s v%d.%d, (c)%d\n", NAME, MAJOR, MINOR, YEAR);
}

void asrepl_get_registers(pid_t pid, struct user_regs_struct *gpregs)
{
    memset(gpregs, 0, sizeof(*gpregs));
    ptrace(PTRACE_GETREGS, pid, NULL, gpregs);
}

uintptr_t asrepl_get_pc(pid_t pid)
{
    struct user_regs_struct gpregs;
    asrepl_get_registers(pid, &gpregs);
    return gpregs.rip;
}

void asrepl_dump_registers(pid_t pid)
{
    struct user_regs_struct regs;

    asrepl_get_registers(pid, &regs);

    REG64(&regs, eflags);
    REG64(&regs, rip);
    REG64(&regs, cs);
    REG64(&regs, ds);
    REG64(&regs, es);
    REG64(&regs, fs);
    REG64(&regs, gs);
    REG64(&regs, ss);
    REG64(&regs, rbp);
    REG64(&regs, rsp);
    REG64(&regs, rax);
    REG64(&regs, rbx);
    REG64(&regs, rcx);
    REG64(&regs, rdx);
    REG64(&regs, rdi);
    REG64(&regs, rsi);
    REG64(&regs, r8);
    REG64(&regs, r9);
    REG64(&regs, r10);
    REG64(&regs, r11);
    REG64(&regs, r12);
    REG64(&regs, r13);
    REG64(&regs, r14);
    REG64(&regs, r15);
    REG64(&regs, fs_base);
    REG64(&regs, gs_base);
/*    REG64(&regs, orig_rax); */
}

/* Call the assembler to assemble this */
_Bool asrepl_assemble(asrepl_t *asr, const char *line, ctx_t *ctx)
{
    assert(asr);
    return assembler_assemble(asr->assembler, line, ctx);
}

static macro_t *macro_new(const char *name)
{
    macro_t *macro;

    if (strnlen(name, MAX_MACRO_NAME) >= MAX_MACRO_NAME) {
        ERR("Macro name is too long.");
        return NULL;
    }

    if (!(macro = calloc(1, sizeof(macro_t))))
      ERF("Error allocating memory to store a macro.");

    if (!(macro->name = strdup(name)))
      ERF("Error allocting memory to store the macro name.");

    return macro;
}

static void macro_delete(macro_t *macro)
{
    macro_t *m = macro;
    while (m) {
        ctx_t *c = m->ctxs;
        while (c) {
            ctx_t *cnext = c->next;
            asrepl_delete_ctx(c);
            c = cnext;
        }
        macro_t *mnext = m->next;
        free(m->name);
        free(m);
        m = mnext;
    }
}

/* TODO: Hash */
macro_t *asrepl_macro_find(asrepl_t *asr, const char *name)
{
    for (macro_t *macro=asr->macros; macro; macro=macro->next)
      if (strncmp(macro->name, name, MAX_MACRO_NAME) == 0)
        return macro;
    return NULL;
}

/* This is and should be called by a context that has already verified 'name' is
 * not larger than MAX_MACRO_NAME.
 */
static void trim_name(const char *name, char *result)
{
    size_t len = strlen(name);

    /* Trim leading whitespace */
    while (name[0] && isspace(name[0]))
      ++name;
    if (name[0] == '\0') {
        ERR("Invalid macro name.");
        return;
    }

    /* Copy the original name (now without leading whitespace) to what the
     * result will be (for mutation) */
    memcpy(result, name, len);
    result[len] = '\0';
    
    /* Trim trailing whitespace */
    for (int i=len-1; i>0; --i)
      if (isspace(result[i]))
        result[i] = '\0';
      else
        break;
}

/* Create/Terminate/Populate a macro.
 * There is only one macro being built at a time, so add/terminate
 * operate on that.
 */
void asrepl_macro_begin(asrepl_t *asr, const char *name)
{
    macro_t *macro;
    char mname[MAX_MACRO_NAME + 1];

    assert(asr);

    if (strnlen(name, MAX_MACRO_NAME) >= MAX_MACRO_NAME) {
        ERR("Macro name is too long... be concise please.");
        return;
    }

    /* Put name into a mutable buffer */
    trim_name(name, mname);
    if (mname[0] == '\0') {
        ERR("Invalid macro name.");
        return;
    }

    /* If macro already exists, clean it up and overwrite it. */
    if ((macro = asrepl_macro_find(asr, mname)))
      macro_delete(macro);
    else
      macro = macro_new(mname);

    if (!macro)
      ERF("Error creating a macro.");

    macro->next = macro;
    asr->macros = macro;
    asr->mode = MODE_MACRO;
}

void asrepl_macro_end(asrepl_t *asr)
{
    assert(asr);
    asr->mode = MODE_NORMAL;
}

void asrepl_macro_add_ctx(asrepl_t *asr, ctx_t *ctx)
{
    assert(asr && ctx && asr->active_macro);
    if (!asr->active_macro->tail) {
        asr->active_macro->ctxs = ctx;
        asr->active_macro->tail = ctx;
    }
    else {
        asr->active_macro->tail->next = ctx;
        asr->active_macro->tail = ctx;
    }
}

void asrepl_macro_execute(asrepl_t *asr, const char *name)
{
    ctx_t *ctx;
    macro_t *macro;
    char trimmed[MAX_MACRO_NAME + 1];

    trim_name(name, trimmed);

    if (!(macro = asrepl_macro_find(asr, trimmed))) {
        ERR("Could not locate macro: %s", trimmed);
        return;
    }

    /* Execute each context in the macro */
    for (ctx=macro->ctxs; ctx; ctx=ctx->next)
      asrepl_execute(asrepl, ctx);
}
