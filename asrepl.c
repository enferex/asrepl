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
#include <sys/wait.h>
#include "asrepl.h"
#include "assembler.h"
#include "engine.h"

#ifdef HAVE_LIBUNICORN
#include <unicorn/unicorn.h>
#endif

asrepl_t *asrepl_init(char *marchval, assembler_e assembler_type, engine_e engine_type)
{
    asrepl_t *asr = calloc(1, sizeof(asrepl_t));

    if (!asr)
      ERF("Error allocating memory for the asrepl handle.");

#ifdef HAVE_LIBUNICORN
    // parse out marchval and assign to asr struct if Unicorn toggled on
    if(engine_type == ENGINE_UNICORN){
    	/* ARM */
    	if(strcasecmp(marchval,"arm") == 0 ||strcasecmp(marchval,"armel") == 0)
    	{
		    asr->march = UC_ARCH_ARM;
		    asr->mmode = UC_MODE_ARM || UC_MODE_LITTLE_ENDIAN;
	}

	if(strcasecmp(marchval,"armhf") == 0)
	{
		    asr->march = UC_ARCH_ARM;
		    asr->mmode = UC_MODE_ARM || UC_MODE_BIG_ENDIAN;
	}

    	if(strcasecmp(marchval,"arm64") == 0 ||strcasecmp(marchval,"aarch64") == 0)
    	{
		    asr->march = UC_ARCH_ARM64;
		    asr->mmode = UC_MODE_ARM;
    	}

    	/* x86 */
    	if(strcasecmp(marchval,"x86") == 0)
    	{
		    asr->march = UC_ARCH_X86;
		    asr->mmode = UC_MODE_32;
    	}

    	/* x86-64 */
    	if(strcasecmp(marchval,"x86-64") == 0)
    	{
		    asr->march = UC_ARCH_X86;
		    asr->mmode = UC_MODE_64;
    	}

	/* mips */
	if(strcasecmp(marchval,"mips") == 0 || strcasecmp(marchval,"mips32") == 0)
	{
		asr->march = UC_ARCH_MIPS;
		asr->mmode = UC_MODE_MIPS32;
	}
    }
#endif

    /* Choose and initialize the assembler */
    if (!(asr->assembler = assembler_init(asr,assembler_type)))
      ERF("Error locating an assembler to use.");

    if (!(asr->engine = engine_init(asr,engine_type)))
      ERF("Error locating an engine to use.");

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

void asrepl_dump_registers(asrepl_t *asr)
{
    assert(asr);
    return engine_dump_registers(asr);
}

/* Call the assembler to assemble this */
_Bool asrepl_assemble(asrepl_t *asr, const char *line, ctx_t *ctx)
{
    assert(asr);
    return assembler_assemble(asr->assembler, line, ctx);
}

/* Execute some ctx data. */
void asrepl_execute(asrepl_t *asr, const ctx_t *ctx)
{
	assert(asr);

	if (ctx->text == NULL)
		return;

	// need to engine_update & engine_execute
	/*if (!engine_update(asr->engine, ctx->text, ctx->length)){
		ERR("Failed to update engine execution context");
		return;
	}*/

	return engine_execute(asr->engine, ctx);
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

    if (asr->active_macro) {
        ERR("/end previous macro before defining a new one.");
        return;
    }

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

    if (!(macro = macro_new(mname)))
      ERF("Error creating a macro.");

    macro->next = asr->macros;
    asr->macros = macro;
    asr->mode = MODE_MACRO;
    asr->active_macro = macro;
}

void asrepl_macro_end(asrepl_t *asr)
{
    assert(asr);
    asr->active_macro = NULL;
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
        ERR("Could not locate macro: %s%s", MACRO_PREFIX, trimmed);
        return;
    }

    /* Execute each context in the macro */
    for (ctx=macro->ctxs; ctx; ctx=ctx->next)
      asrepl_execute(asr, ctx);
}
