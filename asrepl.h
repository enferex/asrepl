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
#ifndef __ASREPL_H
#define __ASREPL_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/user.h>
#include "asrepl_types.h"
#include "config.h"

#define NAME       "asrepl"
#define MAJOR      0
#define MINOR      1
#define YEAR       2017
#define TAG        "asm"
#if defined(HAVE_LIBUNICORN) && defined(HAVE_LIBKEYSTONE)
#define MULTI_ARCH
#endif

/* Maximum length of an accepted ASM statement (instruction)...
 * 128 seems way large, but for now that's what we're capping at.
 */
#define MAX_ASM_LINE 128

/* Prompt goodies */
#define MAX_PROMPT_LENGTH 32
#define PROMPTC           ">"
#define DEFAULT_PROMPT    TAG PROMPTC " "
#define ERROR_PROMPT      TAG " error" PROMPTC " "

/* When querying a macro, the prefix must be used <prefix><macroname> */
#define MACRO_PREFIX "@"

#define PR(_msg, ...)\
    fprintf(stdout, TAG PROMPTC _msg "\n", ##__VA_ARGS__)

#define PRINT(_msg, ...)\
    fprintf(stdout, _msg "\n", ##__VA_ARGS__)

#define ERR(_msg, ...) \
    fprintf(stderr, ERROR_PROMPT _msg  "\n", ##__VA_ARGS__)

#define ERF(_msg, ...)                                                       \
    do {                                                                     \
        fprintf(stderr, ERROR_PROMPT _msg  "\n", ##__VA_ARGS__); \
        exit(EXIT_FAILURE);                                                  \
    } while (0)

/* Ptrace operates on word size thingies */
typedef unsigned long word_t;

/* Initialize asrepl: Sets up the assembler and execution engine */
extern asrepl_t *asrepl_init(isa_e isa_type, assembler_e type, engine_e engine);
extern void asrepl_version(void);

/* Utilities */
extern char *prompt;
extern void asrepl_update_prompt(const char *new_prompt);
extern void asrepl_version(void);

/* Get/Print register values to stdout */
extern void asrepl_read_registers(asrepl_t *asr);
extern void asrepl_dump_registers(asrepl_t *asr);

/* Return new context to represent a new blob of machine instructions. */
extern ctx_t *asrepl_new_ctx(const char *asm_line);
extern void asrepl_delete_ctx(ctx_t *ctx);

/* Assemble the line into machine instructions. 'ctx' will contain
 * the newly assembled machine instructions upon success.
 *
 * Returns 'true' on success and 'false' otherwise.
 */
extern _Bool asrepl_assemble(
    asrepl_t   *asr,
    const char *line,
    ctx_t      *ctx);

/* Execute a context.  A context is just machine instructions. */
extern void asrepl_execute(asrepl_t *asr, const ctx_t *ctx);

/* Routines for macros (only one macro built at a time) */
extern void     asrepl_macro_begin(asrepl_t *asr, const char *name);
extern void     asrepl_macro_end(asrepl_t *asr);
extern void     asrepl_macro_add_ctx(asrepl_t *asr, ctx_t *ctx);
extern void     asrepl_macro_execute(asrepl_t *asr, const char *name);
extern macro_t *asrepl_macro_find(asrepl_t *asr, const char *name);

#endif /* __ASREPL_H */
