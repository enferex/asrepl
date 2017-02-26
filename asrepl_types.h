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
#ifndef __ASREPL_TYPES_H
#define __ASREPL_TYPES_H

#include <stdint.h>
#include <sys/types.h>
#include "config.h"

/* The machine code */
typedef struct _context_t
{
    char              *asm_line; /* Allocation managed by readline  */
    uint8_t           *text;
    size_t             length;   /* Bytes of .text                  */
    struct _context_t *next;     /* A macro will have a list of ctx */
} ctx_t;

/* Macros are just named lists of contexts (assembled instructions) */
#define MAX_MACRO_NAME 64
typedef struct _macro_t
{
    char            *name;
    ctx_t           *ctxs;
    ctx_t           *tail; /* Quick access to last inserted item. */
    struct _macro_t *next;
} macro_t;

/* Assembler type */
typedef enum
{
    ASSEMBLER_INVALID = 0,
    ASSEMBLER_GNU_AS_X8664,
#ifdef HAVE_LIBKEYSTONE
    ASSEMBLER_KEYSTONE,
#endif
    ASSEMBLER_MAX
} assembler_e;

/* Handles are just opaque pointers and specific (or ignored) by the assembler
 * implementation.
 */
typedef void *assembler_h;

/* Assembler */
struct _assembler_desc_t;
typedef struct _assembler_t
{
    assembler_e type;

    /* Some assemblers have a handle (e.g., api/library based assemblers) */
    assembler_h handle;

    /* Description */
    const struct _assembler_desc_t *desc;
} assembler_t;

/* A mode defines the behavior of execution.  Macro mode
 * means that all user-input asm instructions are collected
 * and will/might be played back later.
 *
 * Macros are named see the command '/def' and '/end' in 
 * asrepl_commands.c.
 *
 * Macro:  Macro mode.
 * Normal: Not-macro mode.  The instructions are not collected.
 */
typedef enum _mode_e
{
    MODE_NORMAL = 0,
    MODE_MACRO
} mode_e;

/* State object, one for each instance of asreplt... probably only ever one. */
typedef struct _asrepl_t
{
    mode_e       mode;
    assembler_t *assembler;
    macro_t     *macros;
    macro_t     *active_macro; /* The macro in macros being used. */
    pid_t        engine_pid;
} asrepl_t;

#endif /* __ASREPL_TYPES_H */
