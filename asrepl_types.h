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
    uint8_t *text;
    size_t   length; /* Bytes of .text */
} ctx_t;

typedef struct _ctx_list_t
{
    ctx_t              *ctx;
    struct _ctx_list_t *next;
} ctx_list_t;

/* Macros are just named lists of contexts (assembled instructions) */
typedef struct _macro_t
{
    const char       *name; /* Set via /def */
    const ctx_list_t *ctxs;
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


/* State object, one for each instance of asreplt... probably only ever one. */
typedef struct _asrepl_t
{
    assembler_t *assembler;
    macro_t     *macros;
    pid_t        engine_pid;
} asrepl_t;

#endif /* __ASREPL_TYPES_H */
