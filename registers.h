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
#ifndef __REGISTERS_H
#define __REGISTERS_H

#include <stdint.h>

/* Instruction Set Architecture tags */
typedef enum _isa_e
{
    ISA_X8664,
} isa_e;

/* Similar to sys/user.h */
typedef struct _x8664_regs_t
{
    /* These are tagged by ISA_X8664 */
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rbp, rsp, rdi, rsi;
    uint64_t cs, ds, es, fs, gs, ss;
    uint64_t rip, eflags;
} x8664_regs_t;

/* Mmmm fake algebraic data type */
typedef union _registers_t
{
    union {
        x8664_regs_t x8664;
    } u;

    isa_e tag; /* Which union variant is represented by 'u' */
} registers_u;

/* Accessors */
#define REGS_X8664(_eng) ((_eng)->registers.u.x8664)

#endif /* __REGISTERS_H */

