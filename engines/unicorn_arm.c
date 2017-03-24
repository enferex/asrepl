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

#include "common.h"
#include "unicorn.h"
#include "../asrepl_types.h"

static void unicorn_arm_read_registers(engine_t *eng)
{
#define R(_eng, _reg) (&(REGS_ARM(_eng)._reg))
    engine_h handle = eng->handle;

    uc_reg_read(handle, UC_ARM_REG_CPSR, R(eng, cpsr));
	uc_reg_read(handle, UC_ARM_REG_PC,   R(eng, pc));
	uc_reg_read(handle, UC_ARM_REG_SP,   R(eng, sp));
	uc_reg_read(handle, UC_ARM_REG_LR,   R(eng, lr));
	uc_reg_read(handle, UC_ARM_REG_R0,   R(eng, r0));
	uc_reg_read(handle, UC_ARM_REG_R1,   R(eng, r1));
	uc_reg_read(handle, UC_ARM_REG_R2,   R(eng, r2));
	uc_reg_read(handle, UC_ARM_REG_R3,   R(eng, r3));
	uc_reg_read(handle, UC_ARM_REG_R4,   R(eng, r4));
	uc_reg_read(handle, UC_ARM_REG_R5,   R(eng, r5));
	uc_reg_read(handle, UC_ARM_REG_R6,   R(eng, r6));
	uc_reg_read(handle, UC_ARM_REG_R7,   R(eng, r7));
	uc_reg_read(handle, UC_ARM_REG_R8,   R(eng, r8));
	uc_reg_read(handle, UC_ARM_REG_R9,   R(eng, r9));
	uc_reg_read(handle, UC_ARM_REG_R10,  R(eng, r10));
	uc_reg_read(handle, UC_ARM_REG_R11,  R(eng, r11));
	uc_reg_read(handle, UC_ARM_REG_R12,  R(eng, r12));
}

/*
 * REGISTRATION
 */
const engine_desc_t *unicorn_arm_registration(void)
{
    static const engine_desc_t desc = {
        .type           = ENGINE_UNICORN_ARM,
        .init           = unicorn_init,
        .execute        = unicorn_execute,
        .shutdown       = unicorn_shutdown,
        .read_registers = unicorn_arm_read_registers,
        .dump_registers = common_arm_dump_registers
    };

    return &desc;
}

#endif /* HAVE_LIBUNICORN */
