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

#include "unicorn.h"
#include "common.h"
#include "../asrepl_types.h"

static void unicorn_mips32_read_registers(engine_t *eng)
{
#define R(_eng, _reg) (&(REGS_MIPS32(_eng)._reg))
    engine_h handle = eng;

	uc_reg_read(handle, UC_MIPS_REG_GP, &gp);
	uc_reg_read(handle, UC_MIPS_REG_SP, &sp);
	uc_reg_read(handle, UC_MIPS_REG_FP, &fp);
	uc_reg_read(eng, UC_MIPS_REG_RA, &ra);

	uc_reg_read(eng, UC_MIPS_REG_ZERO, &zero);
	uc_reg_read(eng, UC_MIPS_REG_AT, &at);
	uc_reg_read(eng, UC_MIPS_REG_V0, &v0);
	uc_reg_read(eng, UC_MIPS_REG_V1, &v1);

	uc_reg_read(eng, UC_MIPS_REG_A0, &a0);
	uc_reg_read(eng, UC_MIPS_REG_A1, &a1);
	uc_reg_read(eng, UC_MIPS_REG_A2, &a2);
	uc_reg_read(eng, UC_MIPS_REG_A3, &a3);

	uc_reg_read(eng, UC_MIPS_REG_T0, &t0);
	uc_reg_read(eng, UC_MIPS_REG_T1, &t1);
	uc_reg_read(eng, UC_MIPS_REG_T2, &t2);
	uc_reg_read(eng, UC_MIPS_REG_T3, &t3);
	uc_reg_read(eng, UC_MIPS_REG_T4, &t4);
	uc_reg_read(eng, UC_MIPS_REG_T5, &t5);
	uc_reg_read(eng, UC_MIPS_REG_T6, &t6);
	uc_reg_read(eng, UC_MIPS_REG_T7, &t7);
	uc_reg_read(eng, UC_MIPS_REG_T8, &t8);
	uc_reg_read(eng, UC_MIPS_REG_T9, &t9);

	uc_reg_read(eng, UC_MIPS_REG_S0, &s0);
	uc_reg_read(eng, UC_MIPS_REG_S1, &s1);
	uc_reg_read(eng, UC_MIPS_REG_S2, &s2);
	uc_reg_read(eng, UC_MIPS_REG_S3, &s3);
	uc_reg_read(eng, UC_MIPS_REG_S4, &s4);
	uc_reg_read(eng, UC_MIPS_REG_S5, &s5);
	uc_reg_read(eng, UC_MIPS_REG_S6, &s6);
	uc_reg_read(eng, UC_MIPS_REG_S7, &s7);

	uc_reg_read(eng, UC_MIPS_REG_K0, &k0);
	uc_reg_read(eng, UC_MIPS_REG_K1, &k1);
}

/*
 * REGISTRATION
 */
const engine_desc_t *unicorn_mips32_registration(void)
{
    static const engine_desc_t desc = {
        .type           = ENGINE_UNICORN_MIPS32,
        .init           = unicorn_init,
        .execute        = unicorn_execute,
        .shutdown       = unicorn_shutdown,
        .read_registers = unicorn_mips32_read_registers,
        .dump_registers = common_mips32_dump_registers
    };

    return &desc;
}
