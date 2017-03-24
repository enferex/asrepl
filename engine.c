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
#include "asrepl.h"
#include "asrepl_types.h"
#include "config.h"
#include "engines/registration.h"

static const engine_desc_t *get_desc(engine_e type)
{
    const int n_regs = sizeof(engine_registrations) /
                       sizeof(engine_registrations[0]);

    for (int i=0; i<n_regs; ++i) {
        const engine_desc_t *desc = engine_registrations[i]();
        if (desc && desc->type == type)
          return desc;
    }

    return NULL;
}

/* Ensure a complete desc */
static void sanity(const engine_t *eng, engine_e type)
{
    assert(eng);
    assert(eng->desc);
    assert(eng->desc->type == type);
    assert(eng->desc->init);
    assert(eng->desc->execute);
    assert(eng->desc->shutdown);
    assert(eng->desc->read_registers);
    assert(eng->desc->dump_registers);
}

engine_t *engine_init(asrepl_t *asr, engine_e type)
{
	engine_t *eng = calloc(1, sizeof(engine_t));
	if (!eng)
		ERF("Could not allocate enough memory to represent an engine.");

	eng->desc = get_desc(type);
    sanity(eng, type);

	/* Initialize the engine */
	if (eng->desc->init(asr, eng) == false)
      ERF("Error initializing the engine.");

	return eng;
}

void engine_execute(engine_t *eng, const ctx_t *ctx)
{
    assert(ctx && eng && eng->desc);
    return eng->desc->execute(eng, ctx);
}

void engine_read_registers(engine_t *eng)
{
    assert(eng && eng->desc);
    return eng->desc->read_registers(eng);
}

void engine_dump_registers(engine_t *eng)
{
    assert(eng && eng->desc);
    eng->desc->read_registers(eng);
    eng->desc->dump_registers(eng);
}
