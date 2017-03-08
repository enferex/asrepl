#ifndef __ENGINE_H
#define __ENIGNE_H

#include <stdbool.h>
#include "asrepl_types.h"
#include "config.h"

/* Return an engine */
extern engine_t *engine_init(asrepl_t *asr, engine_e type);

/* Feed the engine with new machine code, returning 'true' on success and 'false' otherwise. */
//extern _Bool engine_update(engine_t *eng, const char *instructions, size_t length);

/* Execute the instructions */
extern void engine_execute(engine_t *eng, const ctx_t *ctx);

/* Dump registers */
extern void engine_dump_registers(asrepl_t *asr);
extern void unicorn_dump_registers_x86_64(engine_t *eng);
extern void unicorn_dump_registers_x86_32(engine_t *eng);
extern void unicorn_dump_registers_arm(engine_t *eng);
#endif /* __ENGINE_H */
