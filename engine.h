#ifndef __ENGINE_H
#define __ENIGNE_H

#include <stdbool.h>
#include "asrepl_types.h"
#include "config.h"

/* Return an engine */
extern engine_t *engine_init(engine_e type);

/* Execute the instructions */
extern void engine_execute(engine_t *eng, const ctx_t *ctx);

/* Read in registers from the engine */
extern void engine_read_registers(const engine_t *eng);

/* Dump registers */
extern void engine_dump_registers(const engine_t *eng);

#endif /* __ENGINE_H */
