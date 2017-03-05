#ifndef __ENGINE_H
#define __ENIGNE_H

#include <stdbool.h>
#include "asrepl_types.h"
#include "config.h"

/* Return an engine */
extern engine_t *engine_init(engine_e type);

/* Execute the instructions */
extern void engine_execute(engine_t *eng, const ctx_t *ctx);

/* Dump registers */
extern void engine_dump_registers(engine_t *eng);
#endif /* __ENGINE_H */
