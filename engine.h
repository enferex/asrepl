#ifndef __ENGINE_H
#define __ENIGNE_H

#include <stdbool.h>
#include "asrepl_types.h"
#include "config.h"

/* Return an engine */
extern engine_t *engine_init(engine_e type);

/* Feed the engine with new machine code, returning 'true' on success and 'false' otherwise. */
extern _Bool engine_update(engine_t *eng, const char *instructions, size_t length);

/* Execute the instructions */
extern void engine_execute(engine_t *eng, size_t length, size_t count);
#endif /* __ENGINE_H */
