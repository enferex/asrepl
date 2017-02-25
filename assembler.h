#ifndef __ASSEMBLER_H
#define __ASSEMBLER_H

#include <stdbool.h>
#include "asrepl_types.h"
#include "config.h"

/* Return an assembler for 'type', or NULL on error. */
extern assembler_t *assembler_init(assembler_e type);

/* Return 'true' on success and 'false' otherwise. */
extern _Bool assembler_assemble(assembler_t *as, const char *line, ctx_t *ctx);

#endif /* __ASSEMBLER_H */
