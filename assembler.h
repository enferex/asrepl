#ifndef __ASSEMBLER_H
#define __ASSEMBLER_H
#include <stdbool.h>
#include "config.h"

/* Some assemblers have a handle (e.g., api/library based assemblers) */
typedef void *assembler_h;

typedef enum
{
    ASSEMBLER_INVALID = 0,
    ASSEMBLER_GNU_AS_X8664,
#ifdef HAVE_LIBKEYSTONE
    ASSEMBLER_KEYSTONE,
#endif
    ASSEMBLER_MAX
} assembler_e;

/* Assembler representation */
typedef struct _assembler_t
{
    const char *flags;

    /* True: success, False: failure */
    _Bool (*init)(assembler_h *handle);    /* Initialize assembler       */
    _Bool (*shutdown)(assembler_h handle); /* Stop and cleanup assembler */

    /* 'line' is the user-supplied assembly string. */
    _Bool (*assemble)(assembler_h handle, const char *line, ctx_t *ctx);
} assembler_t;

/* Return an assembler for 'type', or NULL on error. */
extern const assembler_t *assembler_find(assembler_e type);

#endif /* __ASSEMBLER_H */
