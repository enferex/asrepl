#ifndef __ASSEMBLER_H
#define __ASSEMBLER_H
#include <stdbool.h>
#include "asrepl.h"
#include "config.h"

typedef enum
{
    ASSEMBLER_INVALID = 0,
    ASSEMBLER_GNU_AS_X8664,
#ifdef HAVE_LIBKEYSTONE
    ASSEMBLER_KEYSTONE,
#endif
    ASSEMBLER_MAX
} assembler_e;

/* Handle's are just opaque pointers and specific (or ignored) by the assembler
 * implementation.
 */
typedef void *assembler_h;

/* Assembler representation */
struct _assembler_desc_t;
typedef struct _assembler_t
{
    assembler_e type;

    /* Some assemblers have a handle (e.g., api/library based assemblers) */
    assembler_h handle;

    /* Description */
    const struct assembler_desc_t *desc;
} assembler_t;

/* Return an assembler for 'type', or NULL on error. */
extern assembler_t *assembler_init(assembler_e type);

#endif /* __ASSEMBLER_H */
