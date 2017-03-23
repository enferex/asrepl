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
#include <elf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "asrepl.h"
#include "assembler.h"
#include "config.h"

/* Temporary file names for assembly generation */
#define ASM_OBJ   "./.asrepl.temp.o"
#define ASM_SRC   "./.asrepl.temp.s"
#define REDIR     "2>&1 1>/dev/null"
#define ASM_CMD   ASSEMBLER " " ASM_SRC " -o " ASM_OBJ " " REDIR

#ifdef HAVE_LIBKEYSTONE
#include <keystone/keystone.h>
#endif /* HAVE_LIBKEYSTONE */

/* Size agnostic ELF section header */
typedef struct _shdr_t
{
    _Bool is_64bit;
    union {
        Elf64_Shdr ver64;
        Elf32_Shdr ver32;
    } u;
} shdr_t;

#define SHDR(_shdr, _field) \
    ((_shdr).is_64bit ? (_shdr).u.ver64._field : (_shdr).u.ver32._field)

/* Assembler description. Static data for each assembler supported. */
typedef struct _assembler_desc_t
{
    /* True: success, False: failure */
    _Bool (*init)(asrepl_t *asr, assembler_t *as); /* Initialize assembler */
    _Bool (*shutdown)(assembler_t *as); /* Stop and cleanup     */

    /* 'line' is the user-supplied assembly string. */
    _Bool (*assemble)(assembler_t *as, const char *line, ctx_t *ctx);
} assembler_desc_t;

/* Only to be called from assemble(), where
 * the str is to be at most sizeof(errbuf) and null terminated.
 */
static char *trim_newline(char *str)
{
    size_t len = strlen(str);
    if (len-1 > 0 && str[len-1] == '\n')
      str[len-1] = '\0';
    return str;
}

/* Returns 'true' on success, 'false' if the .text section
 * cannot be found.
 */
static _Bool read_elf_text_section(const char *obj_name, ctx_t *ctx)
{
    FILE *fp;
    size_t shdr_size;
    _Bool found;
    shdr_t shdr = {0};
    Elf64_Ehdr hdr;

    if (!(fp = fopen(obj_name, "r")))
      return false;

    /* Get the ELF header */
    if (fread((void *)&hdr, 1, sizeof(hdr), fp) != sizeof(hdr))
      ERF("Error reading header from %s", obj_name);

    if (memcmp(hdr.e_ident, ELFMAG, SELFMAG) != 0)
      ERF("Error: Invalid ELF file: %s", obj_name);

    fseek(fp, hdr.e_shoff, SEEK_SET);
    if (hdr.e_ident[EI_CLASS] == ELFCLASS64) {
        shdr_size = sizeof(Elf64_Shdr);
        shdr.is_64bit = true;
    }
    else if (hdr.e_ident[EI_CLASS] == ELFCLASS32)
      shdr_size = sizeof(Elf32_Shdr);
    else
      ERF("Invalid binary, expected 32 or 64 bit");

    /* For each section: Look for .text only */
    found = false;
    while (fread((void *)&shdr.u.ver64, 1, shdr_size, fp) == shdr_size) {
        if ((SHDR(shdr,sh_type)   != SHT_PROGBITS) ||
             (SHDR(shdr,sh_flags) != (SHF_ALLOC | SHF_EXECINSTR)))
          continue;
        found = true;
        break;
    }

    if (found) {
        /* Hopefully .text */
        if (!(ctx->text = malloc(SHDR(shdr,sh_size))))
          ERF("Error allocating room to store the binary's read-only data");

        /* Read in .text contents */
        fseek(fp, SHDR(shdr,sh_offset), SEEK_SET);
        if (fread(ctx->text, 1, SHDR(shdr,sh_size), fp) != SHDR(shdr,sh_size))
          ERF("Error reading section contents");
        ctx->length = SHDR(shdr,sh_size);
    }

    return found;
}

/* Returns 'true' on success and 'false' on error */
static _Bool gnu_assemble(assembler_t *as, const char *line, ctx_t *ctx)
{
    _Bool ret;
    FILE *fp;
    char errbuf[512];

    /* If error reading file then exit immediately. */
    if (!(fp = fopen(ASM_SRC, "w")))
      ERF("Error reading temporary asm file: %s", ASM_SRC);

    /* Write line to a new asm file */
    ret = (fprintf(fp, "%s\n", line) >= 0);
    fclose(fp);
    if (ret == false) {
        ERF("Error writing assembly to temp assembly file: %s, "
            "check permissions.", ASM_SRC);
    }

    /* Assemble */
    fp = popen(ASM_CMD, "r");

    /* If popen error, gracefully return */
    if (!fp)
      return true;

    /* Capture any errors: bound this by 10 iterations,
     * that should be enough to report an error of sizeof(errbuf)*10.
     */
    for (int i=0; i<10; ++i) {
        char *msg = fgets(errbuf, sizeof(errbuf), fp);
        if (msg)
          ERR("%s", trim_newline(errbuf));
        if (!msg || feof(fp) || ferror(fp))
          break;
    }

    pclose(fp);

    /* We might have generated bad assembly.
     * 1) The user should get the error output from the assembler.
     * 2) If there was an error, then the next call will fail.
     *    Just ignore that error, and return false.
     */
    return read_elf_text_section(ASM_OBJ, ctx);
}

#ifdef HAVE_LIBKEYSTONE
/* ISA is chosen via (-a) command line read from main.c
 *
 * XXX If this is updated, also update engines/unicorn.c
 */
static void keystone_set_config(assembler_t *as, isa_e isa)
{
    switch (isa) {
    case ISA_ARM:
        as->march = KS_ARCH_ARM;
        as->mmode = KS_MODE_ARM;
        break;

    case ISA_ARM64:
        as->march = KS_ARCH_ARM64;
        as->mmode = KS_MODE_ARM;
        break;

    /* x86 */
    case ISA_X8632:
        as->march = KS_ARCH_X86;
        as->mmode = KS_MODE_32;
        break;

    /* x86-64 */
    case ISA_X8664:
        as->march = KS_ARCH_X86;
        as->mmode = KS_MODE_64;
        break;

    case ISA_MIPS32:
        as->march = KS_ARCH_MIPS;
        as->mmode = KS_MODE_MIPS32;
        break;

    default:
         ERF("Invalid arch (-a) specified.");
    }
}
#endif /* HAVE_LIBKEYSTONE */

#ifdef HAVE_LIBKEYSTONE
static _Bool keystone_init(asrepl_t *asr, assembler_t *as)
{
    ks_engine *ks;
    ks_err err;

    keystone_set_config(as, asr->isa);

    err = ks_open(as->march, as->mmode, &ks);
    if (err != KS_ERR_OK)
      return false;

    if (as->handle)
      return false;

    as->handle = (assembler_h)ks;
    return true;
}
#endif /* HAVE_LIBKEYSTONE */

#ifdef HAVE_LIBKEYSTONE
static _Bool keystone_shutdown(assembler_t *as)
{
    ks_engine *ks = (ks_engine *)as->handle;

    if (!ks)
      return false;

    ks = (ks_engine *)as->handle;
    ks_close(ks);
    return true;
}

#endif /* HAVE_LIBKEYSTONE */

#ifdef HAVE_LIBKEYSTONE
static _Bool keystone_assemble(
    assembler_t *as,
    const char  *line,
    ctx_t       *ctx)
{
    size_t count, size;
    unsigned char *encode;
    ks_engine *ks = (ks_engine *)as->handle;

    if (!ks)
      ERF("Invalid Keystone handle.");

    if (ks_asm(ks, line, 0, &encode, &size, &count) != KS_ERR_OK) {
        ERR("Invalid assembly.");
        return false;
    }

    /* Copy the bytes into the context */
    if (!(ctx->text = malloc(size)))
      ERF("Error allocating data for .text.");

    for (size_t i=0; i<size; ++i)
      ctx->text[i] = encode[i];

    ctx->length = size;
    ks_free(encode);
    return true;
}
#endif /* HAVE_LIBKEYSTONE */

/* Always true predicates (for convenience) */
static _Bool yes_init(asrepl_t *asr, assembler_t *unused) { return true; }
static _Bool yes_shutdown(assembler_t *unused) { return true; }

/* Array of all assemblers that we support */
static const assembler_desc_t assemblers[] =
{
    [ASSEMBLER_GNU_AS_X8664] = {yes_init, yes_shutdown, gnu_assemble},
#ifdef HAVE_LIBKEYSTONE
    [ASSEMBLER_KEYSTONE] = {keystone_init,keystone_shutdown,keystone_assemble},
#endif
};

assembler_t *assembler_init(asrepl_t *asr, assembler_e type)
{
    assembler_t *as = calloc(1, sizeof(assembler_t));
    if (!as)
      ERF("Could not allocate enough memory to represent an assembler.");

    /* Find the description */
    if (type == ASSEMBLER_INVALID || type >= ASSEMBLER_MAX)
      ERF("Invalid assembler type: %d", (int)type);

    as->type = type;
    as->desc = &assemblers[type];
    
    /* Initialize the assembler */
    if (as->desc->init(asr,as) == false)
      ERF("Error initializing assembler.");

    return as;
}

_Bool assembler_assemble(assembler_t *as, const char *line, ctx_t *ctx)
{
    assert(as && as->desc);
    return as->desc->assemble(as, line, ctx);
}
