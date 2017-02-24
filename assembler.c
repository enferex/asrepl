#include <elf.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "asrepl.h"
#include "assembler.h"
#include "config.h"

/* Temporary file names for assembly generation */
#define ASM_OBJ   "./.asrepl.temp.o"
#define ASM_SRC   "./.asrepl.temp.s"
#define REDIR     "2>&1 1>/dev/null"
#define ASM_FLAGS "--64"
#define ASM_CMD   ASSEMBLER " " ASM_SRC " " ASM_FLAGS " -o " ASM_OBJ " " REDIR

#ifdef HAVE_LIBKEYSTONE
#include <keystone/keystone.h>
#define ARCH KS_ARCH_X86
#define MODE KS_MODE_64
#endif /* HAVE_LIBKEYSTONE */

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

        if (!(ctx->text = malloc(SHDR(shdr,sh_size))))
          ERF("Error allocating data from .text");

        /* Read in .text contents */
        fseek(fp, SHDR(shdr,sh_offset), SEEK_SET);
        if (fread(ctx->text, 1, SHDR(shdr,sh_size), fp) != SHDR(shdr,sh_size))
          ERF("Error reading section contents");
        ctx->length = SHDR(shdr,sh_size);
    }

    return found;
}

/* Returns 'true' on success and 'false' on error */
static _Bool gnu_assemble(assembler_h handle, const char *line, ctx_t *ctx)
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
static _Bool keystone_init(assembler_h *handle)
{
    ks_engine *ks;
    ks_err err;

    err = ks_open(ARCH,MODE,&ks);
    if(err != KS_ERR_OK)
      return false;

    if (!handle)
      return false;

    *handle = (assembler_h *)ks;
    return true;
}
#endif /* HAVE_LIBKEYSTONE */

#ifdef HAVE_LIBKEYSTONE
static _Bool keystone_shutdown(assembler_h handle)
{
    ks_engine *ks = (ks_engine *)handle;

    if (!ks)
      return false;

    ks = (ks_engine *)handle;
    ks_close(ks);
    return true;
}

#endif /* HAVE_LIBKEYSTONE */

#ifdef HAVE_LIBKEYSTONE
static _Bool keystone_assemble(
    assembler_h  handle,
    const char  *line,
    ctx_t       *ctx)
{
    size_t count, size;
    unsigned char *encode;
    ks_engine *ks = (ks_engine *)handle;

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

/* Always true predicates */
static _Bool yes_init(assembler_h     *unused) { return true; }
static _Bool yes_shutdown(assembler_h  unused) { return true; }

/* Array of all assemblers that we support */
static const assembler_t assemblers[] =
{
    [ASSEMBLER_GNU_AS_X8664] = {"--64", yes_init, yes_shutdown, gnu_assemble},

#ifdef HAVE_LIBKEYSTONE
    [ASSEMBLER_KEYSTONE] = {NULL, keystone_init,
                            keystone_shutdown, keystone_assemble},
#endif
};

const assembler_t *assembler_find(assembler_e type)
{
    if (type == ASSEMBLER_INVALID || type >= ASSEMBLER_MAX)
      return NULL;
    return &assemblers[type];
}
