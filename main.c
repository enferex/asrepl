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
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/ptrace.h>
#include "asrepl.h"
#include "asrepl_commands.h"

/* Temporary file names for assembly generation */
#define ASM_OBJ   "./.asrepl.temp.o"
#define ASM_SRC   "./.asrepl.temp.s"
#define REDIR     "2>&1 1>/dev/null"
#define ASM_FLAGS "--64"
#define ASM_CMD   ASSEMBLER " " ASM_SRC " " ASM_FLAGS " -o " ASM_OBJ " " REDIR

// Adding for keystone-engine
#include <keystone/keystone.h>
#define ARCH KS_ARCH_X86
#define MODE KS_MODE_64

/* Ptrace operates on word size thingies */
typedef unsigned long word_t;

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

typedef struct _context_t
{
    uint8_t *text;
    size_t   length; /* Bytes of .text */
} ctx_t;

static pid_t init_engine(void)
{
    const pid_t pid = fork();

    if (pid > 0) {
        /* Parent with child's pid.  Wait for the child. */
        int status;
        const pid_t ret = waitpid(pid, &status, __WALL);
        return (pid == ret && WIFSTOPPED(status)) ? pid : 0;
    }
    else if (pid == 0) {
        /* Child (tracee) */
        if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) == -1) {
            ERF("Error setting traceme in the child process: %s",
                strerror(errno));
        }

        /* Just a ton of nops for space */
        for ( ;; ) {
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");

            /* All instructions should be inserted here, since
             * this is where the pc will be in the tracee as the int3 below
             * will signal the tracer to start inserting instructions.
             */
            __asm__ __volatile__ ("int $3\n");

            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
        }
    }
    else
      ERR("Error fork()ing child process: %s", strerror(errno));

    return 0; /* Error */
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

static _Bool keyassemble(const char *line, ks_engine *ks, ctx_t *ctx)
{
	size_t count;
	unsigned char *encode;
	size_t size;

	if(ks_asm(ks, line, 0, &encode, &size, &count)!= KS_ERR_OK){
		ERR("Not a valid instruction!");
		return false;
	}

	// copy the bytes into the context
	if(!(ctx->text = malloc(size)))
		ERF("Error allocating data on .text");

	size_t i;
	for(i = 0; i < size; i++){
		ctx->text[i] = encode[i];
	}
	ctx->length = size;
	ks_free(encode);
	return true;
}

/* Returns 'true' on success and 'false' on error */
static _Bool assemble(const char *line, ctx_t *ctx)
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

#if 0
static uintptr_t read_text(pid_t pid, uintptr_t addr)
{
    uintptr_t data;
    uintptr_t text = ptrace(PTRACE_PEEKTEXT, pid, addr, &data);
    return text;
}
#endif

static void execute(pid_t pid, const ctx_t *ctx)
{
    int i, status, n_words;
    pid_t ret;
    uint8_t *insns;
    uintptr_t orig_pc, pc;
    struct user_regs_struct regs;

    if (ctx->text == NULL)
      return; /* Non-fatal error */

    /* We will restore the pc after we single step and gather registers */
    orig_pc = asrepl_get_pc(pid);

    /* POKETEXT operates on word size units (round up) */
    pc = orig_pc;
    insns = ctx->text;
    n_words = (ctx->length / sizeof(word_t));
    if (ctx->length % sizeof(word_t))
      ++n_words;
    for (i=0; i<n_words; ++i) {
        word_t word = *(word_t *)insns;
        ptrace(PTRACE_POKETEXT, pid, (void *)pc, (void *)word);
        pc    += sizeof(word_t);
        insns += sizeof(word_t);
    }

    /* Now that data is loaded at the PC of the engine, single step one insn */
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    ret = waitpid(pid, &status, __WALL);
    if (ret != 0 && !WIFSTOPPED(status))
      ERF("Error waiting for engine to single step\n");

    /* Now that we have executed the instruction, restore the pc */
    asrepl_get_registers(pid, &regs);
    regs.rip = orig_pc;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}

static void cleanup(ctx_t *ctx)
{
    free(ctx->text);
    memset(ctx, 0, sizeof(ctx_t));
}

int main(void)
{
    char *line;
    pid_t engine;
    ctx_t ctx;

    /* Setup Keystone instance */
    ks_engine *ks;
    ks_err err;

    err = ks_open(ARCH,MODE,&ks);
    if(err != KS_ERR_OK){
	ERR("Failed on ks_open()");
	exit(EXIT_FAILURE);
    }
    /* Keystone is initialized */

#ifndef __x86_64__
    ERR("Sorry, %s only operates on x86-64 architectures.", NAME);
    exit(EXIT_FAILURE);
#endif

    if ((engine = init_engine()) == 0) {
        ERR("Error starting engine process, terminating now.");
        exit(EXIT_FAILURE);
    }

    /* Engine has started, now query user for asm code */
    while ((line = readline(PROMPT))) {

        /* Commands are optional, any commands (success or fail) should
         * not terminate, go back to readline, and get more data.
         */
        const cmd_status_e cmd_status = asrepl_cmd_process(line, engine);
        if (cmd_status == CMD_ERROR || cmd_status == CMD_HANDLED)
          continue;

        /* Do the real work */
        if (keyassemble(line, ks, &ctx)) {
            execute(engine, &ctx);
            cleanup(&ctx);
        }
        add_history(line);
    }

    ks_close(ks);	//close keystone instance
    return 0;
}
