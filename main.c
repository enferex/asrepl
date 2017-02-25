/*******************************************************************************
 * BSD 3-Clause License
 *
 * Copyright (c) 2017, Matt Davis (enferex) https://github.com/enferex
 * See "CONTRIBUTORS" file for other contributions since the initial release.
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
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/ptrace.h>
#include "asrepl.h"
#include "asrepl_commands.h"
#include "assembler.h"
#include "config.h"

/* Returns 'true' on success and 'false' otherwise. */
static _Bool init_engine(asrepl_t *asr)
{
    assert(asr);
    const pid_t pid = fork();
    
    asr->engine_pid = pid;

    if (pid > 0) {
        /* Parent with child's pid.  Wait for the child. */
        int status;
        const pid_t ret = waitpid(pid, &status, __WALL);
        return (pid == ret && WIFSTOPPED(status));

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

    return false; /* Error */
}

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

static void usage(const char *execname)
{
    printf("Usage: %s [-h] [-v] "
#ifdef HAVE_LIBKEYSTONE
           "[-k]"
#endif
           "\n"
           " -h: This help message.\n"
           " -v: Version information.\n"
#ifdef HAVE_LIBKEYSTONE
           " -k: Use the Keystone assembler.\n"
#endif
           , execname);

}

int main(int argc, char **argv)
{
    int opt;
    char *line;
    assembler_e assembler_type;
    asrepl_t *asr;

    /* Setup defaults for command line args */
    assembler_type = ASSEMBLER_GNU_AS_X8664;
    while ((opt = getopt(argc, argv, "hkv")) != -1) {
    switch (opt) {
        case 'h': usage(argv[0]);   exit(EXIT_SUCCESS);
        case 'v': asrepl_version(); exit(EXIT_SUCCESS);
#ifdef HAVE_LIBKEYSTONE
        case 'k': assembler_type = ASSEMBLER_KEYSTONE; break;
#endif
        default: break;
        }
    }

#ifndef __x86_64__
    ERF("Sorry, %s only operates on x86-64 architectures.", NAME);
#endif
    /* Create a state object for this instance of asrepl */
    if (!(asr = asrepl_init(assembler_type)))
      ERF("Error initializing a new asrepl instance.");

    /* Initialize the engine */
    if (init_engine(asr) == false)
      ERF("Error starting engine process, terminating now.");

    /* Engine has started, now query user for asm code */
    while ((line = readline(PROMPT))) {
        _Bool asm_result;
        ctx_t *ctx;

        /* Commands are optional, any commands (success or fail) should
         * not terminate, go back to readline, and get more data.
         */
        const cmd_status_e cmd_status = asrepl_cmd_process(asr, line);
        if (cmd_status == CMD_ERROR || cmd_status == CMD_HANDLED)
          continue;

        /* Do the real work */
        if (!(ctx = asrepl_new_ctx()))
          ERF("Error allocating a new context.");
        asm_result = asrepl_assemble(asr, line, ctx);
        
        /* The assembly was generated correctly, execute it. */
        if (asm_result == true)
          execute(asr->engine_pid, ctx);

        cleanup(ctx);
        add_history(line);
    }

    return 0;
}
