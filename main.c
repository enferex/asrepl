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
#include <readline/readline.h>
#include <readline/history.h>
#include "asrepl.h"
#include "assembler.h"
#include "commands.h"
#include "engine.h"
#include "tui.h"
#include "config.h"
#ifdef HAVE_LIBUNICORN
#include "engines/unicorn.h"
#endif

static void usage(const char *execname)
{
    assert(execname);

    printf("Usage: %s [-h] [-v] "
#ifdef MULTI_ARCH
           "[-a ARCH]"
#endif
           "\n", execname);
    printf(" -h: This help message.\n"
           " -v: Version information.\n"
#ifdef MULTI_ARCH
           " -a ARCH: Architectures to emulate:( %s)\n"
           , isa_all_names()
#endif
           );
}

static char *read_line(asrepl_t *asr, const char *prompt)
{
    assert(asr);
#ifdef HAVE_LIBNCURSES
    if (asr->mode & MODE_TUI)
      return tui_readline(prompt);
    else
      return readline(prompt);
#else
    return readline(prompt);
#endif
}

/* Main loop of execution */
static void repl(asrepl_t *asr)
{
    char *line;

    assert(asr);

    /* Engine has started, now query user for asm code */
    asrepl_update_prompt(DEFAULT_PROMPT);
    while ((line = read_line(asr, prompt))) {
        _Bool asm_result;
        ctx_t *ctx;

        /* Commands are optional, any commands (success or fail) should
         * not terminate, go back to readline, and get more data.
         */
        const cmd_status_e cmd_status = asrepl_cmd_process(asr, line);
        if (cmd_status == CMD_ERROR || cmd_status == CMD_HANDLED) {
            free(line);
            continue;
        }

        /* Do the real work */
        if (!(ctx = asrepl_new_ctx(line))) {
            free(line);
            continue;
        }
        asm_result = asrepl_assemble(asr, line, ctx);
        
        /* The assembly was generated correctly, execute it.
         * If we are building a macro, do not execute while building it.
         */
        if (asm_result == true && asr->mode != MODE_MACRO)
          asrepl_execute(asr, ctx);

        /* If we are in macro mode, and assembled successful, keep the ctx */
        if (asr->mode == MODE_MACRO && asm_result == true)
          asrepl_macro_add_ctx(asr, ctx);
        else
          asrepl_delete_ctx(ctx);

        /* We only keep track of libreadline lines */
        if (asr->mode == MODE_TUI)
          free(line);
        else
          add_history(line);
    }
}

int main(int argc, char **argv)
{
    int           opt;
    isa_e        isa_type;
    assembler_e  assembler_type;
    engine_e     engine_type;
    asrepl_t    *asr;

    /* Setup defaults for command line args (default to x8664 native) */
    isa_type       = ISA_X8664;
    assembler_type = ASSEMBLER_GNU_AS_X8664;
    engine_type    = ENGINE_NATIVE_X8664;
    while ((opt = getopt(argc, argv, "a:hv")) != -1) {
    switch (opt) {
        case 'h': usage(argv[0]);   exit(EXIT_SUCCESS);
        case 'v': asrepl_version(); exit(EXIT_SUCCESS);
#ifdef MULTI_ARCH
        case 'a':
		  isa_type       = isa_from_string(optarg);
		  engine_type    = unicorn_engine_from_isa(isa_type);;
		  assembler_type = ASSEMBLER_KEYSTONE;
		  break;
#endif
        case '?':
        default:
            exit(EXIT_FAILURE);
            break;
        }
    }

#ifndef __x86_64__
    /* If 32bit and trying to run gnu as OR our native engine. */
    if (assembler_type == ASSEMBLER_GNU_AS_X8664 || 
        engine_type    == ENGINE_NATIVE) {
        ERF("Sorry, %s only operates on x86-64 architectures when "
            "using the default assembler and execution engine.", NAME);
    }
#endif
    
    if (isa_type == ISA_UNKNOWN)
      ERF("Invalid arch (-a), see '-h' for list of available "
          "architectures.");

    if (engine_type == ENGINE_NATIVE_X8664 && isa_type != ISA_X8664) 
      ERF("Native execution only permits x8664 assembly.\n"
          "Install Unicorn and Keystone for multi arch support.");

    /* Create a state object for this instance of asrepl */
    if (!(asr = asrepl_init(isa_type, assembler_type, engine_type)))
      ERF("Error initializing a new asrepl instance.");

    repl(asr);

    return 0;
}
