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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "asrepl.h"
#include "asrepl_commands.h"

/* REPL commands beginning with a leading '/' are considered prefix,
 * else they are not prefixed.  The reason for the two command types
 * is to increase command-lookup speed, while also eliminating any
 * potential asm instruction collisions.
 */
#define IS_NOT_PREFIXED(_str) ((_str)[0] != '/')

/* Utility */
#define ARRAY_LENGTH(_a) (sizeof((_a)) / sizeof((_a)[0]))

/* REPL Command */
typedef struct _repl_cmd_t {
    const char *command;
    const char *description;
    void        (*fn)(asrepl_t *asr, const struct _repl_cmd_t *, const void *);
    _Bool       hidden;
} repl_cmd_t;

/* REPL Command Callbacks */
#define DECL_CALLBACK(_name) \
    static void cmd_ ##_name (asrepl_t *a, const repl_cmd_t *c, const void *d)
DECL_CALLBACK(dump);
DECL_CALLBACK(exit);
DECL_CALLBACK(help);
DECL_CALLBACK(version);
DECL_CALLBACK(defmacro);
DECL_CALLBACK(endmacro);
DECL_CALLBACK(exemacro);

/* Commands defined */
static const repl_cmd_t nonprefixed_cmds[] = {
    {"$",  "Defined macro name (see /help).", cmd_exemacro, true},
    {"r",  "Dump registers.",                 cmd_dump,     true},
    {"q",  "Exit",                            cmd_exit,     true},
    {"x",  "Exit",                            cmd_exit,     true},
    {"?",  "This help message.",              cmd_help,     true}
};

/* Commands defined */
static const repl_cmd_t prefixed_cmds[] = {
    {"/regs",    "Dump registers.",             cmd_dump,     false},
    {"/reg",     "Dump registers.",             cmd_dump,     true},
    {"/def",     "Define a macro (see /help).", cmd_defmacro, false},
    {"/end",     "End a macro.",                cmd_endmacro, false},
    {"/help",    "This help message.",          cmd_help,     false},
    {"/h",       "This help message.",          cmd_help,     true},
    {"/wtf",     "This help message.",          cmd_help,     true},
    {"/exit",    "Exit",                        cmd_exit,     false},
    {"/quit",    "Exit",                        cmd_exit,     true},
    {"/ver",     "About/Version information",   cmd_version,  false},
    {"/version", "About/Version information",   cmd_version,  true},
    {"/about",   "About/Version information",   cmd_version,  true},
};

static void cmd_help(asrepl_t *asr, const repl_cmd_t *cmd, const void *unused)
{
    PRINT("Commands:");

    for (int i=0; i<ARRAY_LENGTH(nonprefixed_cmds); ++i)
      if (!nonprefixed_cmds[i].hidden)
        PRINT("%8s: %s",
              nonprefixed_cmds[i].command,
              nonprefixed_cmds[i].description);

    for (int i=0; i<ARRAY_LENGTH(prefixed_cmds); ++i)
      if (!prefixed_cmds[i].hidden)
        PRINT("%8s: %s",
              prefixed_cmds[i].command,
              prefixed_cmds[i].description);

    PRINT("\nAdditional Information:");
    PRINT("/def <name> ");
    PRINT("  Defines a macro named <name> which represents the list of ");
    PRINT("  assembly instructions following the /def macro. Each assembly");
    PRINT("  instruction must begin on its own line. The list is ");
    PRINT("  terminated once an /end command is issued.  Once defined, a ");
    PRINT("  macro can be executed as a command: @<name>");
    PRINT("  Example:");
    PRINT("    /def mymacro");
    PRINT("    mov $0x2a, %%rax");
    PRINT("    mov %%rax, %%rbp");
    PRINT("    /end");
    PRINT("  This macro can now be executed by issuing @mymacro in the REPL.");
}

static void cmd_exit(asrepl_t *asr, const repl_cmd_t *cmd, const void *none)
{
    exit(EXIT_SUCCESS);
}

static void cmd_version(asrepl_t *asr, const repl_cmd_t *cmd, const void *none)
{
    asrepl_version();
}

static void cmd_dump(asrepl_t *asr, const repl_cmd_t *cmd, const void *none)
{
    asrepl_dump_registers(asr->engine_pid);
}

static void cmd_defmacro(
    asrepl_t         *asr,
    const repl_cmd_t *cmd,
    const void       *line)
{
    const char *c = (const char *)line;

    /* Locate the command name, and advance past that */
    c = strstr(c, cmd->command);
    if (!c)
      return;
    c += strlen(cmd->command);
    asrepl_macro_begin(asr, line);
}

static void cmd_endmacro(
    asrepl_t         *asr,
    const repl_cmd_t *cmd,
    const void       *unused)
{
    asrepl_macro_end(asr);
}

static void cmd_exemacro(
    asrepl_t         *asr,
    const repl_cmd_t *cmd,
    const void       *line)
{
    /* Strip off the prefix, asrepl macros have no concept of a prefix. */
    asrepl_macro_execute(asr, (char *)line + 1);
}

cmd_status_e asrepl_cmd_process(asrepl_t *asrepl, const char *data)
{
    if (!data)
      return CMD_NOT_A_COMMAND;

    else if (IS_NOT_PREFIXED(data)) {
        for (int i=0; i<ARRAY_LENGTH(nonprefixed_cmds); ++i) {
            const repl_cmd_t *cmd = &nonprefixed_cmds[i];
            if (strncmp(data, cmd->command, strlen(cmd->command)) == 0) {
                nonprefixed_cmds[i].fn(asrepl, cmd, NULL);
                return CMD_HANDLED;
           }
        }
    }

    else {  /* Else: prefixed */
        for (int i=0; i<ARRAY_LENGTH(prefixed_cmds); ++i) {
            const repl_cmd_t *cmd = &prefixed_cmds[i];
            if (strncmp(data, cmd->command, strlen(cmd->command)) == 0) {
                prefixed_cmds[i].fn(asrepl, cmd, NULL);
                return CMD_HANDLED;
           }
        }
    }

    return CMD_NOT_A_COMMAND;
}
