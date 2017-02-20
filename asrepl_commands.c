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

/* REPL Commands */
static void cmd_help(const void    *unused);
static void cmd_exit(const void    *unused);
static void cmd_version(const void *unused);
static void cmd_dump(const void    *pid);
struct {
    const char *command;
    const char *description;
    void (*fn)(const void *);
    _Bool       hidden;
} static const repl_commands[] = {
    {"regs",    "Dump registers.",           cmd_dump,    false},
    {"help",    "This help message.",        cmd_help,    false},
    {"h",       "This help message.",        cmd_help,    true},
    {"?",       "This help message.",        cmd_help,    true},
    {"wtf",     "This help message.",        cmd_help,    true},
    {"q",       "Exit",                      cmd_exit,    true},
    {"x",       "Exit",                      cmd_exit,    true},
    {"exit",    "Exit",                      cmd_exit,    false},
    {"quit",    "Exit",                      cmd_exit,    true},
    {"ver",     "About/Version information", cmd_version, false},
    {"version", "About/Version information", cmd_version, true},
    {"about",   "About/Version information", cmd_version, true},
};

static void cmd_help(const void *unused)
{
    int i;

    PRINT("Commands:");
    for (i=0; i<sizeof(repl_commands)/sizeof(repl_commands[0]); ++i)
      if (!repl_commands[i].hidden)
        PRINT("%8s: %s",repl_commands[i].command,repl_commands[i].description);
}

static void cmd_exit(const void *unused)
{
    exit(EXIT_SUCCESS);
}

static void cmd_version(const void *unused)
{
    asrepl_version();
}

static void cmd_dump(const void *pid_ptr)
{
    if (pid_ptr == NULL)
      return;

    asrepl_dump_registers(*(pid_t *)pid_ptr);
}

cmd_status_e asrepl_cmd_process(const char *data, pid_t pid)
{
    int i;

    for (i=0; i<sizeof(repl_commands)/sizeof(repl_commands[0]); ++i) {
        const char *cmd = repl_commands[i].command;
        if (strncmp(data, cmd, strlen(cmd)) == 0) {
            repl_commands[i].fn((const void *)&pid);
            return CMD_HANDLED;
        }
    }

    return CMD_NOT_A_COMMAND;
}
