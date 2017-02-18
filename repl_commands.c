#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "repl_commands.h"

/* REPL Commands */
static void cmd_help(void);
static void cmd_exit(void);
static void cmd_version(void);
struct {
    const char *command;
    const char *description;
    void (*fn)(void);
    _Bool       hidden;
} static const repl_commands[] = {
    {"help", "This help message.",        cmd_help,    false},
    {"h",    "This help message.",        cmd_help,    true},
    {"?",    "This help message.",        cmd_help,    true},
    {"wtf",  "This help message.",        cmd_help,    true},
    {"exit", "Exit",                      cmd_exit,    false},
    {"quit", "Exit",                      cmd_exit,    true},
    {"ver",  "About/Version information", cmd_version, false},
};

static void cmd_help(void)
{
    int i;

    PR("Commands:");
    for (i=0; i<sizeof(repl_commands)/sizeof(repl_commands[0]); ++i)
      if (!repl_commands[i].hidden)
        PR("%8s: %s", repl_commands[i].command, repl_commands[i].description);
}

static void cmd_exit(void)
{
    exit(EXIT_SUCCESS);
}

static void cmd_version(void)
{
}

cmd_status_e cmd_process(const char *data)
{
    int i;

    for (i=0; i<sizeof(repl_commands)/sizeof(repl_commands[0]); ++i) {
        const char *cmd = repl_commands[i].command;
        if (strncmp(data, cmd, strlen(cmd)) == 0) {
            repl_commands[i].fn();
            return CMD_HANDLED;
        }
    }

    return CMD_NOT_A_COMMAND;
}
