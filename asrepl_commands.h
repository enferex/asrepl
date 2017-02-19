#ifndef __ASREPL_COMMANDS_H
#define __ASREPL_COMMANDS_H

/* REPL command processing status */
typedef enum _cmd_status_e
{
    CMD_HANDLED,       /* The data was a command, and successful. */
    CMD_ERROR,         /* The data was a command; and not succesful. */
    CMD_NOT_A_COMMAND, /* The data was not a command; not fatal.  */
} cmd_status_e;

/* Given a line of info from the repl, process it as if it 
 * were a command.
 *
 * If this is a command then CMD_HANDLED or CMD_ERROR is returned.
 * If this is unknown, assume it is assembly data, and return CMD_NOT_A_COMMAND.
 *
 * 'pid': pid of the process that we are executing user suppled asm on. 
 */
extern cmd_status_e asrepl_cmd_process(const char *line, pid_t pid);

#endif /* __ASREPL_COMMANDS_H */
