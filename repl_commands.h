#ifndef __REPL_COMMANDS_H
#define __REPL_COMMANDS_H

#define TAG     "asm"
#define PROMPTC "> "
#define PROMPT  TAG PROMPTC

#define PR(_msg, ...)\
    fprintf(stdout, TAG PROMPTC " " _msg "\n", ##__VA_ARGS__)

#define ERR(_msg, ...) \
    fprintf(stderr, TAG " error" PROMPTC " " _msg  "\n", ##__VA_ARGS__)

#define ERF(_msg, ...)                                                       \
    do {                                                                     \
        fprintf(stderr, TAG " error" PROMPTC " " _msg  "\n", ##__VA_ARGS__); \
        exit(EXIT_FAILURE);                                                  \
    } while (0)

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
 */
extern cmd_status_e cmd_process(const char *line);

#endif /* __REPL_COMMANDS_H */
