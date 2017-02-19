#ifndef __ASREPL_H
#define __ASREPL_H
#include <stdint.h>
#include <sys/types.h>
#include <sys/user.h>

#define NAME    "asrepl"
#define MAJOR   0
#define MINOR   1
#define LICENSE "GPLv2"
#define YEAR    2017
#define TAG     "asm"
#define PROMPTC "> "
#define PROMPT  TAG PROMPTC

#define PR(_msg, ...)\
    fprintf(stdout, TAG PROMPTC " " _msg "\n", ##__VA_ARGS__)

#define PRINT(_msg, ...)\
    fprintf(stdout, _msg "\n", ##__VA_ARGS__)

#define ERR(_msg, ...) \
    fprintf(stderr, TAG " error" PROMPTC " " _msg  "\n", ##__VA_ARGS__)

#define ERF(_msg, ...)                                                       \
    do {                                                                     \
        fprintf(stderr, TAG " error" PROMPTC " " _msg  "\n", ##__VA_ARGS__); \
        exit(EXIT_FAILURE);                                                  \
    } while (0)

extern uintptr_t asrepl_get_pc(pid_t pid);
extern void asrepl_get_registers(pid_t pid, struct user_regs_struct *regs);

/* Print register values to stdout */
extern void asrepl_dump_registers(pid_t pid);

#endif /* __ASREPL_H */
