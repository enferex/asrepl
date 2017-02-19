#ifndef __ASREPL_H
#define __ASREPL_H
#include <stdint.h>
#include <sys/types.h>
#include <sys/user.h>

extern uintptr_t asrepl_get_pc(pid_t pid);
extern void asrepl_get_registers(pid_t pid, struct user_regs_struct *regs);

/* Print register values to stdout */
extern void asrepl_dump_registers(pid_t pid);

#endif /* __ASREPL_H */
