#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include "asrepl.h"

#define REG64(_regs, _reg) \
    printf("%s\t 0x%llx\n", #_reg, (_regs)->_reg)

void asrepl_get_registers(pid_t pid, struct user_regs_struct *gpregs)
{
    memset(gpregs, 0, sizeof(*gpregs));
    ptrace(PTRACE_GETREGS, pid, NULL, gpregs);
}

uintptr_t asrepl_get_pc(pid_t pid)
{
    struct user_regs_struct gpregs;
    asrepl_get_registers(pid, &gpregs);
    return gpregs.rip;
}

void asrepl_dump_registers(pid_t pid)
{
#ifdef __x86_64__
    struct user_regs_struct regs;

    asrepl_get_registers(pid, &regs);

    REG64(&regs, eflags);
    REG64(&regs, rip);
    REG64(&regs, cs);
    REG64(&regs, ds);
    REG64(&regs, es);
    REG64(&regs, fs);
    REG64(&regs, gs);
    REG64(&regs, ss);
    REG64(&regs, rbp);
    REG64(&regs, rsp);
    REG64(&regs, rax);
    REG64(&regs, rbx);
    REG64(&regs, rcx);
    REG64(&regs, rdx);
    REG64(&regs, rdi);
    REG64(&regs, rsi);
    REG64(&regs, r8);
    REG64(&regs, r9);
    REG64(&regs, r10);
    REG64(&regs, r11);
    REG64(&regs, r12);
    REG64(&regs, r13);
    REG64(&regs, r14);
    REG64(&regs, r15);
    REG64(&regs, fs_base);
    REG64(&regs, gs_base);
/*    REG64(&regs, orig_rax); */
#endif /* __x86_64__ */
}
