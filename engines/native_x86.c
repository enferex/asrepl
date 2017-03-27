#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <errno.h>
#include "../asrepl.h"
#include "common.h"

static void get_registers(pid_t pid, struct user_regs_struct *gpregs)
{
    memset(gpregs, 0, sizeof(*gpregs));
    ptrace(PTRACE_GETREGS, pid, NULL, gpregs);
}

static uintptr_t get_pc(pid_t pid)
{
    struct user_regs_struct gpregs;
    get_registers(pid, &gpregs);
    return gpregs.rip;
}

static void native_x8664_read_registers(engine_t *eng)
{
    pid_t pid = eng->engine_pid;
    struct user_regs_struct regs;

    get_registers(pid, &regs);

    REGS_X8664(eng).eflags  = regs.eflags;
    REGS_X8664(eng).rip     = regs.rip;
    REGS_X8664(eng).cs      = regs.cs;
    REGS_X8664(eng).ds      = regs.ds;
    REGS_X8664(eng).es      = regs.es;
    REGS_X8664(eng).fs      = regs.fs;
    REGS_X8664(eng).gs      = regs.fs;
    REGS_X8664(eng).ss      = regs.ss;
    REGS_X8664(eng).rbp     = regs.rbp;
    REGS_X8664(eng).rsp     = regs.rsp;
    REGS_X8664(eng).rax     = regs.rax;
    REGS_X8664(eng).rbx     = regs.rbx;
    REGS_X8664(eng).rcx     = regs.rcx;
    REGS_X8664(eng).rdx     = regs.rdx;
    REGS_X8664(eng).rdi     = regs.rdi;
    REGS_X8664(eng).rsi     = regs.rsi;
    REGS_X8664(eng).r8      = regs.r8;
    REGS_X8664(eng).r9      = regs.r9;
    REGS_X8664(eng).r10     = regs.r10;
    REGS_X8664(eng).r11     = regs.r11;
    REGS_X8664(eng).r12     = regs.r12;
    REGS_X8664(eng).r13     = regs.r13;
    REGS_X8664(eng).r14     = regs.r14;
    REGS_X8664(eng).r15     = regs.r15;
}

static _Bool native_x8664_init(asrepl_t *asr, engine_t *eng)
{
    uint64_t pid;

    eng->handle = calloc(1, sizeof(pid_t));
    if (!eng->handle)
        ERF("Could not allocate enough memory to represent an engine handle.");

    pid = fork();
    eng->engine_pid = pid;

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

static _Bool native_x8664_shutdown(engine_t *eng)
{
    return true;
}

static void native_x8664_execute(engine_t *eng, const ctx_t *ctx)
{
    int i, n_words, status;
    uintptr_t pc, orig_pc;
    pid_t ret;
    uint8_t *insns;
    struct user_regs_struct regs;

    /* We will restore the pc after we single step and gather registers */
    orig_pc = get_pc(eng->engine_pid);

    /* POKETEXT operates on word size units (round up) */
    pc = orig_pc;
    insns = ctx->text;
    n_words = (ctx->length / sizeof(word_t));
    if (ctx->length % sizeof(word_t))
        ++n_words;

    for (i=0; i<n_words; ++i) {
        word_t word = *(word_t *)insns;
        ptrace(PTRACE_POKETEXT, eng->engine_pid, (void *)pc, (void *)word);
        pc    += sizeof(word_t);
        insns += sizeof(word_t);
    }

    /* Now that data is loaded at the PC of the engine, single step one insn */
    ptrace(PTRACE_SINGLESTEP, eng->engine_pid, NULL, NULL);
    ret = waitpid(eng->engine_pid, &status, __WALL);
    if (ret != 0 && !WIFSTOPPED(status))
        ERF("Error waiting for engine to single step\n");

    /* Now that we have executed the instruction, restore the pc */
    get_registers(eng->engine_pid, &regs);
    regs.rip = orig_pc;
    ptrace(PTRACE_SETREGS, eng->engine_pid, NULL, &regs);
}

/*
 * REGISTRATION
 */
const engine_desc_t *native_x8664_registration(void)
{
    static const engine_desc_t desc = {
        .type           = ENGINE_NATIVE_X8664,
        .init           = native_x8664_init,
        .execute        = native_x8664_execute,
        .shutdown       = native_x8664_shutdown,
        .read_registers = native_x8664_read_registers,
        .dump_registers = common_x8664_dump_registers
    };

    return &desc;
}
