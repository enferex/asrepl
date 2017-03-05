#include <stdbool.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include "asrepl.h"
#include "engine.h"
#include "config.h"

#define REG64(_regs, _reg) \
    printf("%s\t 0x%llx\n", #_reg, (_regs)->_reg)

#ifdef HAVE_LIBUNICORN
#include <unicorn/unicorn.h>
#define UC_TEXT_ADDR 0x10000000
#endif

typedef struct _engine_desc_t
{
    _Bool (*init)(engine_t      *eng);
    _Bool (*shutdown)(engine_t  *eng);

    //_Bool (*update)(engine_t *eng, const char *instructions, size_t length);
    //void (*execute)(engine_t *eng, size_t length, size_t count);
    void (*execute)(engine_t *eng, const ctx_t *ctx);
    void (*dump_registers)(engine_t *eng);
} engine_desc_t;

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

static void native_dump_registers(engine_t *eng)
{
    pid_t pid = eng->engine_pid;
    struct user_regs_struct regs;

    get_registers(pid, &regs);

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
}

static _Bool native_init(engine_t *eng)
{
    eng->handle = calloc(1, sizeof(pid_t));
    if (!eng->handle)
        ERF("Could not allocate enough memory to represent an engine handle.");

    const uint64_t pid = fork();

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

static _Bool native_shutdown(engine_t *eng)
{
    return true;
}

static void native_execute(engine_t *eng, const ctx_t *ctx)
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

#ifdef HAVE_LIBUNICORN
static _Bool unicorn_init(engine_t *eng)
{
    uc_engine *uc;
    uc_err err;
    uc_context *context = NULL;

    /* TODO: parameterize execution mode via engine_t Arch/Mode flags */
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        ERR("Error opening unicorn engine [uc_open()]: %s", uc_strerror(err));
        return false;
    }

    /* TODO: parametrize UC_TEXT_ADDR based upon the Arch being emulated */
    err = uc_mem_map(uc, UC_TEXT_ADDR, 2*1024*1024, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        ERR("Error mapping executable page [uc_mem_map()]: %s",
            uc_strerror(err));
        return false;
    }

    eng->handle = (engine_h)uc;
    eng->state  = (engine_h)context;
    return true;
}

static _Bool unicorn_shutdown(engine_t *eng)
{
    uc_engine *uc = (uc_engine *)eng->handle;
    uc_context *context = (uc_context *)eng->state;

    if (!uc)
      return false;

    /* A Unicorn context may or may not have been allocated */
    if (context)
      uc_free(context);

    uc_close(uc);
    return true;
}

void unicorn_execute(engine_t *eng, const ctx_t *ctx)
{
    uc_err err;
    uc_engine *uc = (uc_engine *)eng->handle;
    uc_context *context = (uc_context*)eng->state;

    err = uc_mem_write(uc, UC_TEXT_ADDR, ctx->text, ctx->length);
    if (err != UC_ERR_OK) {
        ERR("Failed to write ops to execution memory [uc_mem_write()]: %s",
            uc_strerror(err));
        return;
    }

    /* Use the existing uc state, or allocate a fresh one. */
    if (context) {
        err = uc_context_restore(uc, context);
        if (err != UC_ERR_OK) {
            ERR("Failed to restore unicorn execution "
                "context [uc_context_restore()]: %s",
                uc_strerror(err));
            return;
        }
    } 
    else {
        err = uc_context_alloc(uc, &context);
        if (err != UC_ERR_OK) {
            ERR("Failed to allocat Unicorn context "
                "struct [uc_context_alloc()]: %s",
                uc_strerror(err));
            return;
        }
        eng->state = (engine_h)context;
    }

    err = uc_emu_start(uc, UC_TEXT_ADDR, UC_TEXT_ADDR+ctx->length, 0, 0);
    if (err) {
        ERR("Failed to start emulation [uc_emu_start()]: %s", uc_strerror(err));
        return;
    }

    err = uc_context_save(uc, context);
    if (err != UC_ERR_OK) {
        ERR("Failed to save the unicorn context [uc_context_save()]: %s", uc_strerror(err));
        return;
    }

}

static void unicorn_dump_registers(engine_t *eng)
{
    struct user_regs_struct regs;

    uc_reg_read(eng->handle, UC_X86_REG_EFLAGS, &regs.eflags);
    uc_reg_read(eng->handle, UC_X86_REG_RIP, &regs.rip);
    uc_reg_read(eng->handle, UC_X86_REG_CS, &regs.cs);
    uc_reg_read(eng->handle, UC_X86_REG_DS, &regs.ds);
    uc_reg_read(eng->handle, UC_X86_REG_ES, &regs.es);
    uc_reg_read(eng->handle, UC_X86_REG_FS, &regs.fs);
    uc_reg_read(eng->handle, UC_X86_REG_GS, &regs.gs);
    uc_reg_read(eng->handle, UC_X86_REG_SS, &regs.ss);
    uc_reg_read(eng->handle, UC_X86_REG_RBP, &regs.rbp);
    uc_reg_read(eng->handle, UC_X86_REG_RSP, &regs.rsp);
    uc_reg_read(eng->handle, UC_X86_REG_RAX, &regs.rax);
    uc_reg_read(eng->handle, UC_X86_REG_RBX, &regs.rbx);
    uc_reg_read(eng->handle, UC_X86_REG_RCX, &regs.rcx);
    uc_reg_read(eng->handle, UC_X86_REG_RDX, &regs.rdx);
    uc_reg_read(eng->handle, UC_X86_REG_RDI, &regs.rdi);
    uc_reg_read(eng->handle, UC_X86_REG_RSI, &regs.rsi);
    uc_reg_read(eng->handle, UC_X86_REG_R8, &regs.r8);
    uc_reg_read(eng->handle, UC_X86_REG_R9, &regs.r9);
    uc_reg_read(eng->handle, UC_X86_REG_R10, &regs.r10);
    uc_reg_read(eng->handle, UC_X86_REG_R11, &regs.r11);
    uc_reg_read(eng->handle, UC_X86_REG_R12, &regs.r12);
    uc_reg_read(eng->handle, UC_X86_REG_R13, &regs.r13);
    uc_reg_read(eng->handle, UC_X86_REG_R14, &regs.r14);
    uc_reg_read(eng->handle, UC_X86_REG_R15, &regs.r15);

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
    //REG64(&regs, fs_base);
    //REG64(&regs, gs_base);
}
#endif

static const engine_desc_t engines[] =
{
    [ENGINE_NATIVE]  = {native_init,    native_shutdown,
                        native_execute, native_dump_registers},
#ifdef HAVE_LIBUNICORN
    [ENGINE_UNICORN] = {unicorn_init, unicorn_shutdown,
                        unicorn_execute, unicorn_dump_registers}
#endif
};

engine_t *engine_init(engine_e type)
{
    engine_t *eng = calloc(1, sizeof(engine_t));
    if (!eng)
      ERF("Could not allocate enough memory to represent an engine.");

    /* Handle descriptions */
    if (type == ENGINE_INVALID || type >= ENGINE_MAX)
      ERF("Invalid engine type: %d", (int)type);

    eng->type  = type;
    eng->desc  = &engines[type];
    eng->state = NULL;

    /* Initialize the engine */
    if (eng->desc->init(eng) == false)
      ERF("Error initializing the engine.");

    return eng;
}

void engine_execute(engine_t *eng, const ctx_t *ctx)
{
    assert(eng && eng->desc);
    return eng->desc->execute(eng, ctx);
}

void engine_dump_registers(engine_t *eng)
{
    assert(eng && eng->desc);
    return eng->desc->dump_registers(eng);
}
