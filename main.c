#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/ptrace.h>

#define TAG     "asm"
#define PROMPTC "> "
#define PROMPT  TAG PROMPTC

#define ERR(_msg, ...) \
    fprintf(stderr, TAG " error" PROMPTC " " _msg  "\n", ##__VA_ARGS__)

#define ERF(_msg, ...)                                                       \
    do {                                                                     \
        fprintf(stderr, TAG " error" PROMPTC " " _msg  "\n", ##__VA_ARGS__); \
        exit(EXIT_FAILURE);                                                  \
    } while (0)

typedef long word_t;

/* Size agnostic ELF section header */
typedef struct _shdr_t
{
    _Bool is_64bit;
    union
    {
        Elf64_Shdr ver64;
        Elf32_Shdr ver32;
    } u;
} shdr_t;
#define SHDR(_shdr, _field) \
    ((_shdr).is_64bit ? (_shdr).u.ver64._field : (_shdr).u.ver32._field)

typedef struct _context_t
{
    uint8_t *text;
    size_t   length; /* Bytes of .text */
} ctx_t;

static pid_t init_engine(void)
{
    const pid_t pid = fork();

    if (pid > 0) {
        /* Parent with child's pid.  Wait for the child. */
        int status;
        pid_t ret = waitpid(pid, &status, __WALL);

        if (pid == ret && WIFSTOPPED(status)) {
            for (int i=0; i<10; ++i)
              ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
            return pid;
        }
        return 0;
    }
    else if (pid == 0) {
        /* Child (tracee) */
        if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) == -1) {
            ERF("Error setting traceme in the child process: %s",
                strerror(errno));
        }

        raise(SIGSTOP);

        for ( ;; ) {
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
            __asm__ __volatile__ ("nop\n");
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

    return 0; /* Error */
}

static _Bool read_elf_text_section(const char *obj_name, ctx_t *ctx)
{
    FILE *fp;
    size_t shdr_size;
    _Bool found;
    shdr_t shdr = {0};
    Elf64_Ehdr hdr;

    if (!(fp = fopen(obj_name, "r")))
        ERF("Error opening object file: %s (%s)\n", obj_name, strerror(errno));

    /* Get the ELF header */
    if (fread((void *)&hdr, 1, sizeof(hdr), fp) != sizeof(hdr))
      ERF("Error reading header from %s", obj_name);

    if (memcmp(hdr.e_ident, ELFMAG, SELFMAG) != 0)
      ERF("Error: Invalid ELF file: %s", obj_name);

    fseek(fp, hdr.e_shoff, SEEK_SET);
    if (hdr.e_ident[EI_CLASS] == ELFCLASS64) {
        shdr_size = sizeof(Elf64_Shdr);
        shdr.is_64bit = true;
    }
    else if (hdr.e_ident[EI_CLASS] == ELFCLASS32)
      shdr_size = sizeof(Elf32_Shdr);
    else
      ERF("Invalid binary, expected 32 or 64 bit");

    /* For each section: Look for .text only */
    found = false;
    while (fread((void *)&shdr.u.ver64, 1, shdr_size, fp) == shdr_size) {
        if ((SHDR(shdr,sh_type)   != SHT_PROGBITS) || 
             (SHDR(shdr,sh_flags) != (SHF_ALLOC | SHF_EXECINSTR)))
          continue;

        found = true;
        break;
    }

    if (found) {
        /* Hopefully .text */
        if (!(ctx->text = malloc(SHDR(shdr,sh_size))))
          ERF("Error allocating room to store the binary's read-only data");

        if (!(ctx->text = malloc(SHDR(shdr,sh_size))))
          ERF("Error allocating data from .text");

        /* Read in .text contents */
        fseek(fp, SHDR(shdr,sh_offset), SEEK_SET);
        if (fread(ctx->text, 1, SHDR(shdr,sh_size), fp) != SHDR(shdr,sh_size))
          ERF("Error reading section contents");
        ctx->length = SHDR(shdr,sh_size);
    }

    return found;
}

static _Bool assemble(const char *line, ctx_t *ctx)
{
    _Bool ret;
    FILE *fp;
    
    if (!(fp = fopen(".foo.asm", "w")))
      return false;

    /* Write line to a new asm file */
    ret = (fprintf(fp, "%s\n", line) >= 0);
    fclose(fp);
    if (ret == false) /* Error */
      return false;

    /* Assemble */
    fp = popen("as ./.foo.asm -o ./.foo.o", "r");
    pclose(fp);
    
    /* Locate the code blob */
    read_elf_text_section("./.foo.o", ctx);

    return ret;
}

#define REG64(_regs, _reg)\
    printf("%s\t 0x%llx\n", #_reg, _regs->_reg);

static void dump_regs(const struct user_regs_struct *regs)
{
#ifdef __x86_64__
//    REG64(regs, eflags);
    REG64(regs, rip);
//    REG64(regs, cs);
//    REG64(regs, ds);
//    REG64(regs, es)
//    REG64(regs, fs);
//    REG64(regs, gs);
//    REG64(regs, ss);
//    REG64(regs, rbp);
//    REG64(regs, rsp);
    REG64(regs, rax);
//    REG64(regs, rbx);
//    REG64(regs, rcx);
//    REG64(regs, rdx);
//    REG64(regs, rdi);
//    REG64(regs, rsi);
//    REG64(regs, r8);
//    REG64(regs, r9);
//    REG64(regs, r10);
//    REG64(regs, r11);
//    REG64(regs, r12);
//    REG64(regs, r13);
//    REG64(regs, r14);
//    REG64(regs, r15);
//    REG64(regs, fs_base);
//    REG64(regs, gs_base);
//    REG64(regs, orig_rax);
#endif /* __x86_64__ */
}

static _Bool execute(pid_t pid, const ctx_t *ctx)
{
    int i, status;
    pid_t ret;
    word_t pc;
    uint8_t *insns;
    struct user_regs_struct gpregs;

    ptrace(PTRACE_GETREGS, pid, NULL, &gpregs);
    printf("== Before (pid %d) ==\n", pid);
    dump_regs(&gpregs);

    /* POKETEXT operates on word size units */
    pc = gpregs.rip;
    insns = ctx->text;
    for (i=0; i<1/*ctx->length / sizeof(word_t)*/; ++i) {
        ptrace(PTRACE_POKETEXT, pid, (void *)pc, (void *)insns);
        pc    += sizeof(word_t);
        insns += sizeof(word_t);
    }

    /* Now that data is loaded at the PC of the engine, single step one insn */
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    ret = waitpid(pid, &status, __WALL);
    if (ret != 0 && !WIFSTOPPED(status))
      ERF("Error waiting for engine to single step\n");

    ptrace(PTRACE_GETREGS, pid, NULL, &gpregs);
    printf("== After  (pid %d) ==\n", pid);
    dump_regs(&gpregs);

    return true;
}

static void cleanup(ctx_t *ctx)
{
    free(ctx->text);
    memset(ctx, 0, sizeof(ctx_t));
}

int main(void)
{
    char *line;
    pid_t engine;
    ctx_t ctx;

    if ((engine = init_engine()) == 0) {
        ERR("Error starting engine process, terminating now.");
        exit(EXIT_FAILURE);
    }

    /* Engine has started, now query user for asm code */
    while ((line = readline(PROMPT))) {
        if (assemble(line, &ctx)) {
            execute(engine, &ctx);
            cleanup(&ctx);
            add_history(line);
        }
        else {
            free(line);
            continue;
        }
    }

    return 0;
}
