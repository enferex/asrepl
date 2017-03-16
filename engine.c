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

#define REG32(_regs, _reg) \
    printf("%s\t 0x%zx\n", _regs, (uint32_t)_reg)

#ifdef HAVE_LIBUNICORN
#include <unicorn/unicorn.h>
#define UC_TEXT_ADDR 0x10000000
#endif

typedef struct _engine_desc_t
{
	_Bool (*init)(asrepl_t *asr, engine_t *eng);
	_Bool (*shutdown)(engine_t *eng);

	//_Bool (*update)(engine_t *eng, const char *instructions, size_t length);
	//void (*execute)(engine_t *eng, size_t length, size_t count);
	void (*execute)(engine_t *eng, const ctx_t *ctx);
	void (*dump_registers)(asrepl_t *asr);
} engine_desc_t;

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

void native_dump_registers(asrepl_t *asr)
{
    engine_t *eng = asr->engine;
    pid_t pid = eng->engine_pid;
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
}
static _Bool native_init(asrepl_t *asr, engine_t *eng)
{
    eng->handle = calloc(1, sizeof(pid_t));
    if (!eng->handle)
        ERF("Could not allocate enough memory to represent an engine handle.");

    const uint64_t pid = fork();
    
    //assert(asr);
    //asr->engine_pid = pid;
    eng->engine_pid = pid;
    //eng->handle = (engine_h)pid;

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

static _Bool native_shutdown(engine_t *eng) { return true; }

static void native_execute(engine_t *eng, const ctx_t *ctx)
{
	//TODO: cleanup move from asrepl.c (helper functions)
	int i, n_words, status;
	uintptr_t pc, orig_pc;
	pid_t ret;
	uint8_t *insns;
	struct user_regs_struct regs;
	
	/* We will restore the pc after we single step and gather registers */
	orig_pc = asrepl_get_pc(eng->engine_pid);
	
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
	asrepl_get_registers(eng->engine_pid, &regs);
	regs.rip = orig_pc;
	ptrace(PTRACE_SETREGS, eng->engine_pid, NULL, &regs);
}

#ifdef HAVE_LIBUNICORN
static _Bool unicorn_init(asrepl_t *asr, engine_t *eng)
{
	uc_engine *uc;
	uc_err err;
	uc_context *context = 0x00;
	uint32_t r_sp = UC_TEXT_ADDR + 0x200000 - 0x400; //Base address to bottom of 2MB alloc, less 1KB for padding

	err = uc_open(asr->march, asr->mmode, &uc);
	if (err != UC_ERR_OK) {
		ERR("Error opening unicorn engine [uc_open()]: %s", uc_strerror(err));
		return false;
	}

	//TODO: parametrize UC_TEXT_ADDR based upon the Arch being emulated
	err = uc_mem_map(uc, UC_TEXT_ADDR, 2*1024*1024, UC_PROT_ALL);
	if (err != UC_ERR_OK) {
		ERR("Error mapping executable page [uc_mem_map()]: %s", uc_strerror(err));
		return false;
	}

	err = uc_context_alloc(uc, &context);
	if (err != UC_ERR_OK) {
		ERR("Failed to allocat Unicorn context struct [uc_context_alloc()]: %s",
				uc_strerror(err));
		return false;
	}
	eng->state = (engine_h)context;
	
	switch(asr->march)
	{
		case UC_ARCH_X86: uc_reg_write(uc, UC_X86_REG_ESP, &r_sp); break;
		case UC_ARCH_ARM: uc_reg_write(uc, UC_ARM_REG_SP,  &r_sp); break;
		case UC_ARCH_MIPS:uc_reg_write(uc, UC_MIPS_REG_SP, &r_sp); break;
	}
	
	err = uc_context_save(uc, context);
	if (err != UC_ERR_OK) {
		ERR("Failed to save the unicorn context [uc_context_save()]: %s", uc_strerror(err));
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

	if(!uc)
		return false;

	// a Unicorn context may or may not have been allocated
	if(context)
		uc_free(context);

	uc_close(uc);
	return true;
}

void unicorn_execute(engine_t *eng, const ctx_t *ctx)
{
	uc_engine *uc = (uc_engine *)eng->handle;
	uc_err err;
	uc_context *context = (uc_context*)eng->state;
	
	err = uc_mem_write(uc, UC_TEXT_ADDR, ctx->text, ctx->length);
	if (err != UC_ERR_OK) {
		ERR("Failed to write ops to execution memory [uc_mem_write()]: %s", uc_strerror(err));
		return;
	}

	if(context){
		err = uc_context_restore(uc, context);
		if (err != UC_ERR_OK) {
			ERR("Failed to restore unicorn execution context [uc_context_restore()]: %s",
					uc_strerror(err));
			return;
		}
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

void unicorn_dump_registers(asrepl_t *asr)
{
	assert(asr);
	/* x86-64 */
	if(asr->march == UC_ARCH_X86 && asr->mmode == UC_MODE_64)
		unicorn_dump_registers_x86_64(asr->engine);
	/* x86 */
	else if(asr->march == UC_ARCH_X86 && asr->mmode == UC_MODE_32)
		unicorn_dump_registers_x86_32(asr->engine);
	/* arm */
	else if(asr->march == UC_ARCH_ARM)
		unicorn_dump_registers_arm(asr->engine);
	/* mips32 */
	else if(asr->march == UC_ARCH_MIPS)
		unicorn_dump_registers_mips(asr->engine);
}

void unicorn_dump_registers_arm(engine_t *eng)
{
	uint32_t cpsr, sp, lr, pc;
	uint32_t r0, r1, r2, r3;
	uint32_t r4, r5, r6, r7;
	uint32_t r8, r9, r10, r11;
	uint32_t r12;

	uc_reg_read(eng->handle, UC_ARM_REG_CPSR, &cpsr);
	uc_reg_read(eng->handle, UC_ARM_REG_PC, &pc);
	uc_reg_read(eng->handle, UC_ARM_REG_SP, &sp);
	uc_reg_read(eng->handle, UC_ARM_REG_LR, &lr);
	uc_reg_read(eng->handle, UC_ARM_REG_R0, &r0);
	uc_reg_read(eng->handle, UC_ARM_REG_R1, &r1);
	uc_reg_read(eng->handle, UC_ARM_REG_R2, &r2);
	uc_reg_read(eng->handle, UC_ARM_REG_R3, &r3);
	uc_reg_read(eng->handle, UC_ARM_REG_R4, &r4);
	uc_reg_read(eng->handle, UC_ARM_REG_R5, &r5);
	uc_reg_read(eng->handle, UC_ARM_REG_R6, &r6);
	uc_reg_read(eng->handle, UC_ARM_REG_R7, &r7);
	uc_reg_read(eng->handle, UC_ARM_REG_R8, &r8);
	uc_reg_read(eng->handle, UC_ARM_REG_R9, &r9);
	uc_reg_read(eng->handle, UC_ARM_REG_R10, &r10);
	uc_reg_read(eng->handle, UC_ARM_REG_R11, &r11);
	uc_reg_read(eng->handle, UC_ARM_REG_R12, &r12);


	REG32("cpsr", cpsr);
	REG32("pc", pc);
	REG32("sp", sp);
	REG32("lr", lr);
	REG32("r0", r0);
	REG32("r1", r1);
	REG32("r2", r2);
	REG32("r3", r3);
	REG32("r4", r4);
	REG32("r5", r5);
	REG32("r6", r6);
	REG32("r7", r7);
	REG32("r8", r8);
	REG32("r9", r9);
	REG32("r10", r10);
	REG32("r11", r11);
	REG32("r12", r12);
}

void unicorn_dump_registers_mips(engine_t *eng)
{
	uint32_t gp, sp, fp, ra;
	uint32_t zero, at, v0, v1;
	uint32_t a0, a1, a2, a3;
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7;
	uint32_t s0, s1, s2, s3, s4, s5, s6, s7;
	uint32_t t8, t9, k0, k1;

	uc_reg_read(eng->handle, UC_MIPS_REG_GP, &gp);
	uc_reg_read(eng->handle, UC_MIPS_REG_SP, &sp);
	uc_reg_read(eng->handle, UC_MIPS_REG_FP, &fp);
	uc_reg_read(eng->handle, UC_MIPS_REG_RA, &ra);

	uc_reg_read(eng->handle, UC_MIPS_REG_ZERO, &zero);
	uc_reg_read(eng->handle, UC_MIPS_REG_AT, &at);
	uc_reg_read(eng->handle, UC_MIPS_REG_V0, &v0);
	uc_reg_read(eng->handle, UC_MIPS_REG_V1, &v1);

	uc_reg_read(eng->handle, UC_MIPS_REG_A0, &a0);
	uc_reg_read(eng->handle, UC_MIPS_REG_A1, &a1);
	uc_reg_read(eng->handle, UC_MIPS_REG_A2, &a2);
	uc_reg_read(eng->handle, UC_MIPS_REG_A3, &a3);

	uc_reg_read(eng->handle, UC_MIPS_REG_T0, &t0);
	uc_reg_read(eng->handle, UC_MIPS_REG_T1, &t1);
	uc_reg_read(eng->handle, UC_MIPS_REG_T2, &t2);
	uc_reg_read(eng->handle, UC_MIPS_REG_T3, &t3);
	uc_reg_read(eng->handle, UC_MIPS_REG_T4, &t4);
	uc_reg_read(eng->handle, UC_MIPS_REG_T5, &t5);
	uc_reg_read(eng->handle, UC_MIPS_REG_T6, &t6);
	uc_reg_read(eng->handle, UC_MIPS_REG_T7, &t7);
	uc_reg_read(eng->handle, UC_MIPS_REG_T8, &t8);
	uc_reg_read(eng->handle, UC_MIPS_REG_T9, &t9);

	uc_reg_read(eng->handle, UC_MIPS_REG_S0, &s0);
	uc_reg_read(eng->handle, UC_MIPS_REG_S1, &s1);
	uc_reg_read(eng->handle, UC_MIPS_REG_S2, &s2);
	uc_reg_read(eng->handle, UC_MIPS_REG_S3, &s3);
	uc_reg_read(eng->handle, UC_MIPS_REG_S4, &s4);
	uc_reg_read(eng->handle, UC_MIPS_REG_S5, &s5);
	uc_reg_read(eng->handle, UC_MIPS_REG_S6, &s6);
	uc_reg_read(eng->handle, UC_MIPS_REG_S7, &s7);

	uc_reg_read(eng->handle, UC_MIPS_REG_K0, &k0);
	uc_reg_read(eng->handle, UC_MIPS_REG_K1, &k1);

	REG32("gp", gp);
	REG32("sp", sp);
	REG32("fp", fp);
	REG32("ra", ra);

	REG32("zero", zero);
	REG32("at", at);
	REG32("v0", v0);
	REG32("v1", v1);

	REG32("a0", a0);
	REG32("a1", a1);
	REG32("a2", a2);
	REG32("a3", a3);

	REG32("t0", t0);
	REG32("t1", t1);
	REG32("t2", t2);
	REG32("t3", t3);
	REG32("t4", t4);
	REG32("t5", t5);
	REG32("t6", t6);
	REG32("t7", t7);
	REG32("t8", t8);
	REG32("t9", t9);

	REG32("s0", s0);
	REG32("s1", s1);
	REG32("s2", s2);
	REG32("s3", s3);
	REG32("s4", s4);
	REG32("s5", s5);
	REG32("s6", s6);
	REG32("s7", s7);

	REG32("k0", k0);
	REG32("k1", k1);
}

void unicorn_dump_registers_x86_32(engine_t *eng)
{
	uint32_t eflags, eip, cs, ds;
	uint32_t es, fs, gs, ss;
	uint32_t ebp, esp, eax, ebx;
	uint32_t ecx, edx, edi, esi;

	uc_reg_read(eng->handle, UC_X86_REG_EFLAGS, &eflags);
	uc_reg_read(eng->handle, UC_X86_REG_EIP, &eip);
	uc_reg_read(eng->handle, UC_X86_REG_CS, &cs);
	uc_reg_read(eng->handle, UC_X86_REG_DS, &ds);
	uc_reg_read(eng->handle, UC_X86_REG_ES, &es);
	uc_reg_read(eng->handle, UC_X86_REG_FS, &fs);
	uc_reg_read(eng->handle, UC_X86_REG_GS, &gs);
	uc_reg_read(eng->handle, UC_X86_REG_SS, &ss);
	uc_reg_read(eng->handle, UC_X86_REG_EBP, &ebp);
	uc_reg_read(eng->handle, UC_X86_REG_ESP, &esp);
	uc_reg_read(eng->handle, UC_X86_REG_EAX, &eax);
	uc_reg_read(eng->handle, UC_X86_REG_EBX, &ebx);
	uc_reg_read(eng->handle, UC_X86_REG_ECX, &ecx);
	uc_reg_read(eng->handle, UC_X86_REG_EDX, &edx);
	uc_reg_read(eng->handle, UC_X86_REG_EDI, &edi);
	uc_reg_read(eng->handle, UC_X86_REG_ESI, &esi);

	REG32("eflags", eflags);
	REG32("eip", eip);
	REG32("cs", cs);
	REG32("ds", ds);
	REG32("es", es);
	REG32("fs", fs);
	REG32("gs", gs);
	REG32("ss", ss);
	REG32("ebp", ebp);
	REG32("esp", esp);
	REG32("eax", eax);
	REG32("ebx", ebx);
	REG32("ecx", ecx);
	REG32("edx", edx);
	REG32("edi", edi);
	REG32("esi", esi);
}

void unicorn_dump_registers_x86_64(engine_t *eng)
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
	[ENGINE_NATIVE]  = {native_init,  native_shutdown,  native_execute,  native_dump_registers},
#ifdef HAVE_LIBUNICORN
	[ENGINE_UNICORN] = {unicorn_init, unicorn_shutdown, unicorn_execute, unicorn_dump_registers}
#endif
};

engine_t *engine_init(asrepl_t *asr, engine_e type)
{
	engine_t *eng = calloc(1, sizeof(engine_t));
	if (!eng)
		ERF("Could not allocate enough memory to represent an engine.");

	/* Handle descriptions */
	if (type == ENGINE_INVALID || type >= ENGINE_MAX)
		ERF("Invalid engine type: %d", (int)type);

	eng->type  = type;
	eng->desc  = &engines[type];
	eng->state = 0x00;

	/* Initialize the engine */
	if (eng->desc->init(asr,eng) == false)
		ERF("Error initializing the engine.");

	return eng;
}

void engine_execute(engine_t *eng, const ctx_t *ctx)
{
	assert(eng && eng->desc);
	return eng->desc->execute(eng, ctx);
}

void engine_dump_registers(asrepl_t *asr)
{
	assert(asr && asr->engine && asr->engine->desc);
	return asr->engine->desc->dump_registers(asr);
}
