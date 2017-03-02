#include <stdbool.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include "asrepl.h"
#include "engine.h"
#include "config.h"

#ifdef HAVE_LIBUNICORN
#include <unicorn/unicorn.h>
#define UC_TEXT_ADDR 0x10000000
#endif

typedef struct _engine_desc_t
{
	_Bool (*init)(engine_t		*eng);
	_Bool (*shutdown)(engine_t	*eng);

	_Bool (*update)(engine_t *eng, const char *instructions, size_t length);
	void (*execute)(engine_t *eng, size_t length, size_t count);
} engine_desc_t;

static _Bool native_init(engine_t *eng)
{
    const pid_t pid = fork();
    
    //assert(asr);
    //asr->engine_pid = pid;

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

static _Bool native_update(engine_t *eng, const char *instructions, size_t length)
{
	//TODO: ID and incorporate
}

static void native_execute(engine_t *eng, size_t length, size_t count)
{
	//TODO: ID and incorporate
}

#ifdef HAVE_LIBUNICORN
static _Bool unicorn_init(engine_t *eng)
{
	uc_engine *uc;
	uc_err err;
	uc_context *context = 0x00;

	//TODO: parameterize execution mode via engine_t Arch/Mode flags
	err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
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

_Bool unicorn_update(engine_t *eng, const char *instructions, size_t length)
{
	uc_engine *uc = (uc_engine *)eng->handle;
	uc_err err;

	err = uc_mem_write(uc, UC_TEXT_ADDR, instructions, length);
	if (err != UC_ERR_OK) {
		ERR("Failed to write ops to execution memory [uc_mem_write()]: %s", uc_strerror(err));
		return false;
	}

	return true;
}

void unicorn_execute(engine_t *eng, size_t length, size_t count)
{
	uc_engine *uc = (uc_engine *)eng->handle;
	uc_err err;
	uc_context *context = (uc_context*)eng->state;
	
	if(context){
		err = uc_context_restore(uc, context);
		if (err != UC_ERR_OK) {
			ERR("Failed to restore unicorn execution context [uc_context_restore()]: %s",
					uc_strerror(err));
			return;
		}
	}else{
		err = uc_context_alloc(uc, &context);
		if (err != UC_ERR_OK) {
			ERR("Failed to allocat Unicorn context struct [uc_context_alloc()]: %s",
					uc_strerror(err));
			return;
		}
		eng->state = (engine_h)context;
	}

	err = uc_emu_start(uc, UC_TEXT_ADDR, UC_TEXT_ADDR+length, 0, count);
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
#endif

static const engine_desc_t engines[] =
{
	[ENGINE_NATIVE]  = {native_init,  native_shutdown,  native_update,  native_execute},
#ifdef HAVE_LIBUNICORN
	[ENGINE_UNICORN] = {unicorn_init, unicorn_shutdown, unicorn_update, unicorn_execute}
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
	eng->state = 0x00;

	/* Initialize the engine */
	if (eng->desc->init(eng) == false)
		ERF("Error initializing the engine.");

	return eng;
}

_Bool engine_update(engine_t *eng, const char *instructions, size_t length)
{
	assert(eng && eng->desc);
	return eng->desc->update(eng, instructions, length);
}

void engine_execute(engine_t *eng, size_t length, size_t count)
{
	assert(eng && eng->desc);
	return eng->desc->execute(eng, length, count);
}
