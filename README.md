asrepl: x86-64 assembly REPL
===============================
asrepl is an assembly based REPL.  The REPL processes each line of user input,
the output can be witnessed by issuing the command 'regs' and looking
at the register state.

How asrepl Works
----------------
asrepl works by the following steps:
1. Fork a process that will be used to execute user supplied asm.  The
   terminology to recognize is: "The parent process forks the child process."
2. The parent process listens for user supplied asm instructions.
3. When a newline is encountered (pressing enter in the REPL), the asm is
   assembled via the host assembler.
4. The parent process opens the object file generated from the host
   assembler, which contains the user's supplied asm, assembled down to machine
   instructions.
5. Those instructions are injected into the child process, and the child
   process is single stepped one instruction.
   goto 2.

Building
--------
Run `make` from the directory.  Once you jump into the REPL issue a "?" to
get a list of commands.

Notes
-----
* This tool is alpha. (Lame excuse if something doesn't work).
* This tool creates and overwrites two files: .asrepl.foo.s, .asrepl.foo.o.  Be
  aware if you already have those files.  Additionally, since asrepl leaves
  these files around, ensure that you do not leave any super secret leet asm
  marinating, or others might get your leet secretz.

Dependencies
------------
1. GNU readline library, you probably have this.
2. x86-64 bit architecture.
3. An assembler, ideally GNU as: https://www.gnu.org/software/binutils/
3. I've only tested this on Linux.

Contact
-------
Matt Davis (enferex)

If you want more features or find a bug, feel free to reach out to me
via github: http://github.com/enferex
