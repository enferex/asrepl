asrepl: x86-64 assembly REPL
===============================
asrepl is an assembly based REPL.  The REPL processes each line of user input,
the output can be witnessed by issuing the command 'regs' and looking
at the register state.

How asrepl Works
----------------
asrepl works by the following steps when not using Unicorn + Keystone:

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
1. Run `./configure` to generate a Makefile and autodetect a build
   configuration based on libraries available on your system.
2. Run `make` from the directory.  Once you jump into the REPL issue a "?" to
   get a list of commands.
3. The resulting application is called `asrepl`, so have at it!

Notes
-----
* mips32 support is not functioning.
* This tool is alpha. (Lame excuse if something doesn't work).
* This tool creates and overwrites two files: .asrepl.foo.s, .asrepl.foo.o.  Be
  aware if you already have those files.  Additionally, since asrepl leaves
  these files around, ensure that you do not leave any super secret leet asm
  marinating, or others might get your leet secretz.

Dependencies (for default x8664 asm operation)
------------
1. GNU readline library, you probably have this.
2. x86-64 bit architecture.
3. An assembler, ideally GNU as: https://www.gnu.org/software/binutils/
3. I've only tested this on Linux.
4. Optional: Keystone and Unicorn Engine (for arm, mips, x8632 support).

Thanks
------
Special thanks goes out to sibios who charged the Keystone in Unicorn support.
That feature allows asrepl act as a repl for a multitude of architectures.

Contact
-------
Matt Davis (enferex)

If you want more features or find a bug, feel free to reach out to me
via github: http://github.com/enferex
