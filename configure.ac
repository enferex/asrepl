AC_PREREQ([2.69])
AC_INIT([asrepl], [0.1])
AC_CONFIG_SRCDIR([asrepl.c])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_LANG_C

# Checks for programs.
AC_PROG_CC

# Definitions
# AC_DEFINE([ASSEMBLER], CCAS, [Define assembler to use.])

# Checks for libraries (we check unicorn twice to easily add -lpthread to LIBS)
AC_CHECK_LIB([readline], [readline])
AC_CHECK_LIB([keystone], [ks_asm])
AC_CHECK_LIB([unicorn],  [uc_context_alloc], [], [], [-lpthread])
AC_CHECK_LIB([unicorn],  [uc_context_alloc], [LIBS+=-lpthread], [], [-lpthread])
AC_CHECK_LIB([ncurses],  [initscr])
AC_CHECK_LIB([panel],    [new_panel])

# Checks for header files.
AC_CHECK_HEADERS([stdarg.h stdint.h stdlib.h string.h \
                  time.h unistd.h ncurses.h panel.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strerror])

AC_OUTPUT
