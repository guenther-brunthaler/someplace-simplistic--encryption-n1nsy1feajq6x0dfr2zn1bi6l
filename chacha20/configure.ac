#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([simplistic_enc], [2024.66], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([chacha20.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h limits.h stdint.h stdlib.h string.h sys/ioctl.h unistd.h termios.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_HEADER_TIOCGWINSZ
AC_C_BIGENDIAN

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memmove strstr])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
