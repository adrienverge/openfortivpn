#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([openfortivpn], [1.3.0])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([foreign subdir-objects])

# Checks for programs.
AC_PROG_CC
AC_GNU_SOURCE

AM_SILENT_RULES([yes])

# Checks for libraries.
AC_CHECK_LIB([crypto], [ERR_peek_last_error], [], [AC_MSG_ERROR([Cannot find libcrypto.])])
AC_CHECK_LIB([pthread], [pthread_create], [], [AC_MSG_ERROR([Cannot find libpthread.])])
AC_CHECK_LIB([ssl], [SSL_connect], [], [AC_MSG_ERROR([Cannot find libssl.])])
AC_CHECK_LIB([util], [forkpty], [], [AC_MSG_ERROR([Cannot find libutil.])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/ioctl.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero gethostbyname inet_ntoa memmove memset memmem select socket strerror strstr strtol])

AC_DEFINE_UNQUOTED([SYSCONFDIR],["`eval echo $sysconfdir`"])
AC_SUBST([SYSCONFDIR],["`eval echo $sysconfdir`"])
AC_CONFIG_FILES([doc/openfortivpn.1])

#AC_CONFIG_FILES([Makefile])
AC_OUTPUT(Makefile)
