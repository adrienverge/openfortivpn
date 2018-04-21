#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([openfortivpn], [1.7.0])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([foreign subdir-objects])

# Checks for programs.
AC_PROG_CC
AC_GNU_SOURCE
m4_ifndef([PKG_PROG_PKG_CONFIG], [m4_fatal([Please install pkg-config.])])
PKG_PROG_PKG_CONFIG

# Helps support multiarch by setting 'host_os' and 'host_cpu'
AC_CANONICAL_HOST

AM_SILENT_RULES([yes])

# Checks for libraries.
PKG_CHECK_MODULES(OPENSSL, [libcrypto libssl])
AC_CHECK_LIB([pthread], [pthread_create], [], [AC_MSG_ERROR([Cannot find libpthread.])])
AC_CHECK_LIB([util], [forkpty], [], [AC_MSG_ERROR([Cannot find libutil.])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h assert.h ctype.h errno.h fcntl.h getopt.h ifaddrs.h limits.h mach/mach.h netdb.h net/if.h netinet/in.h netinet/tcp.h net/route.h pty.h semaphore.h signal.h stdarg.h stddef.h stdint.h stdio.h stdlib.h string.h strings.h sys/ioctl.h syslog.h sys/socket.h sys/stat.h sys/time.h sys/types.h sys/wait.h termios.h unistd.h util.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([struct termios], [], [], [#include <termios.h>])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([atoi close connect execv exit _exit fclose fcntl fflush fopen forkpty fprintf fputs free freeaddrinfo freeifaddrs freopen fwrite getaddrinfo getchar getenv getopt_long htons index inet_addr inet_ntoa isatty malloc memcpy memmem memmove memset ntohs open openlog pclose popen printf pthread_cancel pthread_cond_init pthread_cond_signal pthread_cond_wait pthread_join pthread_mutexattr_init pthread_mutex_destroy pthread_mutex_init pthread_mutex_lock pthread_mutex_unlock pthread_sigmask puts read realloc rewind select setenv sigaddset sigemptyset signal snprintf socket sprintf strcasestr strcat strchr strcmp strcpy strdup strerror strlen strncasecmp strncat strncpy strsignal strstr strtok strtok_r strtol syslog system tcsetattr usleep vprintf vsnprintf vsyslog write], [], AC_MSG_ERROR([Required function not present]))
AC_CHECK_FUNCS([pthread_mutexattr_setrobust X509_check_host])

AC_OUTPUT(Makefile)
