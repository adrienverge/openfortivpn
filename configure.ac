#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([openfortivpn], [1.11.0])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([foreign subdir-objects])

# Checks for programs.
AC_PROG_CC
AC_GNU_SOURCE
m4_ifndef([PKG_PROG_PKG_CONFIG], [m4_fatal([Please install pkg-config.])])
PKG_PROG_PKG_CONFIG

# Helps support multiarch by setting 'host_os' and 'host_cpu'
AC_CANONICAL_HOST

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for libraries.
PKG_CHECK_MODULES(OPENSSL, [libssl >= 0.9.8 libcrypto >= 0.9.8], [], [AC_MSG_ERROR([Cannot find OpenSSL 0.9.8 or higher.])])
AC_CHECK_LIB([pthread], [pthread_create], [], [AC_MSG_ERROR([Cannot find libpthread.])])
AC_CHECK_LIB([util], [forkpty], [], [AC_MSG_ERROR([Cannot find libutil.])])
PKG_CHECK_MODULES(LIBSYSTEMD, [libsystemd], [AC_DEFINE(HAVE_SYSTEMD)], [AC_MSG_RESULT([libsystemd not present])])

# we assume presence of the follwowing C standard headers
# and ommit them in the follwoing header checks
#
# assert.h
# ctype.h
# errno.h
# limits.h
# signal.h
# stdarg.h
# stdint.h
# stdio.h
# stdlib.h
# string.h

# Checks for required header files.
AC_CHECK_HEADERS([ \
arpa/inet.h \
fcntl.h \
getopt.h \
ifaddrs.h \
netdb.h \
net/if.h \
netinet/in.h \
netinet/tcp.h \
pthread.h \
sys/ioctl.h \
syslog.h \
sys/socket.h \
sys/stat.h \
sys/types.h \
sys/wait.h \
termios.h \
unistd.h \
], [], AC_MSG_ERROR([Required header not found]))

# Checks for header files with prerequisites of other headers.
AC_CHECK_HEADERS([net/route.h], [], AC_MSG_ERROR([Required header not found]), [#include <net/if.h>])

# Checks for optional header files.
AC_CHECK_HEADERS([ \
libutil.h \
mach/mach.h \
pty.h \
semaphore.h \
sys/mutex.h \
util.h \
])

# Checks for optional header files with prerequisites of other headers.
AC_CHECK_HEADERS([net/if_var.h],[],[],[#include <net/if.h>])

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
AC_CHECK_FUNCS([ \
access \
atoi \
close \
connect \
execv \
exit \
_exit \
fclose \
fcntl \
fflush \
fileno \
fopen \
forkpty \
fprintf \
fputc \
fputs \
fread \
free \
freeaddrinfo \
freeifaddrs \
freopen \
fwrite \
gai_strerror \
getaddrinfo \
getchar \
getenv \
geteuid \
getifaddrs \
getopt_long \
htons \
index \
inet_addr \
inet_ntoa \
ioctl \
isatty \
isdigit \
isspace \
malloc \
memcmp \
memcpy \
memmem \
memmove \
memset \
ntohs \
open \
openlog \
optarg \
optind \
pclose \
popen \
printf \
pthread_cancel \
pthread_cond_init \
pthread_cond_signal \
pthread_cond_wait \
pthread_create \
pthread_join \
pthread_mutexattr_init \
pthread_mutex_destroy \
pthread_mutex_init \
pthread_mutex_lock \
pthread_mutex_unlock \
pthread_self \
pthread_sigmask \
putchar \
puts \
read \
realloc \
rewind \
select \
sem_destroy \
sem_init \
sem_post \
sem_wait \
setenv \
setsockopt \
sigaddset \
sigemptyset \
signal \
sleep \
snprintf \
socket \
sprintf \
sscanf \
strcasecmp \
strcasestr \
strcat \
strchr \
strcmp \
strcpy \
strdup \
strerror \
strlen \
strncasecmp \
strncat \
strncmp \
strncpy \
strsignal \
strstr \
strtok \
strtok_r \
strtol \
strtoul \
syslog \
system \
tcgetattr \
tcsetattr \
usleep \
vprintf \
vsnprintf \
vsyslog \
waitpid \
write \
], [], AC_MSG_ERROR([Required function not found]))

# Checks for optional functions.
AC_CHECK_FUNCS([pthread_mutexattr_setrobust])
# Use PKG_CHECK_MODULES compiler/linker flags
save_openssl_CPPFLAGS="${CPPFLAGS}"
save_openssl_LIBS="${LIBS}"
CPPFLAGS="${OPENSSL_CFLAGS} ${CPPFLAGS}"
LIBS="${OPENSSL_LIBS} ${LIBS}"
AC_CHECK_FUNCS([X509_check_host])
CPPFLAGS="${save_openssl_CPPFLAGS}"
LIBS="${save_openssl_LIBS}"

# Specialised checks for particular features.
# When cross compile, don't run the tests.
AC_ARG_WITH([rt_dst],
	AS_HELP_STRING([--with-rt_dst],
			  [disable rtentry with rt_dst testing (for linux target when cross compile)]),
	AS_IF([test "x$with_rt_dst" = "xyes"],[
	AC_MSG_NOTICE([HAVE_RT_ENTRY_WITH_RT_DST... 1])
	AC_DEFINE(HAVE_RT_ENTRY_WITH_RT_DST)
	])
)
AS_IF([test "x$with_rt_dst" = "x" ], [
AC_MSG_CHECKING(whether rtentry is available and has rt_dst)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>
static inline struct sockaddr_in *cast_addr(struct sockaddr *addr)
{
  return (struct sockaddr_in *) addr;
}
],[
struct rtentry route;
cast_addr(&(&route)->rt_dst)->sin_family = AF_INET;
])],[
  AC_DEFINE(HAVE_RT_ENTRY_WITH_RT_DST)
  AC_MSG_RESULT(yes)
], AC_MSG_RESULT(no) )
])

NETSTAT_PATH=""
PPP_PATH=""
RESOLVCONF_PATH=""

# prepare possibility to override default locations
AC_ARG_WITH([netstat],
        AS_HELP_STRING([--with-netstat],
                       [Set the path to the netstat executable on MacOSX or FreeBSD]),
        NETSTAT_PATH="$withval"
)
# this is for the pppd daemon executable
AC_ARG_WITH([pppd],
        AS_HELP_STRING([--with-pppd],
                       [Set the path to the pppd daemon executable]),
        AS_IF([test ! "x$with_pppd" = "xno" -a ! "x$with_pppd" = "xyes"],[
		PPP_PATH="$withval"
		with_pppd="yes"
		with_ppp="no"
	])
)
# and this is for the ppp user space client on FreeBSD
AC_ARG_WITH([ppp],
        AS_HELP_STRING([--with-ppp],
                       [Set the path to the ppp userspace client on FreeBSD]),
        AS_IF([test ! "x$with_ppp" = "xno" -a ! "x$with_ppp" = "xyes"],[
		PPP_PATH="$withval"
		with_ppp="yes"
		with_pppd="no"
	])
)
# resolvconf if present
AC_ARG_WITH([resolvconf],
        AS_HELP_STRING([--with-resolvconf],
                       [Set the path to the resolvconf executable]),
        RESOLVCONF_PATH="$withval"
)

# override for /proc/net/route detection
AC_ARG_ENABLE([proc],
	AS_HELP_STRING([--enable-proc],
			[Enable route manipulations directly via /proc/net/route \
			when cross-compiling, use --disable-proc for the opposite]))

# Checks for existence of specific files if not cross-compiling.
AS_IF([test "x$enable_proc" = "x" ], [
AC_CHECK_FILE([/proc/net/route],[
  AS_IF([test "x$enable_proc" = "x" ], [
    enable_proc="yes"
  ])
],[
  AS_IF([test "x$NETSTAT_PATH" = "x" ], [
    AC_CHECK_FILE([/usr/sbin/netstat],[
      NETSTAT_PATH="/usr/sbin/netstat"
    ],[
      AC_CHECK_FILE([/usr/bin/netstat],[
	NETSTAT_PATH="/usr/bin/netstat"
      ],[])
    ])
  ])
])
])

# check for ppp user space client if not specified
AC_PATH_PROG(PPP, [ppp], [/usr/sbin/ppp], "$PATH:/sbin:/usr/sbin")
AS_IF([test "x$PPP_PATH" = "x" ], [
AC_CHECK_FILE([$PPP], [
  AS_IF([test "x$PPP_PATH" = "x" ], [
    PPP_PATH="$PPP"
  ])
  AS_IF([test "x$with_ppp" = "x" ], [
    with_ppp="yes"
  ])
],[])
])
# check for pppd if not specified
AC_PATH_PROG(PPPD, [pppd], [/usr/sbin/pppd], "$PATH:/sbin:/usr/sbin")
AS_IF([test "x$PPP_PATH" = "x" ], [
AC_CHECK_FILE([$PPPD], [
  AS_IF([test "x$PPP_PATH" = "x" ], [
    PPP_PATH="$PPPD"
  ])
  AS_IF([test "x$with_pppd" = "x" ], [
    with_pppd="yes"
  ])
],[])
])
# replace empty settings with "no"
AS_IF([test "x$with_ppp" = "x" ], [
    with_ppp="no"
])
AS_IF([test "x$with_pppd" = "x" ], [
    with_pppd="no"
])

# when neither ppp nor pppd are enabled fall back to a sensible choice for the platform
AS_IF([test "x$with_ppp" = "xno" -a "x$with_pppd" = "xno" ], [
   AS_IF([test "x$uname" = "xFreeBSD" ], [
     PPP_PATH="/usr/sbin/ppp"
     with_ppp="yes"
   ], [
     with_pppd="yes"
     PPP_PATH="/usr/sbin/pppd"
   ])
])

# When both are enabled, give pppd the higher priority (we can only use one of them).
# Note that PPP_PATH should already be correct since pppd is detected later
# and PPP_PATH is overwritten during detection.
AS_IF([test "x$with_ppp" = "xyes" -a "x$with_pppd" = "xyes"], [
   with_ppp="no"
])

AC_PATH_PROG(RESOLVCONF_PATH, [resolvconf], [/sbin/resolvconf], "$PATH:/sbin:/usr/sbin")

AS_IF([test "x$with_ppp" = "xyes"], [
	AC_DEFINE(HAVE_USR_SBIN_PPP, 1)
	AC_MSG_NOTICE([HAVE_USR_SBIN_PPP... 1])
],[
	AC_DEFINE(HAVE_USR_SBIN_PPP, 0)
	AC_MSG_NOTICE([HAVE_USR_SBIN_PPP... 0])
])
AS_IF([test "x$with_pppd" = "xyes"], [
	AC_DEFINE(HAVE_USR_SBIN_PPPD, 1)
	AC_MSG_NOTICE([HAVE_USR_SBIN_PPPD... 1])
],[
	AC_DEFINE(HAVE_USR_SBIN_PPPD, 0)
	AC_MSG_NOTICE([HAVE_USR_SBIN_PPPD... 0])
])
AS_IF([test "x$enable_proc" = "xyes"], [
	AC_DEFINE(HAVE_PROC_NET_ROUTE, 1)
	AC_MSG_NOTICE([HAVE_PROC_NET_ROUTE... 1])
],[
	AC_DEFINE(HAVE_PROC_NET_ROUTE, 0)
	AC_MSG_NOTICE([HAVE_PROC_NET_ROUTE... 0])
])

AC_SUBST(PPP_PATH)
AC_MSG_NOTICE([PPP_PATH...] $PPP_PATH)

AC_SUBST(NETSTAT_PATH)
AS_IF([test "x$NETSTAT_PATH" != "x" ], [
    AC_MSG_NOTICE([NETSTAT_PATH...] $NETSTAT_PATH)
])

AC_SUBST(RESOLVCONF_PATH)
AS_IF([test "x$RESOLVCONF_PATH" != "x" ], [
    AC_MSG_NOTICE([RESOLVCONF_PATH...] $RESOLVCONF_PATH)
])

AC_CONFIG_COMMANDS([timestamp], [touch src/.dirstamp])
AC_OUTPUT(Makefile)
