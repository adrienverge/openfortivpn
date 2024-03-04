#					       -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([openfortivpn], [1.21.0])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([foreign subdir-objects])

# Checks for programs.
AC_PROG_CC
AC_PROG_MKDIR_P
AC_PROG_SED
AC_PROG_INSTALL
AC_USE_SYSTEM_EXTENSIONS
m4_ifndef([PKG_PROG_PKG_CONFIG], [m4_fatal([Please install pkg-config.])])
PKG_PROG_PKG_CONFIG

REVISION=""
AS_IF([test -d .git], [
	AC_PATH_PROG(GIT, [git], [""], "$PATH:/sbin:/usr/sbin")
	AS_IF([test "x$GIT" != "x"], [
		REVISION=`$GIT describe --tags | sed -e 's/-/+git/;y/-/./'`
	])
])
AS_IF([test "x$REVISION" = "x"], [
	REVISION="unavailable"
])

AC_SUBST(REVISION)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for libraries.
PKG_CHECK_MODULES(OPENSSL, [libssl >= 1.0.2 libcrypto >= 1.0.2], [], [AC_MSG_ERROR([Cannot find OpenSSL 1.0.2 or higher.])])
AC_CHECK_LIB([pthread], [pthread_create], [], [AC_MSG_ERROR([Cannot find libpthread.])])
AC_CHECK_LIB([util], [forkpty], [], [AC_MSG_ERROR([Cannot find libutil.])])
PKG_CHECK_MODULES(LIBSYSTEMD, [libsystemd], [AC_DEFINE(HAVE_SYSTEMD)], [AC_MSG_RESULT([libsystemd not present])])

# we assume presence of the following C standard headers
# and omit them in the following header checks
#
# assert.h
# ctype.h
# errno.h
# limits.h
# signal.h
# stdarg.h
# stddef.h
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
strings.h \
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
linux/if_ppp.h \
linux/if_tun.h \
mach/mach.h \
pty.h \
semaphore.h \
util.h \
])

# Checks for optional header files with prerequisites of other headers.
AC_CHECK_HEADERS([net/if_var.h],[],[],[#include <net/if.h>])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([struct termios], [], [], [#include <termios.h>])

# Checks for library functions.
AC_CHECK_FUNCS([ \
access \
close \
connect \
execv \
_exit \
fcntl \
fileno \
forkpty \
freeaddrinfo \
freeifaddrs \
gai_strerror \
getaddrinfo \
geteuid \
getifaddrs \
getopt_long \
htons \
inet_addr \
inet_ntoa \
ioctl \
isatty \
memmem \
ntohs \
open \
openlog \
pclose \
popen \
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
read \
select \
sem_destroy \
sem_init \
sem_post \
sem_wait \
setenv \
setsockopt \
sigaddset \
sigemptyset \
sleep \
socket \
strcasecmp \
strdup \
strncasecmp \
strsignal \
strtok_r \
syslog \
tcgetattr \
tcsetattr \
usleep \
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
AS_IF([test "x$with_rt_dst" = "x"], [
AC_MSG_CHECKING(whether rtentry is available and has rt_dst)
AC_LANG(C)
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
], AC_MSG_RESULT(no))
])

NETSTAT_PATH=""
PPP_PATH=""
RESOLVCONF_PATH=""

# prepare possibility to override default locations
AC_ARG_WITH([netstat],
	AS_HELP_STRING([--with-netstat],
		       [set the path to the netstat executable on MacOS or FreeBSD]),
	NETSTAT_PATH="$withval"
)
# this is for the pppd daemon executable
AC_ARG_WITH([pppd],
	AS_HELP_STRING([--with-pppd],
		       [set the path to the pppd daemon executable]),
	AS_IF([test ! "x$with_pppd" = "xno" -a ! "x$with_pppd" = "xyes"],[
		PPP_PATH="$withval"
		with_pppd="yes"
		with_ppp="no"
	])
)
# support pppd < 2.5.0 by default instead of pppd >= 2.5.0
AC_ARG_ENABLE([legacy_pppd],
	AS_HELP_STRING([--enable-legacy-pppd],
	               [support pppd < 2.5.0 by default instead of pppd >= 2.5.0]))
# this is for the ppp user space client on FreeBSD
AC_ARG_WITH([ppp],
	AS_HELP_STRING([--with-ppp],
		       [set the path to the ppp userspace client on FreeBSD]),
	AS_IF([test ! "x$with_ppp" = "xno" -a ! "x$with_ppp" = "xyes"],[
		PPP_PATH="$withval"
		with_ppp="yes"
		with_pppd="no"
	])
)

# override for /proc/net/route detection
AC_ARG_ENABLE([proc],
	AS_HELP_STRING([--enable-proc],
		       [enable route manipulations directly via /proc/net/route \
			when cross-compiling, use --disable-proc for the opposite]))

# check for netstat if not cross-compiling
AS_IF([test "x$enable_proc" = "x"], [
	AC_CHECK_FILE([/proc/net/route],[
		AS_IF([test "x$enable_proc" = "x"], [
			enable_proc="yes"
		])
	],[
		AS_IF([test "x$NETSTAT_PATH" = "x"], [
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

# check for ppp if not specified
AC_PATH_PROG(PPP, [ppp], [/usr/sbin/ppp], "$PATH:/sbin:/usr/sbin")
AS_IF([test "x$PPP_PATH" = "x"], [
	AC_CHECK_FILE([$PPP], [
		AS_IF([test "x$PPP_PATH" = "x"], [
			PPP_PATH="$PPP"
		])
		AS_IF([test "x$with_ppp" = "x"], [
			with_ppp="yes"
		])
	],[])
])
# check for pppd if not specified
AC_PATH_PROG(PPPD, [pppd], [/usr/sbin/pppd], "$PATH:/sbin:/usr/sbin")
AS_IF([test "x$PPP_PATH" = "x"], [
	AC_CHECK_FILE([$PPPD], [
		AS_IF([test "x$PPP_PATH" = "x"], [
			PPP_PATH="$PPPD"
		])
		AS_IF([test "x$with_pppd" = "x"], [
			with_pppd="yes"
		])
	],[])
])
# when neither ppp nor pppd are enabled fall back to a sensible choice for the platform
AS_IF([test "x$with_ppp" = "x" -a "x$with_pppd" = "x"], [
	AS_IF([test "x$(uname)" = "xFreeBSD"], [
		with_ppp="yes"
		PPP_PATH="/usr/sbin/ppp"
	], [
		with_pppd="yes"
		PPP_PATH="/usr/sbin/pppd"
	])
])
# when both are enabled, give pppd the higher priority (we can only use one of them)
AS_IF([test "x$with_ppp" = "xyes" -a "x$with_pppd" = "xyes"], [
	with_ppp="no"
])
# replace empty settings with "no"
AS_IF([test "x$with_pppd" = "x"], [
	with_pppd="no"
])
AS_IF([test "x$with_ppp" = "x"], [
	with_ppp="no"
])

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
AS_IF([test "x$enable_legacy_pppd" = "xyes"], [
	AC_DEFINE(LEGACY_PPPD, 1)
	AC_MSG_NOTICE([LEGACY_PPPD... 1])
],[
	AC_DEFINE(LEGACY_PPPD, 0)
	AC_MSG_NOTICE([LEGACY_PPPD... 0])
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
AS_IF([test "x$NETSTAT_PATH" != "x"], [
	AC_MSG_NOTICE([NETSTAT_PATH...] $NETSTAT_PATH)
])

# use resolvconf if present
AC_PATH_PROG(RESOLVCONF_PATH, [resolvconf], [DISABLED], "$PATH:/sbin:/usr/sbin")

# allow override at configure time
AC_ARG_WITH([resolvconf],
	AS_HELP_STRING([--with-resolvconf],
	               [set the path to the resolvconf executable, \
	                with special value "DISABLED" fully disabling \
	                resolvconf support at build-time]),
	RESOLVCONF_PATH="$withval"
)

AC_SUBST(RESOLVCONF_PATH)
AS_IF([test "x$RESOLVCONF_PATH" != "x"], [
	AC_MSG_NOTICE([RESOLVCONF_PATH...] $RESOLVCONF_PATH)
])
AS_IF([test "x$RESOLVCONF_PATH" = "xDISABLED"], [
	AC_DEFINE(HAVE_RESOLVCONF, 0)
	AC_MSG_NOTICE([HAVE_RESOLVCONF... 0])
],[
	AC_DEFINE(HAVE_RESOLVCONF, 1)
	AC_MSG_NOTICE([HAVE_RESOLVCONF... 1])
])

# the default for the --use-resolvconf runtime command line option
AC_ARG_ENABLE([resolvconf],
	AS_HELP_STRING([--enable-resolvconf],
	               [enable usage of resolvconf at runtime by default \
	                (please note that resolvconf support will still \
	                 be compiled in with --disable-resolvconf but \
	                 disabled unless explicitly enabled at runtime)]))

# Determine how resolvconf works at build-time if it is installed:
# * openresolv supports option -l that lists active configurations and returns 0
# * resolvconf in Ubuntu/Debian does not support listing but returns 99
#   if invoked without parameters
# * skip resolvectl which does not work as expected when invoked as resolveconf
AS_IF([test "x$enable_resolvconf" = "x" -a "x$RESOLVCONF_PATH" != "xDISABLED"], [
	AC_CHECK_FILE([$RESOLVCONF_PATH],[
		AS_IF([$RESOLVCONF_PATH -l >/dev/null 2>/dev/null], [
			enable_resolvconf="yes"
		],[
			AS_IF([$RESOLVCONF_PATH  >/dev/null 2>/dev/null ; test $? -eq 99], [
				enable_resolvconf="yes"
			],[
				enable_resolvconf="no"
			])
		])
	],[
		enable_resolvconf="no"
	])
])

AS_IF([test "x$enable_resolvconf" = "xyes"], [
	AC_DEFINE(USE_RESOLVCONF, 1)
	AC_MSG_NOTICE([USE_RESOLVCONF... 1])
],[
	AC_DEFINE(USE_RESOLVCONF, 0)
	AC_MSG_NOTICE([USE_RESOLVCONF... 0])
])

# install systemd service file
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
   [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
    with_systemdsystemunitdir=no],
   [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AC_MSG_NOTICE([systemdsystemunitdir... $systemdsystemunitdir])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#include <sys/types.h>
#include <sys/socket.h>
int main(int argc, char **argv){
        int ret, handle;
        handle = socket(AF_INET, SOCK_STREAM, 0);
        ret = setsockopt(handle, SOL_SOCKET, SO_BINDTODEVICE,"lo",3);
}
])], [
	AC_DEFINE(HAVE_SO_BINDTODEVICE, 1)
	AC_MSG_NOTICE([HAVE_SO_BINDTODEVICE... 1])
],[
	AC_DEFINE(HAVE_SO_BINDTODEVICE, 0)
	AC_MSG_NOTICE([HAVE_SO_BINDTODEVICE... 0])
])


AC_CONFIG_COMMANDS([timestamp], [touch src/.dirstamp])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
