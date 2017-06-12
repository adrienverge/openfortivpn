#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([openfortivpn], [1.3.1])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([foreign subdir-objects])

# Checks for programs.
AC_PROG_CC
AC_GNU_SOURCE

AM_SILENT_RULES([yes])

AC_DEFUN([OPENSSL_DEVEL],
[
	dnl
	dnl Set up configure script macros
	dnl
	AC_ARG_WITH(openssl,
		[  --with-openssl=<path>     path containing OpenSSL header and library subdirs],
		[OPENSSL_lib_check="$with_openssl/lib64 $with_openssl/lib $with_openssl/lib64/openssl $with_openssl/lib/openssl"
		  OPENSSL_inc_check="$with_openssl/include $with_openssl/include/openssl"],
		[OPENSSL_lib_check="/usr/local/openssl/lib64 /usr/local/openssl/lib /usr/local/lib64/openssl /usr/local/lib/openssl /opt/openssl/lib64 /opt/openssl/lib /usr/local/opt/openssl/lib64 /usr/local/opt/openssl/lib /usr/lib64/openssl /usr/lib/openssl /usr/local/lib64 /usr/local/lib /usr/lib64 /usr/lib"
		  OPENSSL_inc_check="/usr/local/openssl/include /usr/local/include/openssl /opt/openssl/include /usr/local/opt/openssl/include /usr/local/include/openssl /usr/local/include /usr/include/openssl /usr/include"])
	AC_ARG_WITH(openssl-lib,
		[  --with-openssl-lib=<path> directory path of OpenSSL library],
		[OPENSSL_lib_check="$with_openssl_lib $with_openssl_lib/lib64 $with_openssl_lib/lib $with_openssl_lib/lib64/ssl $with_openssl_lib/lib/ssl"])
	AC_ARG_WITH(openssl-include,
		[  --with-openssl-include=<path> directory path of OpenSSL headers],
		[OPENSSL_inc_check="$with_openssl_include $with_openssl_include/include $with_openssl_include/include/ssl"])

	dnl
	dnl Look for OpenSSL library
	dnl
	AC_CACHE_CHECK([for OpenSSL library location], [ac_cv_openssl_lib],
	[
		for dir in $OPENSSL_lib_check
		do
			if test -d "$dir" && \
				( test -f "$dir/libssl.so" ||
				  test -f "$dir/libssl.a" )
			then
				ac_cv_openssl_lib=$dir
				break
			fi
		done

		if test -z "$ac_cv_openssl_lib"
		then
			AC_MSG_ERROR([Didn't find the OpenSSL library dir in '$OPENSSL_lib_check'])
		fi

		case "$ac_cv_openssl_lib" in
			/* ) ;;
			* )  AC_MSG_ERROR([The OpenSSL library directory ($ac_cv_openssl_lib) must be an absolute path.]) ;;
		esac
	])
	AC_SUBST([OPENSSL_LIB_DIR],[$ac_cv_openssl_lib])

	dnl
	dnl Look for OpenSSL header file directory
	dnl
	AC_CACHE_CHECK([for OpenSSL include path], [ac_cv_openssl_inc],
	[
		for dir in $OPENSSL_inc_check
		do
			if test -d "$dir" && test -f "$dir/openssl/ssl.h"
			then
				ac_cv_openssl_inc=$dir
				break
			fi
		done

		if test -z "$ac_cv_openssl_inc"
		then
			AC_MSG_ERROR([Didn't find the OpenSSL header dir in '$OPENSSL_inc_check'])
		fi

		case "$ac_cv_openssl_inc" in
			/* ) ;;
			* )  AC_MSG_ERROR([The OpenSSL header directory ($ac_cv_openssl_inc) must be an absolute path.]) ;;
		esac
	])
	AC_SUBST([OPENSSL_INC_DIR],[$ac_cv_openssl_inc])

	dnl
	dnl Now check that the above checks resulted in -I and -L flags that
	dnl let us build actual programs against OpenSSL.
	dnl
	case "$ac_cv_openssl_lib" in
	  /usr/lib) ;;
	  *) LDFLAGS="$LDFLAGS -L${ac_cv_openssl_lib}" ;;
	esac
	CPPFLAGS="$CPPFLAGS -I${ac_cv_openssl_inc}"
	AC_MSG_CHECKING([that we can build OpenSSL programs])
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM([#include <openssl/ssl.h>],
			[SSL_library_init()])],
		AC_MSG_RESULT([yes]),
		AC_MSG_ERROR([no]))
]) dnl End OPENSSL_DEVEL


# run it:
OPENSSL_DEVEL

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
