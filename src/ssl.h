/*
 *  Copyright (c) 2015 Adrien Vergé
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give permission
 *  to link the code of portions of this program with the OpenSSL library under
 *  certain conditions as described in each individual source file, and
 *  distribute linked combinations including the two.
 *  You must obey the GNU General Public License in all respects for all of the
 *  code used other than OpenSSL.  If you modify file(s) with this exception,
 *  you may extend this exception to your version of the file(s), but you are
 *  not obligated to do so.  If you do not wish to do so, delete this exception
 *  statement from your version.  If you delete this exception statement from
 *  all source files in the program, then also delete it here.
 */

#ifndef OPENFORTIVPN_SSL_H
#define OPENFORTIVPN_SSL_H

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#ifdef __clang__
/*
 * Get rid of Mac OS X 10.7 and greater deprecation warnings
 * see for instance https://wiki.openssl.org/index.php/Hostname_validation
 * this pragma selectively suppresses this type of warnings in clang
 */
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#ifndef ERESTART
/*
 * ERESTART is one of the recoverable errors which might be returned.
 * However, in Mac OS X and BSD this constant is not defined in errno.h
 * so we define a dummy value here.
 */
#define ERESTART -1
#endif

#define ERR_SSL_AGAIN		 0 // deprecated
#define ERR_TLS_AGAIN		 0
#define ERR_SSL_CLOSED		-1 // deprecated
#define ERR_TLS_CLOSED		-1
#define ERR_SSL_CERT		-2 // deprecated
#define ERR_TLS_CERT		-2
#define ERR_SSL_EOF		-3 // deprecated
#define ERR_TLS_EOF		-3
#define ERR_SSL_PROTOCOL	-4 // deprecated
#define ERR_TLS_PROTOCOL	-4
#define ERR_SSL_SEE_ERRNO	-5 // deprecated
#define ERR_TLS_SEE_ERRNO	-5
#define ERR_SSL_SEE_TLSERR	-6 // deprecated
#define ERR_TLS_SEE_TLSERR	-6
#define ERR_SSL_UNKNOWN		-7 // deprecated
#define ERR_TLS_UNKNOWN		-7

static inline const char *err_ssl_str(int code)
{
	if (code == ERR_TLS_AGAIN)
		return "Try again";
	else if (code == ERR_TLS_CLOSED)
		return "Connection closed";
	else if (code == ERR_TLS_CERT)
		return "Want X509 lookup";
	else if (code == ERR_TLS_EOF)
		return "Protocol violation with EOF";
	else if (code == ERR_TLS_PROTOCOL)
		return "Protocol error";
	else if (code == ERR_TLS_SEE_ERRNO)
		return strerror(errno);
	else if (code == ERR_TLS_SEE_TLSERR)
		return ERR_reason_error_string(ERR_peek_last_error());
	return "unknown";
}

static inline int handle_ssl_error(SSL *ssl, int ret)
{
	int code;

	if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)
		return ERR_TLS_CLOSED;

	code = SSL_get_error(ssl, ret);
	if (code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE)
		return ERR_TLS_AGAIN; // The caller should try again

	if (code == SSL_ERROR_ZERO_RETURN)
		return ERR_TLS_CLOSED;
	if (code == SSL_ERROR_WANT_X509_LOOKUP)
		return ERR_TLS_CERT;
	if (code == SSL_ERROR_SYSCALL) {
		if (ERR_peek_last_error() != 0)
			return ERR_TLS_SEE_TLSERR;
		if (ret == 0)
			return ERR_TLS_EOF;
		if (errno == EAGAIN || errno == ERESTART || errno == EINTR)
			return ERR_TLS_AGAIN; // The caller should try again
		if (errno == EPIPE)
			return ERR_TLS_CLOSED;
		return ERR_TLS_SEE_ERRNO;
	}
	if (code == SSL_ERROR_SSL)
		return ERR_TLS_PROTOCOL;
	return ERR_TLS_UNKNOWN;
}

/*
 * Reads data from the TLS connection.
 *
 * @return  > 0            in case of success (number of bytes transferred)
 *          ERR_TLS_AGAIN  if the caller should try again
 *          < 0            in case of error
 */
static inline int safe_ssl_read(SSL *ssl, uint8_t *buf, int bufsize)
{
	int ret = SSL_read(ssl, buf, bufsize);

	return (ret > 0) ? ret : handle_ssl_error(ssl, ret);
}

/*
 * Reads all data from the TLS connection.
 *
 * @return  1    in case of success
 *          < 0  in case of error
 */
static inline int safe_ssl_read_all(SSL *ssl, uint8_t *buf, int bufsize)
{
	for (int n = 0; n < bufsize; ) {
		int ret;

		ret = safe_ssl_read(ssl, &buf[n], bufsize - n);
		if (ret == ERR_TLS_AGAIN)
			continue;
		else if (ret < 0)
			return ret;
		n += ret;
	}
	return 1;
}

/*
 * Writes data to the TLS connection.
 *
 * Since SSL_MODE_ENABLE_PARTIAL_WRITE is not set by default (see man
 * SSL_get_mode), SSL_write() will only report success once the complete chunk
 * has been written.
 *
 * @return  > 0            in case of success (number of bytes transferred)
 *          ERR_TLS_AGAIN  if the caller should try again
 *          < 0            in case of error
 */
static inline int safe_ssl_write(SSL *ssl, const uint8_t *buf, int n)
{
	int ret = SSL_write(ssl, buf, n);

	return (ret > 0) ? ret : handle_ssl_error(ssl, ret);
}

#endif
