/*
 *  Copyright (c) 2015 Davíð Steinn Geirsson
 *  Copyright (c) 2019 Lubomir Rintel <lkundrak@v3.sk>
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
 */

#include "userinput.h"
#include "log.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *uri_escape(const char *string)
{
	char *escaped = NULL;
	int allocated_len = 0;
	int real_len = 0;

	while (*string != '\0') {
		if (allocated_len < real_len + 4) {
			allocated_len += 16;
			char *tmp = realloc(escaped, allocated_len);

			// bail out if realloc fails
			if (tmp == NULL) {
				free(escaped);
				escaped = NULL;
				break;
			}
			escaped = tmp;
		}
		if (isalnum(*string) || *string == '-' || *string == '_' ||
		    *string == '.' || *string == '~')
			escaped[real_len++] = *string;
		else
			real_len += sprintf(&escaped[real_len], "%%%02X",
			                    (unsigned char)*string);
		string++;
	}
	if (escaped)
		escaped[real_len] = '\0';

	return escaped;
}

static char *uri_unescape(const char *string)
{
	int escaped_len = strlen(string) + 1;
	char *unescaped = malloc(escaped_len);
	int real_len = 0;
	int i = 0;

	// bail out if malloc fails
	if (unescaped == NULL)
		return NULL;

	while (string[i]) {
		if (string[i] == '%' && isxdigit(string[i + 1])
		    && isxdigit(string[i + 2])) {
			sscanf(&string[i + 1], "%02hhx",
			       (unsigned char *)&unescaped[real_len]);
			i += 3;
		} else if (string[i] == '%' && string[i + 1] == '%') {
			unescaped[real_len] = '%';
			i += 2;
		} else {
			unescaped[real_len] = string[i];
			i += 1;
		}
		real_len++;
	}
	unescaped[real_len] = '\0';

	return unescaped;
}

static int pinentry_read(int from, char **retstr)
{
	int bufsiz = 0;
	char *buf = NULL, *saveptr = NULL;
	int len = 0;
	int ret;

	do {
		if (bufsiz - len < 64) {
			bufsiz += 64;
			char *tmp = realloc(buf, bufsiz);

			// bail out if realloc fails
			if (tmp == NULL) {
				if (retstr)
					*retstr = strdup(strerror(errno));
				free(buf);
				return -1;
			}
			buf = tmp;
			buf[bufsiz-1] = '\0';
		}

		ret = read(from, &buf[len], bufsiz - len);
		if (ret == -1) {
			free(buf);
			if (retstr)
				*retstr = strdup(strerror(errno));
			return -1;
		}
		if (ret == 0) {
			free(buf);
			if (retstr)
				*retstr = strdup("Short read");
			return -1;
		}
		len += ret;
	} while (buf[len - 1] != '\n');
	// overwrite the newline with a null character
	buf[len - 1] = '\0';

	if (strcmp(buf, "OK") == 0 || strncmp(buf, "OK ", 3) == 0
	    || strncmp(buf, "D ", 2) == 0) {
		if (retstr) {
			*retstr = strchr(buf, ' ');
			*retstr = *retstr ? strtok_r(*retstr, "\n", &saveptr) : NULL;
			*retstr = *retstr ? uri_unescape(*retstr + 1) : NULL;
		}
		free(buf);
		return 0;
	}

	if (strncmp(buf, "ERR ", 4) == 0 || strncmp(buf, "S ERROR", 7) == 0) {
		ret = strtol(&buf[4], NULL, 10);
		if (!ret)
			ret = -1;
		if (retstr) {
			*retstr = strchr(&buf[4], ' ');
			*retstr = *retstr ? uri_unescape(*retstr + 1) : NULL;
		}
		free(buf);
		return ret;
	}

	free(buf);
	if (retstr)
		*retstr = strdup("pinentry protocol error");

	return -1;
}

#ifndef HAVE_VDPRINTF
static int vdprintf(int fd, const char *format, va_list ap)
{
	char buffer[2049];
	int size = vsnprintf(buffer, sizeof(buffer), format, ap);

	if (size < 0)
		return size;

	if (size >= sizeof(buffer)) // silently discard beyond the buffer size
		size = sizeof(buffer) - 1;

	return (int) write(fd, buffer, size);
}
#endif

static int pinentry_exchange(int to, int from, char **retstr,
                             const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	if (vdprintf(to, format, ap) == 0) {
		if (retstr)
			*retstr = strdup(strerror(errno));
		va_end(ap);
		return -1;
	}
	va_end(ap);

	return pinentry_read(from, retstr);
}

static void pinentry_read_password(const char *pinentry, const char *hint,
                                   const char *prompt, char *pass, size_t len)
{
	int from_pinentry[2];
	int to_pinentry[2];
	int pinentry_status;
	pid_t pinentry_pid;
	char *escaped;
	char *retstr;
	int ret;

	*pass = '\0';

	if (pipe(from_pinentry) == -1) {
		perror("pipe");
		return;
	}

	if (pipe(to_pinentry) == -1) {
		perror("pipe");
		close(from_pinentry[0]);
		close(from_pinentry[1]);
		return;
	}

	pinentry_pid = fork();
	if (pinentry_pid == -1) {
		perror("fork");
		return;
	}

	if (pinentry_pid == 0) {
		close(to_pinentry[1]);
		if (dup2(to_pinentry[0], STDIN_FILENO) == -1) {
			perror("dup2");
			exit(EXIT_FAILURE);
		}
		close(to_pinentry[0]);

		close(from_pinentry[0]);
		if (dup2(from_pinentry[1], STDOUT_FILENO) == -1) {
			perror("dup2");
			exit(EXIT_FAILURE);
		}
		close(from_pinentry[1]);

		execlp(pinentry, pinentry, NULL);
		perror(pinentry);
		exit(EXIT_FAILURE);
	}

	close(to_pinentry[0]);
	close(from_pinentry[1]);

	ret = pinentry_read(from_pinentry[0], &retstr);
	if (ret)
		log_error("Error: %s\n", retstr);
	free(retstr);
	retstr = NULL;
	if (ret)
		goto out;

	ret = pinentry_exchange(to_pinentry[1], from_pinentry[0], &retstr,
	                        "SETTITLE %s\n", "VPN Password");
	if (ret)
		log_error("Failed to set title: %s\n", retstr);
	free(retstr);
	retstr = NULL;
	if (ret)
		goto out;

	ret = pinentry_exchange(to_pinentry[1], from_pinentry[0], &retstr,
	                        "SETDESC %s\n", "VPN Requires a Password");
	if (ret)
		log_error("Failed to set description: %s\n", retstr);
	free(retstr);
	retstr = NULL;
	if (ret)
		goto out;

	escaped = uri_escape(hint);
	ret = pinentry_exchange(to_pinentry[1], from_pinentry[0], NULL,
	                        "SETKEYINFO %s\n", escaped);
	if (ret)
		log_error("Failed to set keyinfo\n");
	free(escaped);
	escaped = NULL;
	if (ret)
		goto out;

	escaped = uri_escape(prompt);
	ret = pinentry_exchange(to_pinentry[1], from_pinentry[0], &retstr,
	                        "SETPROMPT %s\n", escaped);
	free(escaped);
	escaped = NULL;
	if (ret)
		log_error("Failed to set prompt: %s\n", retstr);
	free(retstr);
	retstr = NULL;
	if (ret)
		goto out;

	ret = pinentry_exchange(to_pinentry[1], from_pinentry[0], &retstr,
	                        "GETPIN\n");
	if (ret) {
		log_error("Failed to get PIN: %s\n", retstr);
		free(retstr);
		retstr = NULL;
		goto out;
	}

	if (retstr) {
		strncpy(pass, retstr, len);
		free(retstr);
		retstr = NULL;
	} else {
		log_error("No password given\n");
	}

out:
	close(to_pinentry[1]);
	close(from_pinentry[0]);

	if (waitpid(pinentry_pid, &pinentry_status, 0) == -1)
		perror("waitpid");
}

void read_password(const char *pinentry, const char *hint,
                   const char *prompt, char *pass, size_t len)
{
	int masked = 0;
	struct termios oldt, newt;
	int i;

	if (pinentry && *pinentry) {
		pinentry_read_password(pinentry, hint, prompt, pass, len);
		return;
	}

	printf("%s", prompt);
	fflush(stdout);

	// Try to hide user input
	if (tcgetattr(STDIN_FILENO, &oldt) == 0) {
		newt = oldt;
		newt.c_lflag &= ~ECHO;
		tcsetattr(STDIN_FILENO, TCSANOW, &newt);
		masked = 1;
	}

	for (i = 0; i < len; i++) {
		int c = getchar();

		if (c == '\n' || c == EOF)
			break;
		pass[i] = (char) c;
	}
	pass[i] = '\0';

	if (masked)
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

	printf("\n");
}

char *read_from_stdin(size_t count)
{
	char *buf;
	char *output;
	int bytes_read;

	buf = malloc(count + 1);
	if (buf == NULL)
		return NULL;

	bytes_read = read(STDIN_FILENO, buf, count);
	if (bytes_read == -1) {
		free(buf);
		return NULL;
	}

	buf[bytes_read] = '\0';
	output = realloc(buf, bytes_read + 1);

	// Just keep using the larger buffer if realloc() fails.
	return output ? output : buf;
}
