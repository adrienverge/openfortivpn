/*
 *  Copyright (c) 2015 Davíð Steinn Geirsson
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
 *  Windows implementation of user input handling.
 *  Replaces userinput.c for Windows builds.
 */

#ifdef _WIN32

#include "userinput.h"
#include "log.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Read a password from the console with echo disabled.
 * On Windows, uses SetConsoleMode to disable ENABLE_ECHO_INPUT.
 */
static void console_read_password(const char *prompt, char *pass, size_t len)
{
	HANDLE hStdin;
	DWORD mode, chars_read;
	size_t pos = 0;
	int is_console;

	fputs(prompt, stderr);
	fflush(stderr);

	hStdin = GetStdHandle(STD_INPUT_HANDLE);
	if (hStdin == INVALID_HANDLE_VALUE) {
		log_error("Cannot get stdin handle.\n");
		pass[0] = '\0';
		return;
	}

	/*
	 * Detect whether stdin is a console or a pipe.
	 * When launched by the GUI with redirected stdin,
	 * GetConsoleMode fails and we must use ReadFile.
	 */
	is_console = GetConsoleMode(hStdin, &mode);

	if (is_console)
		SetConsoleMode(hStdin, mode & ~(ENABLE_ECHO_INPUT));

	while (pos < len - 1) {
		char c;
		BOOL ok;

		if (is_console)
			ok = ReadConsoleA(hStdin, &c, 1, &chars_read, NULL);
		else
			ok = ReadFile(hStdin, &c, 1, &chars_read, NULL);

		if (!ok || chars_read == 0)
			break;
		if (c == '\r' || c == '\n')
			break;
		pass[pos++] = c;
	}
	pass[pos] = '\0';

	if (is_console) {
		SetConsoleMode(hStdin, mode);
		fputs("\n", stderr);
	}
}

/*
 * Read a password using pinentry (external program) or console.
 * On Windows, pinentry is launched via CreateProcess + pipes.
 */
static int pinentry_read_password(const char *pinentry, const char *hint,
                                  const char *prompt, char *pass, size_t len)
{
	HANDLE child_stdin_rd = NULL, child_stdin_wr = NULL;
	HANDLE child_stdout_rd = NULL, child_stdout_wr = NULL;
	SECURITY_ATTRIBUTES sa;
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	char cmd_buf[1024];
	char read_buf[4096];
	DWORD bytes_read, bytes_written;
	BOOL success;

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	/* Create pipes for child process stdin/stdout */
	if (!CreatePipe(&child_stdin_rd, &child_stdin_wr, &sa, 0))
		return -1;
	if (!CreatePipe(&child_stdout_rd, &child_stdout_wr, &sa, 0)) {
		CloseHandle(child_stdin_rd);
		CloseHandle(child_stdin_wr);
		return -1;
	}

	/* Ensure our ends of the pipes are not inherited */
	SetHandleInformation(child_stdin_wr, HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation(child_stdout_rd, HANDLE_FLAG_INHERIT, 0);

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.hStdInput = child_stdin_rd;
	si.hStdOutput = child_stdout_wr;
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	si.dwFlags = STARTF_USESTDHANDLES;

	memset(&pi, 0, sizeof(pi));

	/* Launch pinentry */
	if (!CreateProcessA(NULL, (LPSTR)pinentry, NULL, NULL, TRUE,
	                    0, NULL, NULL, &si, &pi)) {
		log_error("Failed to launch pinentry: %s (error %lu)\n",
		          pinentry, GetLastError());
		CloseHandle(child_stdin_rd);
		CloseHandle(child_stdin_wr);
		CloseHandle(child_stdout_rd);
		CloseHandle(child_stdout_wr);
		return -1;
	}

	/* Close child-side handles */
	CloseHandle(child_stdin_rd);
	CloseHandle(child_stdout_wr);

	/* Read initial greeting */
	ReadFile(child_stdout_rd, read_buf, sizeof(read_buf) - 1,
	         &bytes_read, NULL);

	/* Send SETPROMPT */
	snprintf(cmd_buf, sizeof(cmd_buf), "SETPROMPT %s\n", prompt);
	WriteFile(child_stdin_wr, cmd_buf, (DWORD)strlen(cmd_buf),
	          &bytes_written, NULL);
	ReadFile(child_stdout_rd, read_buf, sizeof(read_buf) - 1,
	         &bytes_read, NULL);

	/* Send SETDESC */
	snprintf(cmd_buf, sizeof(cmd_buf), "SETDESC Enter VPN password\n");
	WriteFile(child_stdin_wr, cmd_buf, (DWORD)strlen(cmd_buf),
	          &bytes_written, NULL);
	ReadFile(child_stdout_rd, read_buf, sizeof(read_buf) - 1,
	         &bytes_read, NULL);

	/* Send GETPIN */
	snprintf(cmd_buf, sizeof(cmd_buf), "GETPIN\n");
	WriteFile(child_stdin_wr, cmd_buf, (DWORD)strlen(cmd_buf),
	          &bytes_written, NULL);

	success = ReadFile(child_stdout_rd, read_buf, sizeof(read_buf) - 1,
	                   &bytes_read, NULL);
	if (success && bytes_read > 0) {
		read_buf[bytes_read] = '\0';
		/* Response should be "D <password>\n" */
		if (read_buf[0] == 'D' && read_buf[1] == ' ') {
			char *nl = strchr(&read_buf[2], '\n');

			if (nl)
				*nl = '\0';
			strncpy(pass, &read_buf[2], len - 1);
			pass[len - 1] = '\0';
		}
	}

	/* Send BYE */
	snprintf(cmd_buf, sizeof(cmd_buf), "BYE\n");
	WriteFile(child_stdin_wr, cmd_buf, (DWORD)strlen(cmd_buf),
	          &bytes_written, NULL);

	CloseHandle(child_stdin_wr);
	CloseHandle(child_stdout_rd);

	WaitForSingleObject(pi.hProcess, 5000);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return pass[0] ? 0 : -1;
}

void read_password(const char *pinentry, const char *hint,
                   const char *prompt, char *pass, size_t len)
{
	if (pinentry) {
		if (pinentry_read_password(pinentry, hint, prompt,
		                           pass, len) == 0)
			return;
		log_warn("Pinentry failed, falling back to console.\n");
	}

	console_read_password(prompt, pass, len);
}

char *read_from_stdin(size_t count)
{
	char *buf;
	HANDLE hStdin;
	DWORD bytes_read;

	buf = malloc(count + 1);
	if (!buf)
		return NULL;

	hStdin = GetStdHandle(STD_INPUT_HANDLE);
	if (hStdin == INVALID_HANDLE_VALUE) {
		free(buf);
		return NULL;
	}

	if (!ReadFile(hStdin, buf, (DWORD)count, &bytes_read, NULL)) {
		free(buf);
		return NULL;
	}

	buf[bytes_read] = '\0';

	/* Strip trailing newline */
	while (bytes_read > 0 &&
	       (buf[bytes_read - 1] == '\n' || buf[bytes_read - 1] == '\r'))
		buf[--bytes_read] = '\0';

	return buf;
}

#endif /* _WIN32 */
