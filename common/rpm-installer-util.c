/*
 * rpm-installer
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
 * Jaeho Lee <jaeho81.lee@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <string.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>
#include <stdio.h>
#include <ctype.h>		/* for isspace () */
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <syslog.h>
#include "rpm-installer-util.h"

#include <dlog.h>

#define LOG_TAG				"rpminstaller"

int logging = 0x0004;
#ifdef LOG_IN_FILE
#define RPM_INSTALLER_LOG_FILE "/tmp/rpm-installer"
FILE *logfile = NULL;
#endif

/**
 * This is intended to be a faster splitter, it does not use dynamic
 *  memories. Input is changed to insert nulls at each token location.
 */
int _ri_tok_split_string(char tok, char *input, char **list,
			 unsigned long listmax)
{
	/* Strip any leading spaces */
	char *start = input;
	char *stop = start + strlen(start);
	for (; *start != 0 && isspace(*start) != 0; start++) ;

	unsigned long count = 0;
	char *pos = start;
	while (pos != stop) {
		/* Skip to the next Token */
		for (; pos != stop && *pos != tok; pos++) ;

		/* Back remove spaces */
		char *end = pos;
		for (;
		     end > start && (end[-1] == tok || isspace(end[-1]) != 0);
		     end--) ;

		*end = 0;

		list[count++] = start;
		if (count >= listmax) {
			list[count - 1] = 0;
			return -1;
		}
		/* Advance pos */
		for (;
		     pos != stop && (*pos == tok || isspace(*pos) != 0
				     || *pos == 0); pos++) ;

		start = pos;
	}

	list[count] = 0;
	return 0;
}

void _d_msg_init(char *program)
{
	if (logging == 0)
		return;

#ifdef LOG_IN_FILE
	char logfilename[64] = { 0, };
	char buffer[256] = { 0 };
	snprintf(logfilename, 64, "%s-%s", RPM_INSTALLER_LOG_FILE, program);
	logfile = fopen(logfilename, "a+");

	if (logfile == NULL)
		printf("Error opening log file\n");
	else {
		snprintf(buffer, 64, "\nLog File %s Created", logfilename);
		fwrite(buffer, sizeof(char), strlen(buffer), logfile);
		snprintf(buffer, 64, "\nLog Started\n");
		fwrite(buffer, sizeof(char), strlen(buffer), logfile);
	}
#endif
}

void _d_msg_deinit()
{
	if (logging == 0)
		return;

#ifdef LOG_IN_FILE
	if (logfile != NULL)
		fclose(logfile);
#endif
}

void _print_msg(int type, int exetype, char *format, ...)
{
	char buffer[1024] = { 0 };
	char tbuffer[1024] = { 0 };
	int nbuffer = 0;
	va_list args;
	va_start(args, format);
	nbuffer = vsnprintf(tbuffer, 1024, format, args);
	va_end(args);

	switch (type) {
	case DEBUG_ERR:
		LOG(LOG_ERROR, LOG_TAG, "%s", tbuffer);
		break;
	case DEBUG_RESULT:
		LOG(LOG_WARN, LOG_TAG, "%s", tbuffer);
		break;
	case DEBUG_INFO:
		LOG(LOG_DEBUG, LOG_TAG, "%s", tbuffer);
	default:
		break;
	}

	if (logging == 0)
		return;

	if (DEBUG_ERR == (logging & type)) {
		nbuffer = snprintf(buffer, 1024, "ERROR:%s", tbuffer);
		vfprintf(stderr, format, args);
	} else if (DEBUG_INFO == (logging & type)) {
		nbuffer = snprintf(buffer, 1024, "INFO:%s", tbuffer);
		vfprintf(stdout, format, args);
	} else if (DEBUG_RESULT == (logging & type)) {
		nbuffer = snprintf(buffer, 1024, "RESULT:%s", tbuffer);
		vfprintf(stdout, format, args);
	} else {
		return;
	}

#ifdef LOG_IN_FILE
	if (logfile != NULL)
		fwrite(buffer, sizeof(char), strlen(buffer), logfile);
#endif				/*LOG_IN_FILE */
}

/* Like system(3), but with error messages printed if the fork fails
   or if the child process dies due to an uncaught signal. Also, the
   return value is a bit simpler:

   -1 if there was any problem
   Otherwise, the 8-bit return value of the program ala WEXITSTATUS
   as defined in <sys/wait.h>.
   */
int _ri_xsystem(const char *argv[])
{
	int status;
	pid_t pid;
	pid = vfork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return -1;
	case 0:
		/* child */
		execvp(argv[0], (char *const *)argv);
		_exit(-1);
	default:
		/* parent */
		break;
	}

	_d_msg(DEBUG_INFO, "parent\n");
	if (waitpid(pid, &status, 0) == -1) {
		perror("waitpid failed");
		return -1;
	}

	if (WIFSIGNALED(status)) {
		perror("signal");
		return -1;
	}

	if (!WIFEXITED(status)) {
		/* shouldn't happen */
		perror("should not happen");
		return -1;
	}

	return WEXITSTATUS(status);
}

char *_ri_substring(const char *str, size_t begin, size_t len)
{
	if (str == 0 || strlen(str) == 0 || strlen(str) < (begin + len))
		return 0;
	return strndup(str + begin, len);
}

void _ri_error_no_to_string(int errnumber, char **errstr)
{
	if (errstr == NULL)
		return;
	switch (errnumber) {
	case RPM_INSTALLER_SUCCESS:
		*errstr = RPM_INSTALLER_SUCCESS_STR;
		break;
	case RPM_INSTALLER_ERR_WRONG_PARAM:
		*errstr = RPM_INSTALLER_ERR_WRONG_PARAM_STR;
		break;
	case RPM_INSTALLER_ERR_DBUS_PROBLEM:
		*errstr = RPM_INSTALLER_ERR_DBUS_PROBLEM_STR;
		break;
	case RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY:
		*errstr = RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY_STR;
		break;
	case RPM_INSTALLER_ERR_PACKAGE_EXIST:
		*errstr = RPM_INSTALLER_ERR_PACKAGE_EXIST_STR;
		break;
	case RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED:
		*errstr = RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED_STR;
		break;
	case RPM_INSTALLER_ERR_RESOURCE_BUSY:
		*errstr = RPM_INSTALLER_ERR_RESOURCE_BUSY_STR;
		break;
	case RPM_INSTALLER_ERR_UNKNOWN:
		*errstr = RPM_INSTALLER_ERR_UNKNOWN_STR;
		break;
	case RPM_INSTALLER_ERR_PKG_NOT_FOUND:
		*errstr = RPM_INSTALLER_ERR_PKG_NOT_FOUND_STR;
		break;
	case RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION:
		*errstr = RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION_STR;
		break;
	case RPM_INSTALLER_ERR_NO_RPM_FILE:
		*errstr = RPM_INSTALLER_ERR_NO_RPM_FILE_STR;
		break;
	case RPM_INSTALLER_ERR_DB_ACCESS_FAILED:
		*errstr = RPM_INSTALLER_ERR_DB_ACCESS_FAILED_STR;
		break;
	case RPM_INSTALLER_ERR_RPM_OPERATION_FAILED:
		*errstr = RPM_INSTALLER_ERR_RPM_OPERATION_FAILED_STR;
		break;
	case RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED:
		*errstr = RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED_STR;
		break;
	case RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS:
		*errstr = RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS_STR;
		break;
	case RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED:
		*errstr = RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED_STR;
		break;
	case RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED:
		*errstr = RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED_STR;
		break;
	case RPM_INSTALLER_ERR_CLEAR_DATA_FAILED:
		*errstr = RPM_INSTALLER_ERR_CLEAR_DATA_FAILED_STR;
		break;
	case RPM_INSTALLER_ERR_INTERNAL:
		*errstr = RPM_INSTALLER_ERR_INTERNAL_STR;
		break;
	case RPM_INSTALLER_ERR_NO_MANIFEST:
		*errstr = RPM_INSTALLER_ERR_NO_MANIFEST_STR;
		break;
	case RPM_INSTALLER_ERR_INVALID_MANIFEST:
		*errstr = RPM_INSTALLER_ERR_INVALID_MANIFEST_STR;
		break;
	default:
		*errstr = RPM_INSTALLER_ERR_UNKNOWN_STR;
		break;
	}
}

int _ri_string_to_error_no(char *errstr)
{
	int errnumber = RPM_INSTALLER_ERR_UNKNOWN;
	if (errstr == NULL)
		return errnumber;

	if (strcmp(errstr, RPM_INSTALLER_SUCCESS_STR) == 0)
		errnumber = RPM_INSTALLER_SUCCESS;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_WRONG_PARAM_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_WRONG_PARAM;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_DBUS_PROBLEM_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_DBUS_PROBLEM;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_EXIST_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_EXIST;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED_STR)
		 == 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_RESOURCE_BUSY_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_RESOURCE_BUSY;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_UNKNOWN_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_UNKNOWN;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PKG_NOT_FOUND_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PKG_NOT_FOUND;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION_STR) ==
		 0)
		errnumber = RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_NO_RPM_FILE_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_NO_RPM_FILE;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_DB_ACCESS_FAILED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_DB_ACCESS_FAILED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_RPM_OPERATION_FAILED_STR)
		 == 0)
		errnumber = RPM_INSTALLER_ERR_RPM_OPERATION_FAILED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED_STR) ==
		 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS_STR) ==
		 0)
		errnumber = RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_CLEAR_DATA_FAILED_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_CLEAR_DATA_FAILED;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_INTERNAL_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_INTERNAL;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_NO_MANIFEST_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_NO_MANIFEST;
	else if (strcmp(errstr, RPM_INSTALLER_ERR_INVALID_MANIFEST_STR) == 0)
		errnumber = RPM_INSTALLER_ERR_INVALID_MANIFEST;
	else
		_d_msg(DEBUG_ERR, "Unsupported Error\n");
	return errnumber;
}
