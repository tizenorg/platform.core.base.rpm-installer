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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define __USE_GNU
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>		/* for isspace () */
#include <pkgmgr_parser.h>

#include "rpm-installer-util.h"
#include "rpm-installer.h"
#include "rpm-frontend.h"

#define PRE_CHECK_FOR_MANIFEST
#define INSTALL_SCRIPT		"/usr/bin/install_rpm_package.sh"
#define UNINSTALL_SCRIPT	"/usr/bin/uninstall_rpm_package.sh"
#define UPGRADE_SCRIPT	"/usr/bin/upgrade_rpm_package.sh"
#define RPM2CPIO	"/usr/bin/rpm2cpio"

enum rpm_request_type {
	INSTALL_REQ,
	UNINSTALL_REQ,
	UPGRADE_REQ,
};

typedef enum rpm_request_type rpm_request_type;
extern char *gpkgname;

static int __rpm_xsystem(const char *argv[]);
static void __rpm_process_line(char *line);
static void __rpm_perform_read(int fd);

static void __rpm_process_line(char *line)
{
	char *tok = NULL;
	tok = strtok(line, " ");
	if (tok) {
		if (!strncmp(tok, "%%", 2)) {
			tok = strtok(NULL, " ");
			if (tok) {
				_d_msg(DEBUG_INFO, "Install percentage is %s\n",
				       tok);
				_ri_broadcast_status_notification(gpkgname,
								  "install_percent",
								  tok);
				_ri_stat_cb(gpkgname, "install_percent", tok);
			}
			return;
		}
	}
	return;
}

static void __rpm_perform_read(int fd)
{
	char *buf_ptr = NULL;
	char *tmp_ptr = NULL;
	int size = 0;
	static char buffer[1024] = { 0, };
	static int buffer_position;

	size = read(fd, &buffer[buffer_position],
		    sizeof(buffer) - buffer_position);
	buffer_position += size;
	if (size <= 0)
		return;

	/* Process each line of the recieved buffer */
	buf_ptr = tmp_ptr = buffer;
	while ((tmp_ptr = (char *)memchr(buf_ptr, '\n',
					 buffer + buffer_position - buf_ptr)) !=
	       NULL) {
		*tmp_ptr = 0;
		__rpm_process_line(buf_ptr);
		/* move to next line and continue */
		buf_ptr = tmp_ptr + 1;
	}

	/*move the remaining bits at the start of the buffer
	   and update the buffer position */
	buf_ptr = (char *)memrchr(buffer, 0, buffer_position);
	if (buf_ptr == NULL)
		return;

	/* we have processed till the last \n which has now become
	   0x0. So we increase the pointer to next position */
	buf_ptr++;

	memmove(buffer, buf_ptr, buf_ptr - buffer);
	buffer_position = buffer + buffer_position - buf_ptr;
}

static int __rpm_xsystem(const char *argv[])
{
	int err = 0;
	int status = 0;
	pid_t pid;
	int pipefd[2];

	if (pipe(pipefd) == -1) {
		_d_msg(DEBUG_ERR, "pipe creation failed\n");
		return -1;
	}
	/*Read progress info via pipe */
	pid = fork();

	switch (pid) {
	case -1:
		_d_msg(DEBUG_ERR, "fork failed\n");
		return -1;
	case 0:
		/* child */
		{
			close(pipefd[0]);
			close(1);
			close(2);
			dup(pipefd[1]);
			dup(pipefd[1]);
			if (execvp(argv[0], (char *const *)argv) == -1) {
				_d_msg(DEBUG_ERR, "execvp failed\n");
			}
			_exit(100);
		}
	default:
		/* parent */
		break;
	}

	close(pipefd[1]);

	while ((err = waitpid(pid, &status, WNOHANG)) != pid) {
		if (err < 0) {
			if (errno == EINTR)
				continue;
			_d_msg(DEBUG_ERR, "waitpid failed\n");
			close(pipefd[0]);
			return -1;
		}

		int select_ret;
		fd_set rfds;
		struct timespec tv;
		FD_ZERO(&rfds);
		FD_SET(pipefd[0], &rfds);
		tv.tv_sec = 1;
		tv.tv_nsec = 0;
		select_ret =
		    pselect(pipefd[0] + 1, &rfds, NULL, NULL, &tv, NULL);
		if (select_ret == 0)
			continue;

		else if (select_ret < 0 && errno == EINTR)
			continue;
		else if (select_ret < 0) {
			_d_msg(DEBUG_ERR, "select() returned error\n");
			continue;
		}
		if (FD_ISSET(pipefd[0], &rfds))
			__rpm_perform_read(pipefd[0]);
	}

	close(pipefd[0]);
	/* Check for an error code. */
	if (WIFEXITED(status) == 0 || WEXITSTATUS(status) != 0) {

		if (WIFSIGNALED(status) != 0 && WTERMSIG(status) == SIGSEGV) {
			printf
			    ("Sub-process %s received a segmentation fault. \n",
			     argv[0]);
		} else if (WIFEXITED(status) != 0) {
			printf("Sub-process %s returned an error code (%u)\n",
			       argv[0], WEXITSTATUS(status));
		} else {
			printf("Sub-process %s exited unexpectedly\n", argv[0]);
		}
	}
	return WEXITSTATUS(status);
}

int _rpm_uninstall_pkg(char *pkgname)
{
	int ret = 0;
	int err = 0;
	char buff[256] = {'\0'};
	const char *argv[] = { UNINSTALL_SCRIPT, pkgname, NULL };

#ifdef PRE_CHECK_FOR_MANIFEST
	char *manifest = NULL;
	manifest = pkgmgr_parser_get_manifest_file(pkgname);
	if (access(manifest, F_OK)) {
		_d_msg(DEBUG_ERR, "No Manifest File Found\n");
	} else {
		pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);
		if (manifest) {
			free(manifest);
			manifest = NULL;
		}
	}
#endif
	ret = __rpm_xsystem(argv);
	if (ret != 0) {
		_d_msg(DEBUG_ERR, "uninstall failed with error(%d)\n", ret);
		return ret;
	}
	/* Uninstallation Success. Remove the installation time key from vconf*/
	snprintf(buff, 256, "db/app-info/%s/installed-time", pkgname);
	err = vconf_unset(buff);
	if (err) {
		_d_msg(DEBUG_ERR, "unset installation time failed\n");
	}
	return ret;
}

int _rpm_install_pkg(char *pkgfilepath, char *installoptions)
{
	int err = 0;
	int ret = 0;
	time_t cur_time;
	char buff[256] = {'\0'};
	const char *argv[] = {
		INSTALL_SCRIPT, pkgfilepath, installoptions, NULL
	};
#ifdef PRE_CHECK_FOR_MANIFEST
	char cwd[1024] = {'\0'};
	char query[1024] = {'\0'};
	char manifest[1024] = { '\0'};
	int m_exist = 0;
	getcwd(cwd, 1024);
	if (cwd == NULL) {
		_d_msg(DEBUG_ERR, "getcwd() Failed\n");
		return -1;
	}
	_d_msg(DEBUG_ERR, "Current working directory is %s\n", cwd);
	err = chdir("/tmp");
	if (err != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed\n");
		return -1;
	}
	_d_msg(DEBUG_ERR, "Switched to /tmp\n");
	snprintf(query, 1024, "/usr/bin/rpm2cpio %s | cpio -idmv", pkgfilepath);
	_d_msg(DEBUG_INFO, "query= %s\n", query);
	system(query);
	snprintf(manifest, 1024, "/tmp/opt/share/packages/%s.xml", gpkgname);
	_d_msg(DEBUG_ERR, "Manifest name is %s\n", manifest);
	if (access(manifest, F_OK)) {
		_d_msg(DEBUG_ERR, "No rw Manifest File Found\n");

		snprintf(manifest, 1024, "/tmp/usr/share/packages/%s.xml", gpkgname);
		_d_msg(DEBUG_ERR, "Manifest ro name is %s\n", manifest);

		if (access(manifest, F_OK)) {
			_d_msg(DEBUG_ERR, "No ro Manifest File Found\n");
		} else
			m_exist = 1;
	} else
		m_exist = 1;

	_d_msg(DEBUG_ERR, "Manifest exists\n");

	err = chdir(cwd);
	if (err != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed\n");
		return -1;
	}

	if (m_exist) {
		err = pkgmgr_parser_check_manifest_validation(manifest);
		if(err < 0) {
			_d_msg(DEBUG_ERR, "Invalid manifest\n");
			return -1;
		}
	}
#endif
	err = __rpm_xsystem(argv);
	if (err != 0) {
		_d_msg(DEBUG_ERR, "install complete with error(%d)\n", err);
		return err;
	}

#ifdef PRE_CHECK_FOR_MANIFEST
	if (m_exist) {
		err = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
		if (err < 0) {
			_d_msg(DEBUG_ERR, "Parsing Manifest Failed\n");
		} else
			_d_msg(DEBUG_ERR, "Parsing Manifest Success\n");
	}
#endif
	/* Install Success. Store the installation time*/
	cur_time = time(NULL);
	snprintf(buff, 256, "db/app-info/%s/installed-time", gpkgname);
	/* The time is stored in time_t format. It can be converted to
	local time or GMT time as per the need by the apps*/
	ret = vconf_set_int(buff, cur_time);
	if(ret) {
		_d_msg(DEBUG_ERR, "setting installation time failed\n");
		vconf_unset(buff);
	}
	return err;
}

int _rpm_upgrade_pkg(char *pkgfilepath, char *installoptions)
{
	int err = 0;
	const char *argv[] = {
		UPGRADE_SCRIPT, pkgfilepath, installoptions, NULL
	};
#ifdef PRE_CHECK_FOR_MANIFEST
	char cwd[1024] = {'\0'};
	char query[1024] = {'\0'};
	char manifest[1024] = { '\0'};
	int m_exist = 0;
	getcwd(cwd, 1024);
	if (cwd == NULL) {
		_d_msg(DEBUG_ERR, "getcwd() Failed\n");
		return -1;
	}
	_d_msg(DEBUG_ERR, "Current working directory is %s\n", cwd);
	err = chdir("/tmp");
	if (err != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed\n");
		return -1;
	}
	_d_msg(DEBUG_ERR, "Switched to /tmp\n");
	snprintf(query, 1024, "/usr/bin/rpm2cpio %s | cpio -idmv", pkgfilepath);
	_d_msg(DEBUG_INFO, "query= %s\n", query);
	system(query);
	snprintf(manifest, 1024, "/tmp/opt/share/packages/%s.xml", gpkgname);
	_d_msg(DEBUG_ERR, "Manifest name is %s\n", manifest);
	if (access(manifest, F_OK)) {
		_d_msg(DEBUG_ERR, "No rw Manifest File Found\n");

		snprintf(manifest, 1024, "/tmp/usr/share/packages/%s.xml", gpkgname);
		_d_msg(DEBUG_ERR, "Manifest ro name is %s\n", manifest);

		if (access(manifest, F_OK)) {
			_d_msg(DEBUG_ERR, "No ro Manifest File Found\n");
		} else
			m_exist = 1;
	} else
		m_exist = 1;

	_d_msg(DEBUG_ERR, "Manifest exists\n");

	err = chdir(cwd);
	if (err != 0) {
		_d_msg(DEBUG_ERR, "chdir() failed\n");
		return -1;
	}

	if (m_exist) {
		err = pkgmgr_parser_check_manifest_validation(manifest);
		if(err < 0) {
			_d_msg(DEBUG_ERR, "Invalid manifest\n");
			return -1;
		}
	}
#endif
	err = __rpm_xsystem(argv);
	if (err != 0) {
		_d_msg(DEBUG_ERR, "upgrade complete with error(%d)\n", err);
	}

#ifdef PRE_CHECK_FOR_MANIFEST
	if (m_exist) {
		err = pkgmgr_parser_parse_manifest_for_upgrade(manifest, NULL);
		if (err < 0) {
			_d_msg(DEBUG_ERR, "Parsing Manifest Failed\n");
		} else
			_d_msg(DEBUG_ERR, "Parsing Manifest Success\n");
	}
#endif

	return err;
}
