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

/* System Include files */
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wait.h>
#include <regex.h>
#include <pthread.h>
#include <dirent.h>
#include <fcntl.h>
#include <rpmlib.h>
#include <header.h>
#include <rpmts.h>
#include <rpmdb.h>

/* SLP include files */
#include "rpm-installer.h"
#include "rpm-installer-util.h"
#include "db-util.h"

#define QUERY_PACKAGE		"/usr/bin/query_rpm_package.sh"
#define RPM_PKG_INFO		"/var/rpmpkg.info"

struct pkgfile_info_t {
	char *pkg_filename;
	char *pkg_type;
};
typedef struct pkgfile_info_t pkgfile_info;

extern char *gpkgname;
extern int do_upgrade;
static int __ri_xsystem_with_dup(char *pkgname, int fd);
static int __ri_recursive_delete_dir(char *dirname);

static int __ri_recursive_delete_dir(char *dirname)
{
	DIR *dp;
	struct dirent *ep;
	char abs_filename[FILENAME_MAX];
	struct stat stFileInfo;
	dp = opendir(dirname);
	if (dp != NULL) {
		while (ep = readdir(dp)) {
			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				 ep->d_name);
			if (lstat(abs_filename, &stFileInfo) < 0)
				perror(abs_filename);
			if (S_ISDIR(stFileInfo.st_mode)) {
				if (strcmp(ep->d_name, ".") &&
				    strcmp(ep->d_name, "..")) {
					__ri_recursive_delete_dir(abs_filename);
					remove(abs_filename);
				}
			} else {
				remove(abs_filename);
			}
		}
		(void)closedir(dp);
	} else {
		_d_msg(DEBUG_ERR, "Couldn't open the directory\n");
		return RPM_INSTALLER_ERR_CLEAR_DATA_FAILED;
	}

	return RPM_INSTALLER_SUCCESS;
}

pkginfo *_rpm_installer_get_pkgfile_info(char *pkgfile)
{
	int i;
	int ret = 0;
	rpmts ts;
	rpmtd td;
	FD_t fd;
	rpmRC rc;
	Header hdr = NULL;
	rpmVSFlags vsflags = 0;
	pkginfo *info = NULL;
	if (pkgfile == NULL)
		return NULL;
	info = malloc(sizeof(pkginfo));
	if (info == NULL) {
		_d_msg(DEBUG_ERR, "Malloc Failed\n");
		return NULL;
	}

	fd = Fopen(pkgfile, "r.ufdio");
	if ((!fd) || Ferror(fd)) {
		_d_msg(DEBUG_ERR, "Failed to open package file (%s)\n", Fstrerror(fd));
		if (fd) {
			Fclose(fd);
		}
		free(info);
		info = NULL;
		goto err;
	}

	ts = rpmtsCreate();
	td = rpmtdNew();
	hdr = headerNew();

	vsflags |= _RPMVSF_NODIGESTS;
	vsflags |= _RPMVSF_NOSIGNATURES;
	vsflags |= RPMVSF_NOHDRCHK;
	(void) rpmtsSetVSFlags(ts, vsflags);

	rc = rpmReadPackageFile(ts, fd, pkgfile, &hdr);
	if (rc != RPMRC_OK) {
		_d_msg(DEBUG_ERR, "Could not read package file\n");
		free(info);
		info = NULL;
		goto err;
	}
	Fclose(fd);
	/*Name*/
	headerGet(hdr, RPMTAG_NAME, td, HEADERGET_MINMEM);
	strncpy(info->package_name, rpmtdGetString(td), sizeof(info->package_name));
	_d_msg(DEBUG_INFO, "Package Name : %s\n", info->package_name);
	rpmtdReset(td);
	/*Version*/
	headerGet(hdr, RPMTAG_VERSION, td, HEADERGET_MINMEM);
	strncpy(info->version, rpmtdGetString(td), sizeof(info->version));
	_d_msg(DEBUG_INFO, "Version : %s\n", info->version);
	rpmtdReset(td);


err:
	rpmtdFreeData(td);
	rpmtdFree(td);
	headerFree(hdr);
	rpmtsFree(ts);
	return info;

}

pkginfo *_rpm_installer_get_pkgname_info(char *pkgname)
{
	rpmts ts = NULL;
	Header hdr = NULL;
	int found = 0;
	rpmdbMatchIterator mi;
	rpmtd tn, tv;
	rpmRC rc;
	pkginfo *info = NULL;
	if (pkgname == NULL)
		return NULL;
	info = malloc(sizeof(pkginfo));
	if (info == NULL) {
		_d_msg(DEBUG_ERR, "Malloc Failed\n");
		return NULL;
	}

	tn = rpmtdNew();
	tv = rpmtdNew();
	ts = rpmtsCreate();
	hdr = headerNew();

	mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);
	while (NULL != (hdr = rpmdbNextIterator(mi))) {

		hdr = headerLink(hdr);
		rc = headerGet(hdr, RPMTAG_NAME, tn, HEADERGET_MINMEM);
		if (strcmp(pkgname, rpmtdGetString(tn)) == 0) {
			found = 1;
			break;
		} else {
			rpmtdReset(tn);
			hdr = headerFree(hdr);
		}

	}

	if (found == 0) {
		_d_msg(DEBUG_ERR, "Package not found in DB\n");
		free(info);
		info = NULL;
		goto err;
	}
	/*Name */
	headerGet(hdr, RPMTAG_NAME, tn, HEADERGET_MINMEM);
	strncpy(info->package_name, rpmtdGetString(tn),
		sizeof(info->package_name)-1);
	_d_msg(DEBUG_INFO, "Package Name : %s\n", info->package_name);
	/*Version */
	headerGet(hdr, RPMTAG_VERSION, tv, HEADERGET_MINMEM);
	strncpy(info->version, rpmtdGetString(tv), sizeof(info->version)-1);
	_d_msg(DEBUG_INFO, "Version : %s\n", info->version);


 err:
	headerFree(hdr);
	rpmtdFreeData(tn);
	rpmtdFree(tn);
	rpmtdFreeData(tv);
	rpmtdFree(tv);
	rpmdbFreeIterator(mi);
	rpmtsFree(ts);

	return info;

}

#if 0

static int __ri_xsystem_with_dup(char *pkgname, int fd)
{
	int pid;
	int status = 0;
	const char *argv[] = { QUERY_PACKAGE, pkgname, NULL };
	pid = fork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return -1;
	case 0:		/* child */
		close(1);
		close(2);
		dup(fd);
		dup(fd);	/* dup called twice to create copy of fd 1 and fd 2 */
		execvp(argv[0], (char *const *)argv);
		exit(-1);
	default:		/*parent */
		break;
	}
	if (waitpid(pid, &status, 0) == -1) {
		perror("waitpid failed");
		return -1;
	}
	if (WIFSIGNALED(status)) {
		perror("signal");
		printf("sig no. %d\n", WTERMSIG(status));
		return -1;
	}
	if (!WIFEXITED(status)) {
		perror("should not happen");
		return -1;
	}

	return WEXITSTATUS(status);
}

pkginfo *_rpm_installer_get_pkg_info(char *pkgname)
{
	pkginfo *info = NULL;
	int err = 0;
	int fd = -1;
	FILE *fp = NULL;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	char *saveptr = NULL;
	char *tok = NULL;

	if (pkgname == NULL)
		return NULL;

	fd = open(RPM_PKG_INFO, O_CREAT | O_RDWR, 0644);
	if (fd == -1) {
		_d_msg(DEBUG_ERR, "open failed\n");
		return NULL;
	}

	err = __ri_xsystem_with_dup(pkgname, fd);
	_d_msg(DEBUG_INFO,
	       "[_rpm_installer_get_pkg_info] _xsystem returns %d\n", err);
	if (err == 1) {
		_d_msg(DEBUG_INFO,
		       "[_rpm_installer_get_pkg_info] "
		       "Package Not installed \n");
		close(fd);
		return NULL;
	} else if (err == 2) {
		_d_msg(DEBUG_INFO,
		       "[_rpm_installer_get_pkg_info] "
		       "package already install\n");
		info = malloc(sizeof(pkginfo));
		if (info == NULL) {
			_d_msg(DEBUG_ERR, "Malloc Failed\n");
			close(fd);
			return NULL;
		}
		memset(info, 0x00, sizeof(pkginfo));
		close(fd);
		fp = fopen(RPM_PKG_INFO, "r");
		if (fp == NULL) {
			_d_msg(DEBUG_ERR, "fopen failed\n");
			return NULL;
		}

		/* Now open file and get pkgname and version */
		while ((read = getline(&line, &len, fp)) != -1) {
			int len = strlen(line);
			line[len - 1] = '\0';

			_d_msg(DEBUG_INFO, "line[%s]\n", line);

			tok = strtok_r(line, " ", &saveptr);	/*Name */
			if (tok && strncmp(tok, "Name", 4) == 0) {
				/* : */
				tok = strtok_r(NULL, " ", &saveptr);
				/* <name> */
				tok = strtok_r(NULL, " ", &saveptr);
				if (tok) {
					strncpy(info->package_name, tok,
						sizeof(info->package_name));
				}
			} else if (tok && strncmp(tok, "Version", 7) == 0) {
				/* : */
				tok = strtok_r(NULL, " ", &saveptr);
				/* <version> */
				tok = strtok_r(NULL, " ", &saveptr);
				if (tok) {
					strncpy(info->version, tok,
						sizeof(info->version));
				}
				break;
			} else
				continue;
		}
		if (line) {
			free(line);
			line = NULL;
		}
		fclose(fp);
		remove(RPM_PKG_INFO);
		return info;

	} else {
		_d_msg(DEBUG_ERR,
		       "[_rpm_installer_get_pkg_info] "
		       "_xsystem returns error = %d\n", err);
		close(fd);
		return NULL;
	}
	remove(RPM_PKG_INFO);
	return info;

}

#endif

int _rpm_installer_package_install(char *pkgfilepath, bool forceinstall,
				   char *installoptions)
{
	int err = 0;
	if (forceinstall == true && installoptions == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	pkginfo *info = NULL;
	pkginfo *tmpinfo = NULL;
	/*Check to see if the package is already installed or not
	   If it is installed, compare the versions. If the current version
	   is higher than the installed version, upgrade it automatically
	   else ask for user confirmation before downgrading */

	info = _rpm_installer_get_pkgfile_info(pkgfilepath);
	if (info == NULL) {
		/* failed to get pkg info */
		return RPM_INSTALLER_ERR_UNKNOWN;
	}

	_ri_set_backend_state_info(GOT_PACKAGE_INFO_SUCCESSFULLY);
	if (gpkgname) {
		free(gpkgname);
		gpkgname = NULL;
	}
	gpkgname = strdup(info->package_name);

	tmpinfo = _rpm_installer_get_pkgname_info(info->package_name);
	if (tmpinfo == NULL) {
		/* package is not installed. Go for installation. */
		if (info) {
			free(info);
			info = NULL;
		}
		err = _rpm_install_pkg(pkgfilepath, installoptions);
		if (err != 0) {
			_d_msg(DEBUG_ERR,
			       "install complete with error(%d)\n", err);
			return err;
		} else {
			_ri_set_backend_state_info(REQUEST_COMPLETED);
			return RPM_INSTALLER_SUCCESS;
		}
	} else if (strcmp(info->version, tmpinfo->version) > 0) {
		/*upgrade */
		err = _rpm_upgrade_pkg(pkgfilepath, "--force");
		if (err != 0) {
			_d_msg(DEBUG_ERR,
			       "upgrade complete with error(%d)\n", err);
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			return err;
		} else {
			_ri_set_backend_state_info(REQUEST_COMPLETED);
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			return RPM_INSTALLER_SUCCESS;
		}
	} else if (strcmp(info->version, tmpinfo->version) < 0) {
		/*show popup and confirm from user */
		switch (do_upgrade) {
		case -1:
			_ri_set_backend_state_info(REQUEST_PENDING);
//			return RPM_INSTALLER_ERR_NEED_USER_CONFIRMATION;
			return RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED;
		case 0:
			/*return */
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			_ri_set_backend_state_info(REQUEST_COMPLETED);
			return RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED;
		case 1:
			/*continue with downgrade */
			_ri_set_backend_state_info
			    (GOT_PACKAGE_INFO_SUCCESSFULLY);
			err = _rpm_upgrade_pkg(pkgfilepath, "--force");
			if (err != 0) {
				_d_msg(DEBUG_ERR,
				       "upgrade complete with error(%d)\n",
				       err);
				if (info) {
					free(info);
					info = NULL;
				}
				if (tmpinfo) {
					free(tmpinfo);
					tmpinfo = NULL;
				}
				return err;
			}
			_ri_set_backend_state_info(REQUEST_COMPLETED);
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			return RPM_INSTALLER_SUCCESS;

		}

	} else {
		/*same package. Reinstall it. Manifest should be parsed again */
		err = _rpm_upgrade_pkg(pkgfilepath, "--force");
		if (err != 0) {
			_d_msg(DEBUG_ERR,
			       "upgrade complete with error(%d)\n", err);
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			return err;
		} else {
			_ri_set_backend_state_info(REQUEST_COMPLETED);
			if (info) {
				free(info);
				info = NULL;
			}
			if (tmpinfo) {
				free(tmpinfo);
				tmpinfo = NULL;
			}
			return RPM_INSTALLER_SUCCESS;
		}
	}

	return RPM_INSTALLER_SUCCESS;

}

int _rpm_installer_package_uninstall(char *pkgname)
{
	int ret = 0;
	pkginfo *tmppkginfo = _rpm_installer_get_pkgname_info(pkgname);
	if (tmppkginfo == NULL)
		return RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED;
	if (tmppkginfo) {
		free(tmppkginfo);
		tmppkginfo = NULL;
	}
#ifndef SEND_PKGPATH
	if (gpkgname) {
		free(gpkgname);
		gpkgname = NULL;
	}
	gpkgname = strdup(pkgname);
	_ri_broadcast_status_notification(pkgname, "start", "uninstall");
	_ri_broadcast_status_notification(pkgname, "command", "Uninstall");
#endif
	_ri_set_backend_state_info(GOT_PACKAGE_INFO_SUCCESSFULLY);
	ret = _rpm_uninstall_pkg(pkgname);

	_ri_set_backend_state_info(REQUEST_COMPLETED);

	return ret;
}

int _rpm_installer_clear_private_data(char *pkgname)
{
	if (pkgname == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	char dir_path[256] = { '\0' };
	int ret = -1;
	snprintf(dir_path, 255, "/opt/apps/%s/data/", pkgname);
	ret = __ri_recursive_delete_dir(dir_path);
	return ret;
}
