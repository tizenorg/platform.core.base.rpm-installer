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
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <rpmlib.h>
#include <header.h>
#include <rpmts.h>
#include <rpmdb.h>
#include "rpm-installer.h"
#include "rpm-frontend.h"
#include <pkgmgr_installer.h>

#define RPM	"/usr/etc/package-manager/backend/rpm"

char *gpkgname = NULL;
extern char scrolllabel[256];
enum optionsflags {
	INVALID_OPTIONS = 0,
	FORCE_OVERWITE = 1,
	IGNORE_DEPENDS = 2,
};

struct ri_backend_data_t {
	int req_cmd;
	char *cmd_string;
	char *pkg_name;
	int force_overwrite;
};

typedef struct ri_backend_data_t ri_backend_data;
static int __ri_native_recovery(int lastbackstate);
static int __ri_uninstall_package(char *pkgname);
static int __ri_clear_private_data(char *pkgname);
static inline int __ri_read_proc(const char *path, char *buf, int size);
static inline int __ri_find_pid_by_cmdline(const char *dname,
					   const char *cmdline,
					   const char *priv);
static bool __ri_is_another_instance_running(const char *exepath);

static int __ri_uninstall_package(char *pkgname)
{

	if (pkgname == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	int ret = 0;
	ret = _rpm_installer_package_uninstall(pkgname);
	if (ret == RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED) {
		_d_msg(DEBUG_ERR, "[__ri_uninstall_package]%s "
		       "not installed\n", pkgname);
	} else if (ret != 0) {
		_d_msg(DEBUG_ERR,
		       "[__ri_uninstall_package]%s uninstall failed(%d)\n",
		       pkgname, ret);
	} else {
		_d_msg(DEBUG_ERR,
		       "[__ri_uninstall_package]%s successfully uninstalled\n",
		       pkgname);
	}
	return ret;
}

static int __ri_clear_private_data(char *pkgname)
{
	if (pkgname == NULL)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	int ret = 0;
	ret = _rpm_installer_clear_private_data(pkgname);
	if (ret == RPM_INSTALLER_SUCCESS) {
		_d_msg(DEBUG_ERR,
		       "[__clear_private_data]%s clear data successful\n",
		       pkgname);
	} else {
		_d_msg(DEBUG_ERR,
		       "[__clear_private_data]%s clear data failed(%d)\n",
		       pkgname, ret);
	}
	return ret;
}

static inline int __ri_read_proc(const char *path, char *buf, int size)
{
	int fd;
	int ret;

	if (buf == NULL || path == NULL)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
}

static inline int __ri_find_pid_by_cmdline(const char *dname,
					   const char *cmdline,
					   const char *priv)
{
	int pid = 0;
	if (strncmp(cmdline, priv, strlen(RPM)) == 0) {
		pid = atoi(dname);
		if (pid != getpgid(pid))
			pid = 0;
		if (pid == getpid())
			pid = 0;
	}

	return pid;
}

static bool __ri_is_another_instance_running(const char *exepath)
{
	DIR *dp;
	struct dirent *dentry;
	int pid;
	int ret;
	char buf[256] = { 0, };
	char buf1[256] = { 0, };
	dp = opendir("/proc");
	if (dp == NULL) {
		return 0;
	}
	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;
		snprintf(buf, sizeof(buf), "/proc/%s/cmdline", dentry->d_name);
		ret = __ri_read_proc(buf, buf1, sizeof(buf));
		if (ret <= 0)
			continue;
		pid = __ri_find_pid_by_cmdline(dentry->d_name, buf1, exepath);
		if (pid > 0) {
			closedir(dp);
			return 1;
		}
	}

	closedir(dp);
	return 0;

}

static int __ri_native_recovery(int lastbackstate)
{
	char *pn = NULL;
	int lreq;
	int opt;
	int err = 0;
	pkginfo *tmp_pkginfo = NULL;
	char *installoptions = NULL;

	_d_msg(DEBUG_INFO, "Rpm Installer Recovery Entry \n");

	/* which package it was installing and what was state at that time */
	_ri_get_last_input_info(&pn, &lreq, &opt);

	switch (lastbackstate) {
	case REQUEST_ACCEPTED:
		/*
		 * we can restart the last operations
		 * once again as request was only accepted
		 * but nothing was done
		 * It will be same as restarting the last request again
		 */
		_d_msg(DEBUG_INFO,
			      "Rpm Installer Recovery REQUEST_ACCEPTED started \n");
		switch (lreq) {
		case INSTALL_CMD:
			tmp_pkginfo =
			    _rpm_installer_get_pkgfile_info(pn);
			if (tmp_pkginfo == NULL) {
				goto RECOVERYERROR;
			}

			break;

		case DELETE_CMD:
			tmp_pkginfo = _rpm_installer_get_pkgname_info(pn);
			if (tmp_pkginfo == NULL)
				goto RECOVERYERROR;
			if (tmp_pkginfo != NULL) {
				free(tmp_pkginfo);
				tmp_pkginfo = NULL;
			}
			break;
		}
		_d_msg(DEBUG_INFO,
			      " Rpm Installer Recovery REQUEST_ACCEPTED Ended \n");

		_ri_set_backend_state_info(GOT_PACKAGE_INFO_SUCCESSFULLY);

	case GOT_PACKAGE_INFO_SUCCESSFULLY:
		_d_msg(DEBUG_INFO,
			      " Rpm Installer Recovery "
			      "GOT_PACKAGE_INFO_SUCCESSFULLY started \n");
		/*
		 * Package information is been read successfully
		 */
		switch (lreq) {
		case INSTALL_CMD:
			err = _rpm_install_pkg(pn, installoptions);
			if (err != 0) {
				_d_msg(DEBUG_ERR,
					      "_rpm_install_pkg "
					      "return error(%d)\n", err);
				goto RECOVERYERROR;
			}
			break;

		case DELETE_CMD:
			err = _rpm_uninstall_pkg(pn);
			if (err != 0) {
				_d_msg(DEBUG_ERR,
					      "_rpm_uninstall_pkg "
					      "return error(%d)\n", err);
				goto RECOVERYERROR;
			}
			break;
		}
		_d_msg(DEBUG_INFO,
			      " Rpm Installer Recovery "
			      "GOT_PACKAGE_INFO_SUCCESSFULLY ended \n");
		_ri_set_backend_state_info(REQUEST_COMPLETED);

	case REQUEST_COMPLETED:
		_d_msg(DEBUG_INFO,
			      " Rpm Installer Recovery "
			      "REQUEST_COMPLETED started \n");

		_d_msg(DEBUG_INFO,
			      " Rpm Installer Recovery"
			      "REQUEST_COMPLETED ended \n");

		_ri_set_backend_state_info(REQUEST_COMPLETED);
		break;
	default:
		/*
		 * Unknown state
		 * No need to recover
		 */
		_d_msg(DEBUG_INFO,
			      " Rpm Installer Recovery Default state \n");
		break;

	}
	return 0;

 RECOVERYERROR:
	_d_msg(DEBUG_ERR, "Error in Recovery error number = (%d)\n",
		      err);
	return err;

}

int _rpm_backend_interface(char *keyid, char *pkgname, char *reqcommand)
{
	int ret = -1;
	ri_backend_data data = { 0 };
	int backendstate;
	rpmRC rc;
	if (keyid == NULL || pkgname == NULL || reqcommand == NULL) {
		_d_msg(DEBUG_ERR, " Either keyid/pkgname/reqcommand is NULL\n");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	if (strncmp(reqcommand, "install", strlen("install")) == 0) {
		data.req_cmd = INSTALL_CMD;
		data.cmd_string = strdup("install");
		if (data.cmd_string == NULL) {
			_d_msg(DEBUG_ERR,
			       "strdup failed due to insufficient memory\n");
		}
	} else if (strncmp(reqcommand, "remove", strlen("remove")) == 0) {
		data.req_cmd = DELETE_CMD;
		data.cmd_string = strdup("uninstall");
		if (data.cmd_string == NULL) {
			_d_msg(DEBUG_ERR,
			       "strdup failed due to insufficient memory\n");
		}
	} else if (strncmp(reqcommand, "recover", strlen("recover")) == 0) {
		data.req_cmd = RECOVER_CMD;
		data.cmd_string = strdup("recover");
		if (data.cmd_string == NULL) {
			_d_msg(DEBUG_ERR,
			       "strdup failed due to insufficient memory\n");
		}
	} else if (strncmp(reqcommand, "cleardata", strlen("cleardata")) == 0) {
		data.req_cmd = CLEARDATA_CMD;
		data.cmd_string = strdup("cleardata");
		if (data.cmd_string == NULL) {
			_d_msg(DEBUG_ERR,
			       "strdup failed due to insufficient memory\n");
		}
	} else {
		_d_msg(DEBUG_INFO, "wrong input parameter\n");
		_d_msg(DEBUG_RESULT, "%d\n", RPM_INSTALLER_ERR_WRONG_PARAM);
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}

	data.pkg_name = pkgname;
	backendstate = _ri_get_backend_state();

	rc = rpmReadConfigFiles(NULL, NULL);
	if (rc == RPMRC_OK) {
		_d_msg(DEBUG_INFO, "Successfully read rpm configuration\n");
	} else {
		_d_msg(DEBUG_ERR, "Unable to read RPM configuration.\n");
	}

	if (RECOVER_CMD == data.req_cmd) {
		if (0 == backendstate) {
			int lastbackstate;

			/* check the current state of backend */
			lastbackstate = _ri_get_backend_state_info();

			if (REQUEST_COMPLETED == lastbackstate) {
				_d_msg(DEBUG_INFO,
				       " Rpm Installer recovery is in REQUEST_COMPLETED  \n");
				snprintf(scrolllabel, sizeof(scrolllabel),
					 "No Recovery Needed");
			} else
				ret = __ri_native_recovery(lastbackstate);
			if (ret == 0)
				snprintf(scrolllabel, sizeof(scrolllabel),
					 "Recovery Success");

			/* set the backend state as completed */
			_ri_set_backend_state(1);
		} else {
			/* nothing to recover */
			_d_msg(DEBUG_INFO,
			       " Rpm Installer recovery Nothing need to be done\n");
			ret = 0;
			snprintf(scrolllabel, sizeof(scrolllabel),
				 "No Recovery Needed");
		}
		_d_msg(DEBUG_RESULT, "%d\n", ret);
		return ret;

	}
	if (backendstate == 0) {

		/* Non Recovery case
		 *
		 * Another Instance may be running
		 * or something went wrong in last execution
		 * Check for it
		 */
		char *pn = NULL;
		int lreq;
		int opt;
		/* which package it was installing and
		   what was state at that time */
		_ri_get_last_input_info(&pn, &lreq, &opt);
		if ((data.req_cmd == lreq) && (strcmp(pn, data.pkg_name) == 0)) {
			/* same command is executed for 2nd time */
			/* this is same as recover  */
			/* call recover */
			int lastbackstate;

			/* check the current state of backend */
			lastbackstate = _ri_get_backend_state_info();
			/* Publish Notification that backend has started */
			_ri_broadcast_status_notification(data.pkg_name,
							  "start",
							  data.cmd_string);
			_ri_broadcast_status_notification(data.pkg_name,
							  "command",
							  data.cmd_string);
			if (REQUEST_COMPLETED == lastbackstate) {
				_d_msg(DEBUG_INFO,
				       " Rpm Installer recovery"
				       " is in REQUEST_COMPLETED  \n");
				ret = 0;
			} else
				ret = __ri_native_recovery(lastbackstate);

			_d_msg(DEBUG_INFO,
			       "Recovery of old instance failed errno: %d\n ",
			       ret);
			_d_msg(DEBUG_RESULT, "%d\n", ret);
			if (ret != 0) {
				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkg_name,
								  "error",
								  errstr);
				_ri_stat_cb(data.pkg_name, "error", errstr);
				_ri_broadcast_status_notification(data.pkg_name,
								  "end",
								  "fail");
				_ri_stat_cb(data.pkg_name, "end", "fail");
				_d_msg(DEBUG_ERR,
				       "recovery failed with err(%d) (%s)\n",
				       ret, errstr);
			} else {
				_d_msg(DEBUG_INFO,
				       "recovery of last request success\n");
				_ri_broadcast_status_notification(data.pkg_name,
								  "end", "ok");
				_ri_stat_cb(data.pkg_name, "end", "ok");
			}

			/* set the backend state as completed */
			_ri_set_backend_state(1);
		} else {
			ret = __ri_is_another_instance_running(RPM);
			if (ret == 1) {
				if (data.pkg_name) {
					_ri_broadcast_status_notification
					    (data.pkg_name, "error",
					     "Another Instance Running");
					_ri_stat_cb(data.pkg_name, "error",
						    "Another Instance Running");
					_ri_broadcast_status_notification
					    (data.pkg_name, "end", "fail");
					_ri_stat_cb(data.pkg_name, "end",
						    "fail");
				} else {
					_ri_broadcast_status_notification
					    ("unknown", "error",
					     "Another Instance Running");
					_ri_stat_cb("unknown", "error",
						    "Another Instance Running");
					_ri_broadcast_status_notification
					    ("unknown", "end", "fail");
					_ri_stat_cb("unknown", "end", "fail");
				}
				_d_msg(DEBUG_INFO,
				       "Request Failed as "
				       "Another Instance is running \n");
				ret = RPM_INSTALLER_ERR_RESOURCE_BUSY;
				return ret;
			}
		}
	}

	/* set the backend state as started */
	_ri_set_backend_state(0);

#ifdef SEND_PKGPATH
	gpkgname = strdup(data.pkg_name);

	/* Publish Notification that backend has started */
	if (data.pkg_name)
		_ri_broadcast_status_notification(data.pkg_name, "start",
						  data.cmd_string);
	else
		_ri_broadcast_status_notification("unknown", "start",
						  data.cmd_string);
#endif

	_ri_set_backend_state_info(REQUEST_ACCEPTED);

	/* Set the input request info */
	_ri_save_last_input_info(data.pkg_name, data.req_cmd,
				 data.force_overwrite);

	switch (data.req_cmd) {
	case INSTALL_CMD:
		{
			_d_msg(DEBUG_INFO, "[%s] --install %s\n",
			       "backend", data.pkg_name);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkg_name,
							  "command", "Install");
#endif
			if (data.force_overwrite == FORCE_OVERWITE) {
				_d_msg(DEBUG_INFO,
				       "[%s] --install %s --force-overwrite\n",
				       "backend", data.pkg_name);
				ret =
				    _rpm_installer_package_install
				    (data.pkg_name, true, "--force");
			} else {
				_d_msg(DEBUG_INFO, "[%s] --install %s\n",
				       "backend", data.pkg_name);
				ret =
				    _rpm_installer_package_install
				    (data.pkg_name, false, NULL);
			}
			if (ret == RPM_INSTALLER_ERR_NEED_USER_CONFIRMATION) {
				break;
			} else if (ret == RPM_INSTALLER_SUCCESS) {
				_d_msg(DEBUG_INFO, "install success\n");
				_ri_broadcast_status_notification(data.pkg_name,
								  "end", "ok");
				_ri_stat_cb(data.pkg_name, "end", "ok");
			} else {

				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkg_name,
								  "error",
								  errstr);
				_ri_stat_cb(data.pkg_name, "error", errstr);
				_ri_broadcast_status_notification(data.pkg_name,
								  "end",
								  "fail");
				sleep(2);
				_ri_stat_cb(data.pkg_name, "end", "fail");
				_d_msg(DEBUG_ERR,
				       "install failed with err(%d) (%s)\n",
				       ret, errstr);
			}
		}
		break;
	case DELETE_CMD:
		{
			_d_msg(DEBUG_INFO, "[%s] uninstall %s\n",
			       "backend", data.pkg_name);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkg_name,
							  "command", "Remove");
#endif
			ret = __ri_uninstall_package(data.pkg_name);
			if (ret != 0) {
				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkg_name,
								  "error",
								  errstr);
				_ri_stat_cb(data.pkg_name, "error", errstr);
				sleep(2);
				_ri_broadcast_status_notification(data.pkg_name,
								  "end",
								  "fail");
				_ri_stat_cb(data.pkg_name, "end", "fail");
				_d_msg(DEBUG_ERR,
				       "remove failed with err(%d) (%s)\n",
				       ret, errstr);
			} else {
				_d_msg(DEBUG_INFO, "remove success\n");
				_ri_broadcast_status_notification(data.pkg_name,
								  "end", "ok");
				_ri_stat_cb(data.pkg_name, "end", "ok");
			}
		}
		break;
	case CLEARDATA_CMD:
		{
			_d_msg(DEBUG_INFO, "[%s] clear data %s\n",
			       "backend", data.pkg_name);
#ifdef SEND_PKGPATH
			_ri_broadcast_status_notification(data.pkg_name,
							  "command", "clear");
#endif
			ret = __ri_clear_private_data(data.pkg_name);
			if (ret != 0) {
				char *errstr = NULL;
				_ri_error_no_to_string(ret, &errstr);
				_ri_broadcast_status_notification(data.pkg_name,
								  "error",
								  errstr);
				_ri_stat_cb(data.pkg_name, "error", errstr);
				_ri_broadcast_status_notification(data.pkg_name,
								  "end",
								  "fail");
				_ri_stat_cb(data.pkg_name, "end", "fail");
				_d_msg(DEBUG_ERR,
				       "clear data failed with err(%d) (%s)\n",
				       ret, errstr);
			} else {
				_d_msg(DEBUG_INFO, "clear data success\n");
				_ri_broadcast_status_notification(data.pkg_name,
								  "end", "ok");
				_ri_stat_cb(data.pkg_name, "end", "ok");
			}
			break;
		}
	default:
		{
			_ri_broadcast_status_notification("unknown", "command",
							  "unknown");
			_ri_broadcast_status_notification("unknown", "error",
							  "not supported");
			_ri_stat_cb("unknown", "error", "not supported");
			_ri_broadcast_status_notification("unknown",
							  "end", "fail");
			_ri_stat_cb("unknown", "end", "fail");
			_d_msg(DEBUG_ERR, "unknown command \n");
			ret = RPM_INSTALLER_ERR_WRONG_PARAM;
		}
	}

	if (gpkgname) {
		free(gpkgname);
		gpkgname = NULL;
	}

	if (data.cmd_string) {
		free(data.cmd_string);
		data.cmd_string = NULL;
	}

	if (_ri_get_backend_state_info() != REQUEST_PENDING) {
		_ri_set_backend_state_info(REQUEST_COMPLETED);
		/* set the backend state as completed */
		_ri_set_backend_state(1);
		_d_msg(DEBUG_RESULT, "%d\n", ret);
		_d_msg_deinit();
	}
	return ret;
}
