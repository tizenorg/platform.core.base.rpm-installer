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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <appcore-efl.h>
#include <pkgmgr_installer.h>
#include <security-server.h>
#include "rpm-frontend.h"
#include "rpm-installer-util.h"
#include "rpm-installer.h"
#include "rpm-homeview.h"

#define _FIX_POP_UP_
extern struct appdata ad;
extern int ret_val;
extern pkgmgr_installer *pi;
ri_frontend_data front_data;
char scrolllabel[256];

static void __ri_show_usage(char **arg);
static int __ri_process_request(ri_frontend_cmdline_arg *fdata);

static void __ri_show_usage(char **arg)
{

	int i = 0;
	char buffer[256];
	char buff[256] = "";
	while (arg[i] != NULL) {
		snprintf(buffer, 256, "%s %s", buff, arg[i]);
		strncpy(buff, buffer, 255);
		i++;
	}

	_d_msg(DEBUG_INFO, "%s\n", buffer);
	_d_msg(DEBUG_INFO,
	       "\nrpm-backend usage\n   rpm-backend -k <keyid>  <command> <pkg_name | pkg_path> [-q] \n\n");
	_d_msg(DEBUG_INFO, "<Commands> \n");
	_d_msg(DEBUG_INFO,
	       "\t -i <package file path>	  : install package file \n");
	_d_msg(DEBUG_INFO,
	       "\t -k <keyid>			: key id file \n");
	_d_msg(DEBUG_INFO,
	       "\t -r : (recover). Must ignore specific package name or path \n");
	_d_msg(DEBUG_INFO,
	       "\t -d <package name>		: delete a package with package name \n");
	_d_msg(DEBUG_INFO,
	       "\t -q : (quiet) run in background without any user interaction \n");
}

int _ri_parse_cmdline(int argc, char **argv, ri_frontend_cmdline_arg *data)
{
	int req_cmd = INVALID_CMD;
	const char *pkg_name = NULL;
	int quiet = 0;
	const char *pkeyid = NULL;
	int ret = 0;
	pi = pkgmgr_installer_new();
	if (!pi) {
		_d_msg(DEBUG_ERR,
		       "Failure in creating the pkgmgr_installer object \n");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}
	ret = pkgmgr_installer_receive_request(pi, argc, argv);
	if (ret) {
		_d_msg(DEBUG_ERR, "pkgmgr_installer_receive_request failed \n");
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	}
	ret = pkgmgr_installer_get_request_type(pi);
	switch (ret) {
	case PKGMGR_REQ_INSTALL:
		req_cmd = INSTALL_CMD;
		break;
	case PKGMGR_REQ_UNINSTALL:
		req_cmd = DELETE_CMD;
		break;
	case PKGMGR_REQ_RECOVER:
		req_cmd = RECOVER_CMD;
		break;
	case PKGMGR_REQ_CLEAR:
		req_cmd = CLEARDATA_CMD;
		break;
	case PKGMGR_REQ_PERM:
		goto PARSEERROR;
	case PKGMGR_REQ_INVALID:
		req_cmd = INVALID_CMD;
		goto PARSEERROR;
	default:
		goto PARSEERROR;
	}
	if (req_cmd != RECOVER_CMD) {
		pkg_name = pkgmgr_installer_get_request_info(pi);
		if (!pkg_name) {
			_d_msg(DEBUG_ERR,
			       "pkgmgr_installer_get_request_info failed \n");
			return RPM_INSTALLER_ERR_WRONG_PARAM;
		}
		pkeyid = pkgmgr_installer_get_session_id(pi);
		if (!pkeyid) {
			_d_msg(DEBUG_ERR, "pkgmgr_installer_get_session_id failed \n");
			return RPM_INSTALLER_ERR_WRONG_PARAM;
		}

		quiet = pkgmgr_installer_is_quiet(pi);
		if (quiet != 0 && quiet != 1) {
			_d_msg(DEBUG_ERR, "pkgmgr_installer_is_quiet failed \n");
			return RPM_INSTALLER_ERR_WRONG_PARAM;
		}
	}
	if (req_cmd != INSTALL_CMD && req_cmd != DELETE_CMD
	    && req_cmd != RECOVER_CMD && req_cmd != CLEARDATA_CMD) {
		_d_msg(DEBUG_ERR, "invalid command \n");
		goto PARSEERROR;
	}

	data->req_cmd = req_cmd;
	data->pkg_name = (char *)pkg_name;
	data->quiet = quiet;
	data->keyid = (char *)pkeyid;
	return RPM_INSTALLER_SUCCESS;

 PARSEERROR:
	_d_msg(DEBUG_ERR, "Error in parsing input parameter\n");
	__ri_show_usage(argv);
	return RPM_INSTALLER_ERR_WRONG_PARAM;

}

static int __ri_process_request(ri_frontend_cmdline_arg *data)
{
	int ret = 0;
	if (!data)
		return RPM_INSTALLER_ERR_WRONG_PARAM;
	char *pkg_name = NULL;
	char *keyid = NULL;
	if (data->req_cmd != RECOVER_CMD) {
		pkg_name = strdup(data->pkg_name);
                if (PM_UNLIKELY(pkg_name == NULL)) {
                        _d_msg(DEBUG_ERR, "strdup failed\n");
                        return RPM_INSTALLER_ERR_WRONG_PARAM;
                }
                keyid = strdup(data->keyid);
                if (PM_UNLIKELY(keyid == NULL)) {
                        _d_msg(DEBUG_ERR, "strdup failed\n");
                        free(pkg_name);
                        return RPM_INSTALLER_ERR_WRONG_PARAM;
                }
	}
	switch (data->req_cmd) {
	case INSTALL_CMD:
		_d_msg(DEBUG_INFO, "rpm-backend -i %s\n", pkg_name);
		ret = _rpm_backend_interface(keyid, pkg_name, "install");
		break;
	case DELETE_CMD:
		_d_msg(DEBUG_INFO, "rpm-backend -d %s\n", pkg_name);
		ret = _rpm_backend_interface(keyid, pkg_name, "remove");
		break;
	case CLEARDATA_CMD:
		_d_msg(DEBUG_INFO, "rpm-backend -c %s\n", pkg_name);
		ret = _rpm_backend_interface(keyid, pkg_name, "cleardata");
		break;
	case RECOVER_CMD:
		_d_msg(DEBUG_INFO, "rpm-backend -r \n");
		ret = _rpm_backend_interface(keyid, pkg_name, "recover");
		break;
	default:
		_d_msg(DEBUG_ERR,
		       "Error Never Come Here as Error is already checked\n");

	}
	if (keyid) {
		free(keyid);
		keyid = NULL;
	}
	if (pkg_name) {
		free(pkg_name);
		pkg_name = NULL;
	}

	return ret;
}

void _ri_stat_cb(const char *pkg_name, const char *key, const char *val)
{

	if (NULL == pkg_name || NULL == key || NULL == val) {
		_d_msg(DEBUG_ERR, "Either pkg_name/key/val is NULL\n");
		return;		/*TODO: handle error. */
	}

	char *pkg_name_modified = NULL;
	char delims[] = "/";
	char *result = NULL;
	char *pkgname = NULL;
	char *saveptr = NULL;

	pkg_name_modified = (char *)malloc(strlen(pkg_name) + 1);
	if (pkg_name_modified == NULL) {
		_d_msg(DEBUG_ERR, "pkg_name_modified is NULL. Malloc failed\n");
		return;
	}
	memset(pkg_name_modified, '\0', strlen(pkg_name) + 1);
	memcpy(pkg_name_modified, pkg_name, strlen(pkg_name));

	result = strtok_r(pkg_name_modified, delims, &saveptr);
	while (result != NULL) {
		pkgname = result;
		result = strtok_r(NULL, delims, &saveptr);
	}

	if (strcmp(key, "install_percent") == 0) {
		return;
	} else if (strcmp(key, "error") == 0) {
		/* Store the error to be display to the user */
		front_data.error = strdup(val);
	} else if (strcmp(key, "end") == 0) {

		char requesttype[32];
		switch (front_data.args->req_cmd) {
		case INSTALL_CMD:
			snprintf(requesttype, sizeof(requesttype),
				_("Installation"));
			break;
		case DELETE_CMD:
			snprintf(requesttype, sizeof(requesttype), _("Deletion"));
			break;
		case CLEARDATA_CMD:
			snprintf(requesttype, sizeof(requesttype),
				 _("Clear Data"));
			break;
		default:
			snprintf(requesttype, sizeof(requesttype), _("Recovery"));
			break;
		}

		if (front_data.error) {
			/* Error Happened */
			snprintf(scrolllabel, sizeof(scrolllabel),
				 "%s :: %s:: %s:: %s", requesttype, pkgname,
				 dgettext("sys_string", "IDS_COM_POP_ERROR"),
				 front_data.error);
			_d_msg(DEBUG_ERR, "%s\n", scrolllabel);
			ret_val = _ri_string_to_error_no(front_data.error);
			_d_msg(DEBUG_ERR, "%d\n", ret_val);

		} else {
			snprintf(scrolllabel, sizeof(scrolllabel),
				 " %s :: %s :: %s", requesttype, pkgname,
				 dgettext("sys_string", "IDS_COM_POP_SUCCESS"));
			_d_msg(DEBUG_INFO, "%s\n", scrolllabel);
			ret_val = 0;
		}

		if (front_data.args->quiet == 0)
			_ri_frontend_update_progress_info(&ad, scrolllabel);
		else
			elm_exit();
	}

}

int _ri_cmdline_process(ri_frontend_data *data)
{
	char *cookie = NULL;
	int cookie_size = 0;
	int cookie_ret = 0;

	int ret = 0;
	ri_frontend_cmdline_arg *fdata = data->args;

	cookie_size = security_server_get_cookie_size();
	/* If security server is down or some other
	   error occured, raise failure */
	if (0 >= cookie_size) {
		/* TODO: raise error */
		_d_msg(DEBUG_ERR,
		       "security_server_get_cookie_size: Security server down \n");
	} else {
		cookie = calloc(cookie_size, sizeof(char));
		cookie_ret =
		    security_server_request_cookie(cookie, cookie_size);
		/* TODO: Check cookie_ret...
		   (See security-server.h to check return code) */
	}

	if (cookie != NULL)
		_d_msg(DEBUG_INFO, "Got Cookie with size = %d\n", cookie_size);

	data->security_cookie = cookie;

	ret = __ri_process_request(fdata);
	if (ret != RPM_INSTALLER_SUCCESS) {
		_d_msg(DEBUG_ERR, "__ri_process_request: Error\n");
		goto RETURN;
	}

	return RPM_INSTALLER_SUCCESS;

 RETURN:

	if (data->security_cookie) {
		free(data->security_cookie);
		data->security_cookie = NULL;
	}

	return ret;
}

int _ri_cmdline_destroy(ri_frontend_data *data)
{
	if (data == NULL)
		return 0;

	if (data->security_cookie)
		free(data->security_cookie);

	return 0;

}
