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

#ifndef __RPM_INSTALLER_UTIL_H_
#define __RPM_INSTALLER_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

#include <string.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>
#include <wait.h>
#include <stdio.h>

#define RPM_BACKEND_EXEC	"rpm-backend"

#define PKGTYPE "rpm"

#define RPM_INSTALLER_SUCCESS					0
#define RPM_INSTALLER_ERR_WRONG_PARAM				3
#define RPM_INSTALLER_ERR_DBUS_PROBLEM				4
#define RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY		5
#define RPM_INSTALLER_ERR_PACKAGE_EXIST				7
#define RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED	8
#define RPM_INSTALLER_ERR_RESOURCE_BUSY				9
#define RPM_INSTALLER_ERR_UNKNOWN					10
#define RPM_INSTALLER_ERR_PKG_NOT_FOUND				11
#define RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION		12
#define RPM_INSTALLER_ERR_NO_RPM_FILE				13
#define RPM_INSTALLER_ERR_DB_ACCESS_FAILED			14
#define RPM_INSTALLER_ERR_RPM_OPERATION_FAILED		15
#define RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED		16
#define RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS	17
#define RPM_INSTALLER_ERR_NEED_USER_CONFIRMATION	18
#define RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED	19
#define RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED	20
#define RPM_INSTALLER_ERR_CLEAR_DATA_FAILED	21


#define RPM_INSTALLER_SUCCESS_STR			"Success"
#define RPM_INSTALLER_ERR_WRONG_PARAM_STR		"Wrong Input Param"
#define RPM_INSTALLER_ERR_DBUS_PROBLEM_STR			"DBUS Error"
#define RPM_INSTALLER_ERR_NOT_ENOUGH_MEMORY_STR	"Not Enough Memory"
#define RPM_INSTALLER_ERR_PACKAGE_EXIST_STR	"Package Already Installed"
#define RPM_INSTALLER_ERR_PACKAGE_NOT_INSTALLED_STR	"Package Not Installed"
#define RPM_INSTALLER_ERR_RESOURCE_BUSY_STR			"Resource Busy"
#define RPM_INSTALLER_ERR_UNKNOWN_STR			"Unknown Error"
#define RPM_INSTALLER_ERR_PKG_NOT_FOUND_STR		"Package file not found"
#define RPM_INSTALLER_ERR_NOT_SUPPOTED_VERSION_STR	"Version Not supported"
#define RPM_INSTALLER_ERR_NO_RPM_FILE_STR	"No RPM Package"
#define RPM_INSTALLER_ERR_DB_ACCESS_FAILED_STR	"DB Access Failed"
#define RPM_INSTALLER_ERR_RPM_OPERATION_FAILED_STR	"RPM operation failed"
#define RPM_INSTALLER_ERR_PACKAGE_NOT_UPGRADED_STR	"Package Not Upgraded"
#define RPM_INSTALLER_ERR_RPM_SCRIPT_WRONG_ARGS_STR	"Wrong Args to Script"
#define RPM_INSTALLER_ERR_PACKAGE_INSTALLATION_DISABLED_STR	"Installation Disabled"
#define RPM_INSTALLER_ERR_PACKAGE_UNINSTALLATION_DISABLED_STR	"Uninstallation Disabled"
#define RPM_INSTALLER_ERR_CLEAR_DATA_FAILED_STR		"Clear Data Failed"

#define DEBUG_ERR		0x0001
#define DEBUG_INFO		0x0002
#define DEBUG_RESULT	0x0004

#define RPM_LOG	1

	void _print_msg(int type, int exetype, char *format, ...);
#define _d_msg(type, fmtstr, args...) { \
_print_msg(type, RPM_LOG, "%s:%d:%s(): " fmtstr, basename(__FILE__), \
__LINE__, __func__, ##args); \
}

	void _d_msg_init(char *program);
	void _d_msg_deinit();
	int _ri_xsystem(const char *argv[]);
	char *_ri_substring(const char *str, size_t begin, size_t len);
	int _ri_tok_split_string(char tok, char *input, char **list,
				 unsigned long listmax);
	void _ri_error_no_to_string(int errnumber, char **errstr);
	int _ri_string_to_error_no(char *errstr);

#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __RPM_INSTALLER_UTIL_H_ */
