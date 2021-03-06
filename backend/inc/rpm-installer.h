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

#ifndef __RPM_INSTALLER_H_
#define __RPM_INSTALLER_H_

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

#include "rpm-installer-util.h"
#include <stdbool.h>

#define PM_UNLIKELY(expr) __builtin_expect((expr), 0)
#define PM_LIKELY(expr) __builtin_expect((expr), 1)

	enum backend_state {
		REQUEST_ACCEPTED = 1,
		GOT_PACKAGE_INFO_SUCCESSFULLY,
		REQUEST_PENDING,
		REQUEST_COMPLETED
	};
	typedef enum backend_state backend_state;
	struct pkginfo_t {
		char package_name[128];
		char version[11];
	};

	typedef struct pkginfo_t pkginfo;

/**
 * Install the package
 * @in :pkgfilepath : Package file path
 * @in :force_install: Whether we need to forceful overwrite.
 *	   If package already installed then reinstall the application
 * @in :install_options: install options
 */
	int _rpm_installer_package_install(char *pkgfilepath,
					   bool force_install,
					   char *install_options);

/**
 * get the package information from package name
 * return the package information
 * @in :pkgname : package name for which information is requested
 */
	pkginfo *_rpm_installer_get_pkgname_info(char *pkgname);

/**
 * get the package information from package file
 * return the package information
 * @in :pkgfile : package file for which information is requested
 */
	pkginfo *_rpm_installer_get_pkgfile_info(char *pkgfile);

/**
 * Uninstall the Application
 * @in :pkgname : application name to be uninstalled
 */
	int _rpm_installer_package_uninstall(char *pkgname);

/* Dbus related prototype */
	void _ri_broadcast_status_notification(char *pkgname, char *key,
					       char *val);
	int _rpm_backend_interface(char *keyid, char *pkgname,
				   char *reqcommand);

/* RPM operations prototype */
	int _rpm_uninstall_pkg(char *pkgname);
	int _rpm_install_pkg(char *pkgfilepath, char *installoptions);
	int _rpm_upgrade_pkg(char *pkgfilepath, char *installoptions);
	int _ri_set_backend_state(int state);
	int _ri_get_backend_state();
	int _ri_get_backend_state_info();
	int _ri_set_backend_state_info(int state);
	int _ri_get_last_input_info(char **pkgname, int *preqcommand,
				    int *poptions);
	void _ri_save_last_input_info(char *pkgname, int reqcommand,
				      int options);
	void _ri_package_downgrade_information(const char *message);
	int _rpm_installer_clear_private_data(char *pkgname);

#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/* __RPM_INSTALLER_H_ */
