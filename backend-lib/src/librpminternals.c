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
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <regex.h>
#include <dlog.h>
/*rpm specific headers*/
#include <rpmlib.h>
#include <header.h>
#include <rpmts.h>
#include <rpmdb.h>
#include <rpmlog.h>
#include "librpminternals.h"

/* This is backend lib's filter string for dlogutil*/
#define LOCAL_LOG_TAG	 "librpm"
int logging = 0x0004;
#ifdef LOG_IN_FILE
#define RPM_INSTALLER_LIBRPM_LOG_FILE "/tmp/librpm"
FILE *logfile = NULL;
#endif

void _librpm_print_msg(int type, int exetype, char *format, ...)
{
	char buffer[FILENAME_MAX] = { 0 };
	char tbuffer[FILENAME_MAX] = { 0 };

	int nbuffer;
	va_list args;
	va_start(args, format);
	nbuffer = vsnprintf(tbuffer, FILENAME_MAX, format, args);
	va_end(args);

	switch (type) {
	case DEBUG_ERR:
		LOG(LOG_ERROR, LOCAL_LOG_TAG, "%s", tbuffer);
		break;
	case DEBUG_RESULT:
		LOG(LOG_WARN, LOCAL_LOG_TAG, "%s", tbuffer);
		break;
	case DEBUG_INFO:
		LOG(LOG_DEBUG, LOCAL_LOG_TAG, "%s", tbuffer);
	default:
		break;
	}

	if (logging == 0)
		return;

	if (DEBUG_ERR == (logging & type)) {
		nbuffer = snprintf(buffer, FILENAME_MAX, "ERROR:%s", tbuffer);
		vfprintf(stderr, format, args);
	} else if (DEBUG_INFO == (logging & type)) {
		nbuffer = snprintf(buffer, FILENAME_MAX, "INFO:%s", tbuffer);
		vfprintf(stdout, format, args);
	} else if (DEBUG_RESULT == (logging & type)) {
		nbuffer = snprintf(buffer, FILENAME_MAX, "RESULT:%s", tbuffer);
		vfprintf(stdout, format, args);
	} else {
		return;
	}

#ifdef LOG_IN_FILE
	if (logfile != NULL)
		fwrite(buffer, sizeof(char), strlen(buffer), logfile);
#endif				/*LOG_IN_FILE */
}

int _librpm_app_is_installed(char *pkgid)
{
	rpmts ts = NULL;
	int ret = 0;
        Header hdr = NULL;
        int found = 0;
        rpmdbMatchIterator mi;
        rpmtd tn = NULL;
        rpmRC rc;

        tn = rpmtdNew();
        ts = rpmtsCreate();
/*
	hdr = headerNew();
*/

        mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);
        while (NULL != (hdr = rpmdbNextIterator(mi))) {

                hdr = headerLink(hdr);
                rc = headerGet(hdr, RPMTAG_NAME, tn, HEADERGET_MINMEM);
                if (strcmp(pkgid, rpmtdGetString(tn) ) == 0) {
                        found = 1;
                        break;
                } else {
                        rpmtdReset(tn);
                        headerFree(hdr);
                }

        }
	if (found == 0) {
		_librpm_print(DEBUG_INFO, "Package not found in DB\n");
		ret = 0;
		goto err;
	}
	else {
		 _librpm_print(DEBUG_INFO, "Package found in DB\n");
                ret = 1;
		goto err;
	}
err:
	rpmtdFreeData(tn);
	rpmtdFree(tn);
	headerFree(hdr);
	rpmtsFree(ts);
	rpmdbFreeIterator(mi);
	return ret;

}

int _librpm_get_installed_package_info(char *pkgid,
                        package_manager_pkg_detail_info_t *pkg_detail_info)
{
	rpmts ts = NULL;
        Header hdr = NULL;
        int found = 0;
	int ret = 0;
        rpmdbMatchIterator mi;
        rpmtd td, tn, tv, ta;
        rpmRC rc;

        td = rpmtdNew();
        tn = rpmtdNew();
        tv = rpmtdNew();
        ta = rpmtdNew();
        ts = rpmtsCreate();
/*
	hdr = headerNew();
*/
        mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);
        while (NULL != (hdr = rpmdbNextIterator(mi))) {

                hdr = headerLink(hdr);
                rc = headerGet(hdr, RPMTAG_NAME, tn, HEADERGET_MINMEM);
                if (strcmp(pkgid, rpmtdGetString(tn) ) == 0) {
                        found = 1;
                        break;
                } else {
                        rpmtdReset(tn);
                        headerFree(hdr);
                }

        }

	/*Print the header info */
        if (found == 0) {
                _librpm_print(DEBUG_ERR, "Package not found in DB\n");
                ret = LIBRPM_ERROR;
		goto err;
        }
	/*Name*/
	headerGet(hdr, RPMTAG_NAME, tn, HEADERGET_MINMEM);
        strncpy(pkg_detail_info->pkgid, rpmtdGetString(tn), PKG_NAME_STRING_LEN_MAX-1);
        /*Version*/
        headerGet(hdr, RPMTAG_VERSION, tv, HEADERGET_MINMEM);
        strncpy(pkg_detail_info->version, rpmtdGetString(tv), PKG_VERSION_STRING_LEN_MAX-1);
        /*Description*/
        headerGet(hdr, RPMTAG_DESCRIPTION, td, HEADERGET_MINMEM);
        strncpy(pkg_detail_info->pkg_description, rpmtdGetString(td), PKG_VALUE_STRING_LEN_MAX-1);
        /*Size*/
        headerGet(hdr, RPMTAG_SIZE, ta, HEADERGET_MINMEM);
        pkg_detail_info->app_size = rpmtdGetNumber(ta);
	ret = LIBRPM_SUCCESS;

err:
        headerFree(hdr);
	rpmtdFreeData(tn);
	rpmtdFree(tn);
	rpmtdFreeData(td);
	rpmtdFree(td);
	rpmtdFreeData(ta);
	rpmtdFree(ta);
	rpmtdFreeData(tv);
	rpmtdFree(tv);
        rpmdbFreeIterator(mi);
        rpmtsFree(ts);

        return ret;

}

int _librpm_get_package_header_info(char *pkg_path,
				package_manager_pkg_detail_info_t *pkg_detail_info)
{
	int i;
	int ret = 0;
	rpmts ts = NULL;
	rpmtd td = NULL;
	FD_t fd;
	rpmRC rc;
	Header hdr = NULL;
	rpmVSFlags vsflags = 0;

	fd = Fopen(pkg_path, "r.ufdio");
	if ((!fd) || Ferror(fd)) {
		_librpm_print(DEBUG_ERR, "Failed to open package file (%s)\n", Fstrerror(fd));
		ret = LIBRPM_ERROR;
		goto err;
	}

	ts = rpmtsCreate();
	td = rpmtdNew();
	hdr = headerNew();

	vsflags |= _RPMVSF_NODIGESTS;
	vsflags |= _RPMVSF_NOSIGNATURES;
	vsflags |= RPMVSF_NOHDRCHK;
	(void) rpmtsSetVSFlags(ts, vsflags);

	rc = rpmReadPackageFile(ts, fd, pkg_path, &hdr);
	if (rc != RPMRC_OK) {
		_librpm_print(DEBUG_ERR, "Could not read package file\n");
		ret = LIBRPM_ERROR;
		goto err;
	}
	Fclose(fd);
	/*Name*/
	headerGet(hdr, RPMTAG_NAME, td, HEADERGET_MINMEM);
	strncpy(pkg_detail_info->pkgid, rpmtdGetString(td), PKG_NAME_STRING_LEN_MAX-1);
	rpmtdReset(td);
	/*Version*/
	headerGet(hdr, RPMTAG_VERSION, td, HEADERGET_MINMEM);
	strncpy(pkg_detail_info->version, rpmtdGetString(td), PKG_VERSION_STRING_LEN_MAX-1);
	rpmtdReset(td);
	/*Description*/
	headerGet(hdr, RPMTAG_DESCRIPTION, td, HEADERGET_MINMEM);
	strncpy(pkg_detail_info->pkg_description, rpmtdGetString(td), PKG_VALUE_STRING_LEN_MAX-1);
	rpmtdReset(td);
	/*Size*/
	headerGet(hdr, RPMTAG_SIZE, td, HEADERGET_MINMEM);
	pkg_detail_info->app_size = rpmtdGetNumber(td);

	ret = LIBRPM_SUCCESS;
err:
	rpmtdFreeData(td);
	rpmtdFree(td);
	headerFree(hdr);
	rpmtsFree(ts);
	return ret;

}

long long _librpm_calculate_dir_size(char *dirname)
{
	long long total = 0;
	long long ret = 0;
	int q = 0; /*quotient*/
	int r = 0; /*remainder*/
	DIR *dp = NULL;
	struct dirent *ep = NULL;
	struct stat fileinfo;
	char abs_filename[FILENAME_MAX] = { 0, };
	if (dirname == NULL) {
		_librpm_print(DEBUG_ERR,
				"dirname is NULL");
		return LIBRPM_ERROR;
	}
	dp = opendir(dirname);
	if (dp != NULL) {
		while ((ep = readdir(dp)) != NULL) {
			if (!strcmp(ep->d_name, ".") ||
				!strcmp(ep->d_name, "..")) {
				continue;
			}
			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				 ep->d_name);
			if (stat(abs_filename, &fileinfo) < 0)
				perror(abs_filename);
			else {
				if (S_ISDIR(fileinfo.st_mode)) {
					total += fileinfo.st_size;
					if (strcmp(ep->d_name, ".")
					    && strcmp(ep->d_name, "..")) {
						ret = _librpm_calculate_dir_size
						    (abs_filename);
						total = total + ret;
					}
				} else {
					/*It is a file. Calculate the actual
					size occupied (in terms of 4096 blocks)*/
				q = (fileinfo.st_size / BLOCK_SIZE);
				r = (fileinfo.st_size % BLOCK_SIZE);
				if (r) {
					q = q + 1;
				}
				total += q * BLOCK_SIZE;
				}
			}
		}
		(void)closedir(dp);
	} else {
		_librpm_print(DEBUG_ERR,
			     "Couldn't open the directory\n");
		return -1;
	}
	return total;

}
