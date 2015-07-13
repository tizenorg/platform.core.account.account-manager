/*
 *
 * Copyright (c) 2012 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <string.h>
#include <fcntl.h>
#include <glib.h>
#include <db-util.h>
#include <pthread.h>
#include <vconf.h>

#include <pkgmgr-info.h>
#include <aul.h>
#include <unistd.h>

#include <dbg.h>
#include <account_ipc_marshal.h>
#include <account-private.h>
#include <account.h>
#include <account-error.h>
#include "account-server-private.h"
#include "account-server-db.h"

typedef sqlite3_stmt* account_stmt;

#define TEST_APP_ID "org.tizen.MyAccountCoreTest"
#define EAS_CMDLINE "/usr/bin/eas-engine"
#define EMAIL_SERVICE_CMDLINE "/usr/bin/email-service"
#define IMS_ENGINE_CMDLINE "/usr/bin/ims-srv"
#define IMS_AGENT_CMDLINE "/usr/bin/ims-agent"
#define MDM_SERVER_CMDLINE "/usr/bin/mdm-server"

#define RCS_APPID "com.samsung.rcs-im"
#define IMS_SERVICE_APPID "ims-service"
#define ACTIVESYNC_APPID "activesync-ui"
#define EMAIL_APPID "email-setting-efl"
#define SYNCHRONISE_APPID "setting-synchronise-efl"
#define DS_AGENT_CMDLINE "/usr/bin/oma-ds-agent"

#define FACEBOOK_SDK_APPID "com.samsung.facebook-service"
#define FACEBOOK_APPID "com.samsung.facebook"

#define ACCOUNT_DB_OPEN_READONLY 0
#define ACCOUNT_DB_OPEN_READWRITE 1

#define MAX_TEXT 4096

#define _TIZEN_PUBLIC_
#ifndef _TIZEN_PUBLIC_
//#include <csc-feature.h>

#endif

static sqlite3* g_hAccountDB = NULL;
static sqlite3* g_hAccountDB2 = NULL;
pthread_mutex_t account_mutex = PTHREAD_MUTEX_INITIALIZER;

static char *_account_get_text(const char *text_data);
static const char *_account_query_table_column_text(account_stmt pStmt, int pos);
static int _account_insert_custom(account_s *account, int account_id);
static int _account_update_custom(account_s *account, int account_id);
static int _account_query_custom_by_account_id(account_custom_cb callback, int account_id, void *user_data );
static int _account_type_update_provider_feature(account_type_s *account_type, const char* app_id);

int _account_query_capability_by_account_id(capability_cb callback, int account_id, void *user_data );

static void _account_insert_delete_update_notification_send(char *noti_name)
{
	if (!noti_name) {
		_ERR("Noti Name is NULL!!!!!!\n");
		return;
	}

	_INFO("noti_type = %s", noti_name);

	if (vconf_set_str(VCONFKEY_ACCOUNT_MSG_STR, noti_name) != 0) {
		_ERR("Vconf MSG Str set FAILED !!!!!!\n");;
	}
}

int _account_get_current_appid_cb(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char* appid = NULL;
	char* item = NULL;
	GSList** appid_list = (GSList**)user_data;
	int pkgmgr_ret = -1;

	pkgmgr_ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);

	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_appid(%d)", pkgmgr_ret);
	}

	item = _account_get_text(appid);
	*appid_list = g_slist_append(*appid_list, item);

	return 0;
}

static inline int __read_proc(const char *path, char *buf, int size)
{
	int fd = 0, ret = 0;

	if (buf == NULL || path == NULL) {
		ACCOUNT_ERROR("path and buffer is mandatory\n");
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ACCOUNT_ERROR("fd open error(%d)\n", fd);
		return -1;
	}

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		ACCOUNT_ERROR("fd read error(%d)\n", fd);
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
}

char *_account_get_proc_cmdline_bypid(int pid)
{
	char buf[128];
	int ret = 0;

	ACCOUNT_SNPRINTF(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0) {
		ACCOUNT_DEBUG("No proc directory (%d)\n", pid);
		return NULL;
	}

	return strdup(buf);
}


static char* _account_get_current_appid(int pid)
{
	_INFO("getting caller appid with pid=[%d]", pid);

	int ret=0;
	char appid[128]={0,};
	char* appid_ret = NULL;

	ret = aul_app_get_appid_bypid(pid, appid, sizeof(appid));

	if(ret < 0){
		ACCOUNT_ERROR("fail to get current appid ret=[%d], appid=%s\n", ret, appid);
	}

	_INFO("");

	/* SLP platform core exception */
	if(strlen(appid) == 0){
		_INFO("");
		char* cmdline = NULL;
		cmdline = _account_get_proc_cmdline_bypid(pid);
		ACCOUNT_SLOGD("cmdline (%s)!!!!!!\n", cmdline);
		if(!g_strcmp0(cmdline, EAS_CMDLINE)) {
			appid_ret = _account_get_text(ACTIVESYNC_APPID);
			_ACCOUNT_FREE(cmdline);
			return appid_ret;
		} else if (!g_strcmp0(cmdline, EMAIL_SERVICE_CMDLINE) || !g_strcmp0(cmdline, MDM_SERVER_CMDLINE)) {
			appid_ret = _account_get_text(EMAIL_APPID);
			_ACCOUNT_FREE(cmdline);
			return appid_ret;
		} else if (!g_strcmp0(cmdline, IMS_ENGINE_CMDLINE) || !g_strcmp0(cmdline, IMS_AGENT_CMDLINE)) {
			if(_account_type_query_app_id_exist(RCS_APPID)==ACCOUNT_ERROR_NONE){
				appid_ret = _account_get_text(RCS_APPID);
			} else if(_account_type_query_app_id_exist(IMS_SERVICE_APPID)==ACCOUNT_ERROR_NONE){
				appid_ret = _account_get_text(IMS_SERVICE_APPID);
			} else {
				appid_ret = _account_get_text(RCS_APPID);
			}
			_ACCOUNT_FREE(cmdline);
			return appid_ret;
		} else if (!g_strcmp0(cmdline, DS_AGENT_CMDLINE)) {
			appid_ret = _account_get_text(SYNCHRONISE_APPID);
			_ACCOUNT_FREE(cmdline);
			return appid_ret;
		} else {
			ACCOUNT_DEBUG("No app id\n");
			_ACCOUNT_FREE(cmdline);
			return NULL;
		}
	}

	_INFO("");
	/* temporary exception */
	if(!g_strcmp0(appid, "com.samsung.gallery")){
		appid_ret = _account_get_text("com.samsung.facebook");
	} else if(!g_strcmp0(appid, FACEBOOK_SDK_APPID)){
		appid_ret = _account_get_text(FACEBOOK_APPID);
	} else {
		appid_ret = _account_get_text(appid);
	}

	return appid_ret;
}

static int _account_check_account_type_with_appid_group(const char* appid, char** verified_appid)
{
	int error_code = ACCOUNT_ERROR_NOT_REGISTERED_PROVIDER;
	pkgmgrinfo_appinfo_h ahandle=NULL;
	pkgmgrinfo_pkginfo_h phandle=NULL;
	char* package_id = NULL;
	GSList* appid_list = NULL;
	GSList* iter = NULL;

	if(!appid){
		ACCOUNT_ERROR("input param is null\n");
		return ACCOUNT_ERROR_NOT_REGISTERED_PROVIDER;
	}

	if(!verified_appid){
		ACCOUNT_ERROR("output param is null\n");
		return ACCOUNT_ERROR_NOT_REGISTERED_PROVIDER;
	}

	if(!strcmp(appid, "com.samsung.setting")){
		ACCOUNT_DEBUG("Setting exception\n");
		*verified_appid = _account_get_text("com.samsung.setting");
		return ACCOUNT_ERROR_NONE;
	}

	if(!strcmp(appid, "com.samsung.samsung-account-front")){
		ACCOUNT_DEBUG("Setting exception\n");
		*verified_appid = _account_get_text("com.samsung.samsung-account-front");
		return ACCOUNT_ERROR_NONE;
	}

	if(!strcmp(appid, IMS_SERVICE_APPID) || !strcmp(appid, RCS_APPID)){
		ACCOUNT_DEBUG("ims service exception\n");
		*verified_appid = _account_get_text(appid);
		return ACCOUNT_ERROR_NONE;
	}

	/* Get app id family which is stored in account database */
	int pkgmgr_ret = -1;
	pkgmgr_ret = pkgmgrinfo_appinfo_get_appinfo(appid, &ahandle);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_appinfo(%d)", pkgmgr_ret);
	}
	pkgmgr_ret = pkgmgrinfo_appinfo_get_pkgid(ahandle, &package_id);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_pkgid(%d)", pkgmgr_ret);
	}
	pkgmgr_ret = pkgmgrinfo_pkginfo_get_pkginfo(package_id, &phandle);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_pkginfo_get_pkginfo(%d)", pkgmgr_ret);
	}
	pkgmgr_ret = pkgmgrinfo_appinfo_get_list(phandle, PMINFO_ALL_APP, _account_get_current_appid_cb, (void *)&appid_list);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_list(%d)", pkgmgr_ret);
	}

	/* Compare current app id with the stored app id family */
	for(iter=appid_list;iter!=NULL;iter=g_slist_next(iter)){
		char* tmp = (char*)iter->data;
		if(tmp) {
			if(_account_type_query_app_id_exist(tmp) == ACCOUNT_ERROR_NONE) {
				*verified_appid = _account_get_text(tmp);
				error_code = ACCOUNT_ERROR_NONE;
				_ACCOUNT_FREE(tmp);
				break;
			} else {
				ACCOUNT_SLOGD("not matched owner group app id(%s), current appid(%s)\n", tmp, appid);
			}
		}
		_ACCOUNT_FREE(tmp);
	}

	g_slist_free(appid_list);
	pkgmgr_ret = pkgmgrinfo_pkginfo_destroy_pkginfo(phandle);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_pkginfo_destroy_pkginfo(%d)", pkgmgr_ret);
	}

	pkgmgr_ret = pkgmgrinfo_appinfo_destroy_appinfo(ahandle);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_destroy_appinfo(%d)", pkgmgr_ret);
	}

	return error_code;
}

static int _account_check_appid_group_with_package_name(const char* appid, char* package_name)
{
	int error_code = ACCOUNT_ERROR_PERMISSION_DENIED;
	pkgmgrinfo_appinfo_h ahandle=NULL;
	pkgmgrinfo_pkginfo_h phandle=NULL;
	char* package_id = NULL;
	GSList* appid_list = NULL;
	GSList* iter = NULL;

	if(!appid){
		ACCOUNT_ERROR("input param -appid is null\n");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if(!package_name){
		ACCOUNT_ERROR("input param - package name is null\n");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	/* ims-service Exception */
	if ( strcmp(appid, "ims-service") == 0 &&	strcmp(package_name, "ims-service") == 0 ) {
		ACCOUNT_DEBUG("ims exception.");				// TODO: NEED TO REMOVE, debug log.
		return ACCOUNT_ERROR_NONE;
	}

	/* Get app id family which is stored in account database */
	int pkgmgr_ret = -1;
	pkgmgr_ret = pkgmgrinfo_appinfo_get_appinfo(appid, &ahandle);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_appinfo(%d)", pkgmgr_ret);
	}
	pkgmgr_ret = pkgmgrinfo_appinfo_get_pkgid(ahandle, &package_id);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_pkgid(%d)", pkgmgr_ret);
	}
	pkgmgr_ret = pkgmgrinfo_pkginfo_get_pkginfo(package_id, &phandle);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_pkginfo_get_pkginfo(%d)", pkgmgr_ret);
	}
	pkgmgr_ret = pkgmgrinfo_appinfo_get_list(phandle, PMINFO_ALL_APP, _account_get_current_appid_cb, (void *)&appid_list);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_list(%d)", pkgmgr_ret);
	}

	/* Compare current app id with the stored app id family */
	for(iter=appid_list;iter!=NULL;iter=g_slist_next(iter)){
		char* tmp = (char*)iter->data;
		if(tmp) {
			//ACCOUNT_ERROR("tmp(%s)package_name(%s)\n\n", tmp, package_name);	// TODO: NEED TO REMOVE, debug log.
			if( strcmp(tmp, package_name) == 0) {
				error_code = ACCOUNT_ERROR_NONE;
				_ACCOUNT_FREE(tmp);
				break;
			} else if ( strcmp(tmp, "com.samsung.samsung-account-front") == 0 &&
						strcmp(package_name, "gr47by21a5.SamsungAccount") == 0 ) {
				/* Samung Account Exception */
				error_code = ACCOUNT_ERROR_NONE;
				_ACCOUNT_FREE(tmp);
				break;
			} else {
				ACCOUNT_SLOGD("not matched owner group app id(%s), current appid(%s)\n", tmp, appid);
			}
		}
		_ACCOUNT_FREE(tmp);
	}

	g_slist_free(appid_list);
	pkgmgr_ret = pkgmgrinfo_pkginfo_destroy_pkginfo(phandle);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_pkginfo_destroy_pkginfo(%d)", pkgmgr_ret);
	}

	pkgmgr_ret = pkgmgrinfo_appinfo_destroy_appinfo(ahandle);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_destroy_appinfo(%d)", pkgmgr_ret);
	}

	return error_code;
}

static int _remove_sensitive_info_from_non_owning_account(int caller_pid, account_s *account)
{
	if (account == NULL)
	{
		_ERR("Null input");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if (account->package_name)
	{
		char *caller_package_name = _account_get_current_appid(caller_pid);
		if (caller_package_name == NULL)
		{
			_ERR("Could not get caller app id, so removing sensitive info from account id [%d]", account->id);
			return ACCOUNT_ERROR_INVALID_PARAMETER;
		}

		if (g_strcmp0(caller_package_name, account->package_name) != 0)
		{
			// packages dont match, so remove sensitive info
			_INFO("Removing sensitive info from account id [%d]", account->id);
			free (account->access_token);
			account->access_token = NULL;

		}
		_ACCOUNT_FREE(caller_package_name);
		return ACCOUNT_ERROR_NONE;
	}
	return ACCOUNT_ERROR_INVALID_PARAMETER;
}

static int _remove_sensitive_info_from_non_owning_account_list(int caller_pid, GList *account_list)
{
	int return_code = ACCOUNT_ERROR_NONE;

	if (account_list == NULL)
	{
		_ERR("Null input");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	GList *list_iter = NULL;
	for (list_iter = account_list; list_iter != NULL; list_iter = g_list_next(list_iter))
	{
		account_s *account = (account_s *) list_iter->data;
		int ret = _remove_sensitive_info_from_non_owning_account(caller_pid, account);
		if( ret != ACCOUNT_ERROR_NONE)
			return_code = ret;
	}
	return return_code;
}

static int _remove_sensitive_info_from_non_owning_account_slist(int caller_pid, GSList *account_list)
{
	int return_code = ACCOUNT_ERROR_NONE;

	if (account_list == NULL)
	{
		_ERR("Null input");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	GSList *list_iter = NULL;
	for (list_iter = account_list; list_iter != NULL; list_iter = g_slist_next(list_iter))
	{
		account_s *account = (account_s *) list_iter->data;
		int ret = _remove_sensitive_info_from_non_owning_account(caller_pid, account);
		if( ret != ACCOUNT_ERROR_NONE)
			return_code = ret;
	}
	return return_code;
}

static const char *_account_db_err_msg()
{
	return sqlite3_errmsg(g_hAccountDB);
}

static int _account_db_err_code()
{
	return sqlite3_errcode(g_hAccountDB);
}

static int _account_get_record_count(char* query)
{
	_INFO("_account_get_record_count");

	int rc = -1;
	int ncount = 0;
	account_stmt pStmt = NULL;

	if(!query){
		_ERR("NULL query\n");
		return ACCOUNT_ERROR_QUERY_SYNTAX_ERROR;
	}

	if(!g_hAccountDB){
		_ERR("DB is not opened\n");
		return ACCOUNT_ERROR_DB_NOT_OPENED;
	}

	rc = sqlite3_prepare_v2(g_hAccountDB, query, strlen(query), &pStmt, NULL);

	if (SQLITE_BUSY == rc){
		_ERR("sqlite3_prepare_v2() failed(%d, %s).", rc, _account_db_err_msg());
		sqlite3_finalize(pStmt);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	} else if (SQLITE_OK != rc) {
		_ERR("sqlite3_prepare_v2() failed(%d, %s).", rc, _account_db_err_msg());
		sqlite3_finalize(pStmt);
		return ACCOUNT_ERROR_DB_FAILED;
	}

	rc = sqlite3_step(pStmt);
	if (SQLITE_BUSY == rc) {
		_ERR("sqlite3_step() failed(%d, %s).", rc, _account_db_err_msg());
		sqlite3_finalize(pStmt);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	} else if (SQLITE_ROW != rc) {
		_ERR("sqlite3_step() failed(%d, %s).", rc, _account_db_err_msg());
		sqlite3_finalize(pStmt);
		return ACCOUNT_ERROR_DB_FAILED;
	}

	ncount = sqlite3_column_int(pStmt, 0);

	_INFO("account record count [%d]", ncount);
	sqlite3_finalize(pStmt);

	return ncount;
}

static int _account_execute_query(const char *query)
{
	int rc = -1;
	char* pszErrorMsg = NULL;

	if(!query){
		ACCOUNT_ERROR("NULL query\n");
		return ACCOUNT_ERROR_QUERY_SYNTAX_ERROR;
	}

	if(!g_hAccountDB){
		ACCOUNT_ERROR("DB is not opened\n");
		return ACCOUNT_ERROR_DB_NOT_OPENED;
	}

	rc = sqlite3_exec(g_hAccountDB, query, NULL, NULL, &pszErrorMsg);
	if (SQLITE_OK != rc) {
		ACCOUNT_ERROR("sqlite3_exec rc(%d) query(%s) failed(%s).", rc, query, pszErrorMsg);
		sqlite3_free(pszErrorMsg);
	}

	return rc;
}

static int _account_begin_transaction(void)
{
	ACCOUNT_DEBUG("_account_begin_transaction start");
	int ret = -1;

	ret = _account_execute_query("BEGIN IMMEDIATE TRANSACTION");

	if (ret == SQLITE_BUSY){
		ACCOUNT_ERROR(" sqlite3 busy = %d", ret);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	} else if(ret != SQLITE_OK) {
		ACCOUNT_ERROR("_account_svc_begin_transaction fail :: %d", ret);
		return ACCOUNT_ERROR_DB_FAILED;
	}

	ACCOUNT_DEBUG("_account_begin_transaction end");
	return ACCOUNT_ERROR_NONE;
}

static int _account_end_transaction(bool is_success)
{
	ACCOUNT_DEBUG("_account_end_transaction start");

	int ret = -1;

	if (is_success == true) {
		ret = _account_execute_query("COMMIT TRANSACTION");
		ACCOUNT_DEBUG("_account_end_transaction COMMIT");
	} else {
		ret = _account_execute_query("ROLLBACK TRANSACTION");
		ACCOUNT_DEBUG("_account_end_transaction ROLLBACK");
	}

	if(ret == SQLITE_PERM){
		ACCOUNT_ERROR("Account permission denied :: %d", ret);
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (ret == SQLITE_BUSY){
		ACCOUNT_DEBUG(" sqlite3 busy = %d", ret);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}

	if (ret != SQLITE_OK) {
		ACCOUNT_ERROR("_account_svc_end_transaction fail :: %d", ret);
		return ACCOUNT_ERROR_DB_FAILED;
	}

	ACCOUNT_DEBUG("_account_end_transaction end");
	return ACCOUNT_ERROR_NONE;
}

static bool _account_check_add_more_account(const char* app_id)
{
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;

	ACCOUNT_RETURN_VAL((app_id != 0), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("APP ID IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE AppId = '%s' and MultipleAccountSupport = 1", ACCOUNT_TYPE_TABLE, app_id);
	rc = _account_get_record_count(query);

	/* multiple account support case */
	if(rc > 0) {
		ACCOUNT_SLOGD("app id (%s) supports multiple account. rc(%d)\n", app_id, rc);
		return TRUE;
	}

	/* multiple account not support case */
	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);
	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE package_name = '%s'", ACCOUNT_TABLE, app_id);
	rc = _account_get_record_count(query);

	if(rc <= 0) {
		ACCOUNT_SLOGD("app id (%s) supports single account. and there is no account of the app id\n", app_id);
		return TRUE;
	}

	return FALSE;
}

//TODO: Need to enable creating db on the first connect for
//a) multi-user cases
//b) to ensure db exist in every connect call

//static int _account_create_all_tables(void)
//{
//	int rc = -1;
//	int error_code = ACCOUNT_ERROR_NONE;
//	char	query[ACCOUNT_SQL_LEN_MAX] = {0, };

//	ACCOUNT_DEBUG("create all table - BEGIN");
//	ACCOUNT_MEMSET(query, 0, sizeof(query));

//	/*Create the account table*/
//	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s')", ACCOUNT_TABLE);
//	rc = _account_get_record_count(query);
//	if (rc <= 0) {
//		rc = _account_execute_query(ACCOUNT_SCHEMA);
//		if(rc == SQLITE_BUSY) return ACCOUNT_ERROR_DATABASE_BUSY;
//		ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(%s) failed(%d, %s).\n", ACCOUNT_SCHEMA, rc, _account_db_err_msg()));

//#ifndef _TIZEN_PUBLIC_
//		if (CSC_FEATURE_BOOL_TRUE == csc_feature_get_bool(CSC_FEATURE_DEF_BOOL_CONTACTS_DOCOMO_SOCIAL_PHONEBOOK)) {
//			/* NTT docomo specific area */
//			rc = _account_execute_query(DOCOMO_DEFAULT_VAL_INSERT_QUERY);
//			if(rc == SQLITE_BUSY) return ACCOUNT_ERROR_DATABASE_BUSY;
//			ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(%s) failed(%d, %s).\n", DOCOMO_DEFAULT_VAL_INSERT_QUERY, rc, _account_db_err_msg()));
//			/* END of NTT docomo specific area */
//		}
//#endif
//	}

//	/*Create capability table*/
//	ACCOUNT_MEMSET(query, 0, sizeof(query));
//	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s')", CAPABILITY_TABLE);
//	rc = _account_get_record_count(query);
//	if (rc <= 0) {
//		rc = _account_execute_query(CAPABILITY_SCHEMA);
//		if(rc == SQLITE_BUSY) return ACCOUNT_ERROR_DATABASE_BUSY;
//		ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(%s) failed(%d, %s).\n", CAPABILITY_SCHEMA, rc, _account_db_err_msg()));
//	}

//	/* Create account custom table */
//	ACCOUNT_MEMSET(query, 0, sizeof(query));
//	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s')", ACCOUNT_CUSTOM_TABLE);
//	rc = _account_get_record_count(query);
//	if (rc <= 0) {
//		rc = _account_execute_query(ACCOUNT_CUSTOM_SCHEMA);
//		if(rc == SQLITE_BUSY) return ACCOUNT_ERROR_DATABASE_BUSY;
//		ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(%s) failed(%d, %s).\n", query, rc, _account_db_err_msg()));
//	}

//	/* Create account type table */
//	ACCOUNT_MEMSET(query, 0, sizeof(query));
//	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s')", ACCOUNT_TYPE_TABLE);
//	rc = _account_get_record_count(query);
//	if (rc <= 0) {
//		rc = _account_execute_query(ACCOUNT_TYPE_SCHEMA);
//		if(rc == SQLITE_BUSY) return ACCOUNT_ERROR_DATABASE_BUSY;
//		ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(%s) failed(%d, %s).\n", ACCOUNT_TYPE_SCHEMA, rc, _account_db_err_msg()));
//	}

//	/* Create label table */
//	ACCOUNT_MEMSET(query, 0, sizeof(query));
//	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s')", LABEL_TABLE);
//	rc = _account_get_record_count(query);
//	if (rc <= 0) {
//		rc = _account_execute_query(LABEL_SCHEMA);
//		if(rc == SQLITE_BUSY) return ACCOUNT_ERROR_DATABASE_BUSY;
//		ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(%s) failed(%d, %s).\n", LABEL_SCHEMA, rc, _account_db_err_msg()));
//	}

//	/* Create account feature table */
//	ACCOUNT_MEMSET(query, 0, sizeof(query));
//	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s')", PROVIDER_FEATURE_TABLE);
//	rc = _account_get_record_count(query);
//	if (rc <= 0) {
//		rc = _account_execute_query(PROVIDER_FEATURE_SCHEMA);
//		if(rc == SQLITE_BUSY) return ACCOUNT_ERROR_DATABASE_BUSY;
//		ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(%s) failed(%d, %s).\n", PROVIDER_FEATURE_SCHEMA, rc, _account_db_err_msg()));
//	}

//	ACCOUNT_DEBUG("create all table - END");
//	return error_code;
//}

//static int _account_check_is_all_table_exists()
//{
//	int 	rc = 0;
//	char	query[ACCOUNT_SQL_LEN_MAX] = {0,};
//	ACCOUNT_MEMSET(query, 0, sizeof(query));

//	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s', '%s', '%s', '%s', '%s', '%s')",
//			ACCOUNT_TABLE, CAPABILITY_TABLE, ACCOUNT_CUSTOM_TABLE, ACCOUNT_TYPE_TABLE, LABEL_TABLE, PROVIDER_FEATURE_TABLE);
//	rc = _account_get_record_count(query);

//	if (rc != ACCOUNT_TABLE_TOTAL_COUNT) {
//		ACCOUNT_ERROR("Table count is not matched rc=%d\n", rc);
//	}

//	return rc;
//}

int _account_db_handle_close(sqlite3* hDB)
{
	int rc = 0;
	int ret = ACCOUNT_ERROR_NONE;
	if(hDB)
	{
		rc = db_util_close(hDB);
		if(  rc == SQLITE_OK )
			ret = ACCOUNT_ERROR_NONE;
		else if(  rc == SQLITE_PERM )
			ret = ACCOUNT_ERROR_PERMISSION_DENIED;
		else if ( rc == SQLITE_BUSY )
			ret = ACCOUNT_ERROR_DATABASE_BUSY;
		else
			ret = ACCOUNT_ERROR_DB_FAILED;
	}
	return ret;
}

int _account_db_open(int mode, int pid)
{
	int  rc = 0;
	int ret = -1;
	char account_db_path[256] = {0, };

	_INFO( "start _account_db_open()");

	ACCOUNT_MEMSET(account_db_path, 0x00, sizeof(account_db_path));
	ACCOUNT_SNPRINTF(account_db_path, sizeof(account_db_path), "%s", ACCOUNT_DB_PATH);

	if( g_hAccountDB ) {
		_ERR( "Account database is using in another app. %x", g_hAccountDB );
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}

	ret = _account_db_handle_close(g_hAccountDB2);
	if( ret != ACCOUNT_ERROR_NONE )
		ACCOUNT_DEBUG( "db_util_close(g_hAccountDB2) fail ret = %d", ret);

	ACCOUNT_DEBUG( "before db_util_open()");
	if(mode == ACCOUNT_DB_OPEN_READWRITE)
		rc = db_util_open(account_db_path, &g_hAccountDB, DB_UTIL_REGISTER_HOOK_METHOD);
	else if(mode == ACCOUNT_DB_OPEN_READONLY)
		rc = db_util_open_with_options(account_db_path, &g_hAccountDB, SQLITE_OPEN_READONLY, NULL);
	else
		return ACCOUNT_ERROR_DB_NOT_OPENED;
	ACCOUNT_DEBUG( "after db_util_open() sqlite_rc = %d", rc);

	if( rc == SQLITE_PERM || _account_db_err_code() == SQLITE_PERM ) {
		ACCOUNT_ERROR( "Account permission denied");
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if( rc == SQLITE_BUSY ) {
		ACCOUNT_ERROR( "busy handler fail.");
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}

	if( rc != SQLITE_OK ) {
		ACCOUNT_ERROR( "The database isn't connected." );
		return ACCOUNT_ERROR_DB_NOT_OPENED;
	}

	_INFO( "end _account_db_open()");
	return ACCOUNT_ERROR_NONE;
}

int _account_db_close(void)
{
	ACCOUNT_DEBUG( "start db_util_close()");
	int ret = -1;
/*
	ret = _account_db_handle_close(g_hAccountDB2);
	if( ret != ACCOUNT_ERROR_NONE )
		ACCOUNT_DEBUG( "db_util_close(g_hAccountDB2) fail ret = %d", ret);
*/
	ret = _account_db_handle_close(g_hAccountDB);
	if( ret != ACCOUNT_ERROR_NONE )
	{
		ACCOUNT_ERROR( "db_util_close(g_hAccountDB) fail ret = %d", ret);
		g_hAccountDB2 = g_hAccountDB;
	}
	g_hAccountDB = NULL;

	return ret;
}

static int _account_check_duplicated(account_s *data, const char* verified_appid)
{
	char query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int count = 0;
	int ret = -1;

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from %s where package_name='%s' and (user_name='%s' or display_name='%s' or email_address='%s')"
			, ACCOUNT_TABLE, verified_appid, data->user_name, data->display_name, data->email_address);

	count = _account_get_record_count(query);

	if (count<=0) {
		return ACCOUNT_ERROR_NONE;
	}

	//check whether duplicated account or not.
	//1. check user_name
	//2. check display_name
	//3. check email_address
	GList* account_list_temp = _account_query_account_by_package_name(getpid(), verified_appid, &ret);
	if (account_list_temp == NULL)
	{
		_ERR("_account_query_account_by_package_name returned NULL");
		return ACCOUNT_ERROR_DB_FAILED;
	}

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if(ret != ACCOUNT_ERROR_NONE){
		return ret;
	}

	account_list_temp = g_list_first(account_list_temp);
	_INFO("account_list_temp length=[%d]",g_list_length(account_list_temp));

	GList* iter = NULL;
	for (iter = account_list_temp; iter != NULL; iter = g_list_next(iter))
	{
		_INFO("iterating account_list_temp");
		account_s *account = NULL;
		_INFO("Before iter->data");
		account = (account_s*)iter->data;
		_INFO("After iter->data");
		if (account != NULL)
		{
			if(account->user_name!=NULL && data->user_name!=NULL && strcmp(account->user_name, data->user_name)==0)
			{
				_INFO("duplicated account(s) exist!, same user_name=%s", data->user_name);
				return ACCOUNT_ERROR_DUPLICATED;
			}
			//when user_name is not NULL and display_name is same.
			if(account->user_name==NULL && data->user_name==NULL && account->display_name!=NULL && data->display_name!=NULL && strcmp(account->display_name, data->display_name)==0)
			{
				_INFO("duplicated account(s) exist!, same display_name=%s", data->display_name);
				return ACCOUNT_ERROR_DUPLICATED;
			}
			//when user_name and display_name are not NULL and email_address is same.
			if(account->user_name==NULL && data->user_name==NULL && account->display_name==NULL && data->display_name==NULL && account->email_address!=NULL && data->email_address!=NULL && strcmp(account->email_address, data->email_address)==0)
			{
				_INFO("duplicated account(s) exist!, same email_address=%s", data->email_address);
				return ACCOUNT_ERROR_DUPLICATED;
			}
		}
	}

	return ACCOUNT_ERROR_NONE;
}

static int _account_get_next_sequence(const char *pszName)
{
	int 			rc = 0;
	account_stmt	pStmt = NULL;
	int 			max_seq = 0;
	char 			szQuery[ACCOUNT_SQL_LEN_MAX] = {0,};

	ACCOUNT_MEMSET(szQuery, 0x00, sizeof(szQuery));
	ACCOUNT_SNPRINTF(szQuery, sizeof(szQuery),  "SELECT max(seq) FROM %s where name = '%s' ", ACCOUNT_SQLITE_SEQ, pszName);
	rc = sqlite3_prepare_v2(g_hAccountDB, szQuery, strlen(szQuery), &pStmt, NULL);
	if (SQLITE_OK != rc) {
		ACCOUNT_SLOGE("sqlite3_prepare_v2() failed(%d, %s).", rc, _account_db_err_msg());
		sqlite3_finalize(pStmt);
		return ACCOUNT_ERROR_DB_FAILED;
	}

	rc = sqlite3_step(pStmt);
	max_seq = sqlite3_column_int(pStmt, 0);
	max_seq++;

	/*Finalize Statement*/
	rc = sqlite3_finalize(pStmt);
	pStmt = NULL;

	return max_seq;
}

static account_stmt _account_prepare_query(char *query)
{
	int 			rc = -1;
	account_stmt 	pStmt = NULL;

	ACCOUNT_RETURN_VAL((query != NULL), {}, NULL, ("query is NULL"));

	rc = sqlite3_prepare_v2(g_hAccountDB, query, strlen(query), &pStmt, NULL);

	ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, NULL, ("sqlite3_prepare_v2(%s) failed(%s).", query, _account_db_err_msg()));

	return pStmt;
}

static int _account_query_bind_int(account_stmt pStmt, int pos, int num)
{
	if(!pStmt){
		ACCOUNT_ERROR("statement is null");
		return -1;
	}

	if(pos < 0){
		ACCOUNT_ERROR("invalid pos");
		return -1;
	}

	return sqlite3_bind_int(pStmt, pos, num);
}

static int _account_query_bind_text(account_stmt pStmt, int pos, const char *str)
{
	_INFO("_account_query_bind_text");

	if(!pStmt)
	{
		_ERR("statement is null");
		return -1;
	}

	if(str)
	{
		_INFO("sqlite3_bind_text");
		return sqlite3_bind_text(pStmt, pos, (const char*)str, strlen(str), SQLITE_STATIC);
	}
	else
	{
		_INFO("sqlite3_bind_null");
		return sqlite3_bind_null(pStmt, pos);
	}
}

static int _account_convert_account_to_sql(account_s *account, account_stmt hstmt, char *sql_value)
{
	_INFO("start");

	int count = 1;

	/*Caution : Keep insert query orders.*/

	/* 1. user name*/
	_account_query_bind_text(hstmt, count++, (char*)account->user_name);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], user_name=%s", account->id, account->user_name);

	/* 2. email address*/
	_account_query_bind_text(hstmt, count++, (char*)account->email_address);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], email_address=%s", account->id, account->email_address);

	/* 3. display name*/
	_account_query_bind_text(hstmt, count++, (char*)account->display_name);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], display_name=%s", account->id, account->display_name);

	/* 4. icon path*/
	_account_query_bind_text(hstmt, count++, (char*)account->icon_path);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], icon_path=%s", account->id, account->icon_path);

	/* 5. source*/
	_account_query_bind_text(hstmt, count++, (char*)account->source);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], source=%s", account->id, account->source);

	/* 6. package name*/
	_account_query_bind_text(hstmt, count++, (char*)account->package_name);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], package_name=%s", account->id, account->package_name);

	/* 7. access token*/
	_account_query_bind_text(hstmt, count++, (char*)account->access_token);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], access_token=%s", account->id, account->access_token);

	/* 8. domain name*/
	_account_query_bind_text(hstmt, count++, (char*)account->domain_name);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], domain_name=%s", account->id, account->domain_name);

	/* 9. auth type*/
	_account_query_bind_int(hstmt, count++, account->auth_type);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], auth_type=%d", account->id, account->auth_type);

	/* 10. secret */
	_account_query_bind_int(hstmt, count++, account->secret);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], secret=%d", account->id, account->secret);

	/* 11. sync_support */
	_account_query_bind_int(hstmt, count++, account->sync_support);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], sync_support=%d", account->id, account->sync_support);

	int i;

	/* 12. user text*/
	for(i=0; i< USER_TXT_CNT; i++)
		_account_query_bind_text(hstmt, count++, (char*)account->user_data_txt[i]);

	/* 13. user integer	*/
	for(i=0; i< USER_INT_CNT; i++)
	{
		_account_query_bind_int(hstmt, count++, account->user_data_int[i]);
	_INFO("convert user_data_int : marshal_user_int data_int[%d]=%d", i, account->user_data_int[i]);
	}

	_INFO("end");

	return count;
}

static int _account_query_finalize(account_stmt pStmt)
{
	int rc = -1;

	if (!pStmt) {
		ACCOUNT_ERROR( "pStmt is NULL");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	rc = sqlite3_finalize(pStmt);
	if (rc == SQLITE_BUSY){
		ACCOUNT_ERROR(" sqlite3 busy = %d", rc);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	} else if (rc != SQLITE_OK) {
		ACCOUNT_ERROR( "sqlite3_finalize fail, rc : %d, db_error : %s\n", rc, _account_db_err_msg());
		return ACCOUNT_ERROR_DB_FAILED;
	}

	return ACCOUNT_ERROR_NONE;
}

static int _account_query_step(account_stmt pStmt)
{
	if(!pStmt){
		ACCOUNT_ERROR( "pStmt is NULL");
		return -1;
	}

	return sqlite3_step(pStmt);
}

static int _account_execute_insert_query(account_s *account)
{
	_INFO("_account_execute_insert_query start");

	int				rc = 0;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				error_code = ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;

	/* check whether app id exist in account type db */

	if (!account->user_name && !account->display_name && !account->email_address) {
		_INFO("");
		ACCOUNT_ERROR("Mandetory fields is NULL. At least one field is required among username, display name, email address\n");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	_INFO("");
	ACCOUNT_MEMSET(query, 0x00, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s (user_name, email_address , display_name , icon_path , source , package_name , "
			"access_token , domain_name , auth_type , secret , sync_support , txt_custom0, txt_custom1, txt_custom2, txt_custom3, txt_custom4, "
			"int_custom0, int_custom1, int_custom2, int_custom3, int_custom4, txt_custom0 ) values " // to do urusa
			"(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",	ACCOUNT_TABLE);

	hstmt = _account_prepare_query(query);
	ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg()));

	_INFO("");
	_account_convert_account_to_sql(account, hstmt, query);

	_INFO("");
	rc = _account_query_step(hstmt);
	if (rc != SQLITE_DONE) {
		_INFO("");
		ACCOUNT_ERROR( "account_db_query_step() failed(%d, %s)", rc, _account_db_err_msg());

		if( _account_db_err_code() == SQLITE_PERM )
			error_code = ACCOUNT_ERROR_PERMISSION_DENIED;
		else
			error_code = ACCOUNT_ERROR_DB_FAILED;
	}

	_INFO("");
	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	_INFO("_account_execute_insert_query end");
	return error_code;
}

static int _account_insert_capability(account_s *account, int account_id)
{
	_INFO("_account_insert_capability start");
	int 			rc, count = 1;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	account_stmt 	hstmt = NULL;

	ACCOUNT_RETURN_VAL((account != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));

	if (g_slist_length( account->capablity_list)==0) {
		ACCOUNT_DEBUG( "_account_insert_capability, no capability\n");
		return ACCOUNT_ERROR_NONE;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) from %s where _id=%d", ACCOUNT_TABLE, account_id);

	_INFO("_account_insert_capability _account_get_record_count [%s]", query);
	rc = _account_get_record_count(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		_ERR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}
	if (rc <= 0) {
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	/* insert query*/

	GSList *iter;

	for (iter = account->capablity_list; iter != NULL; iter = g_slist_next(iter)) {
		int ret;
		count = 1;

		account_capability_s* cap_data = NULL;
		cap_data = (account_capability_s*)iter->data;

		_INFO("cap_data->type = %s, cap_data->value = %d \n", cap_data->type, cap_data->value);

		ACCOUNT_MEMSET(query, 0x00, sizeof(query));
		ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s(key, value, package_name, user_name, account_id) VALUES "
				"(?, ?, ?, ?, ?) ", CAPABILITY_TABLE);
		hstmt = _account_prepare_query(query);

		ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg()));

		ret = _account_query_bind_text(hstmt, count++, cap_data->type);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_int(hstmt, count++, cap_data->value);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Integer binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)account->package_name);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)account->user_name);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_int(hstmt, count++, (int)account_id);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Integer binding fail"));

		rc = _account_query_step(hstmt);
		_INFO("_account_insert_capability _account_query_step[%d]", rc);

		if (rc != SQLITE_DONE) {
			_ERR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
			break;
		}

		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;

	}

	_INFO("_account_insert_capability end");
	return ACCOUNT_ERROR_NONE;
}

static int _account_update_capability(account_s *account, int account_id)
{
	int 			rc, count = 1;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	account_stmt 	hstmt = NULL;

	ACCOUNT_RETURN_VAL((account != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));

	if (g_slist_length( account->capablity_list)==0) {
		ACCOUNT_ERROR( "_account_update_capability, no capability\n");
		return ACCOUNT_ERROR_NONE;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) from %s where _id=%d", ACCOUNT_TABLE, account_id);

	rc = _account_get_record_count(query);

	if (rc <= 0) {
		ACCOUNT_SLOGI( "_account_update_capability : related account item is not existed rc=%d , %s", rc, _account_db_err_msg());
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE account_id=? ", CAPABILITY_TABLE);
	hstmt = _account_prepare_query(query);
	count = 1;
	_account_query_bind_int(hstmt, count++, (int)account_id);
	rc = _account_query_step(hstmt);

	if (rc != SQLITE_DONE) {
		ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
		return ACCOUNT_ERROR_DB_FAILED;
	}
	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	GSList *iter;

	for (iter = account->capablity_list; iter != NULL; iter = g_slist_next(iter)) {
		int ret;
		count = 1;
		ACCOUNT_MEMSET(query, 0x00, sizeof(query));
		ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s(key, value, package_name, user_name, account_id) VALUES "
				"(?, ?, ?, ?, ?) ", CAPABILITY_TABLE);

		hstmt = _account_prepare_query(query);

		ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg()));

		account_capability_s* cap_data = NULL;
		cap_data = (account_capability_s*)iter->data;

		ret = _account_query_bind_text(hstmt, count++, cap_data->type);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_int(hstmt, count++, cap_data->value);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Integer binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)account->package_name);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)account->user_name);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_int(hstmt, count++, (int)account_id);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Integer binding fail"));

		rc = _account_query_step(hstmt);

		if (rc != SQLITE_DONE) {
			ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
			break;
		}

		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;

	}

	return ACCOUNT_ERROR_NONE;
}

static int _account_update_capability_by_user_name(account_s *account, const char *user_name, const char *package_name )
{
	int 			rc, count = 1;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	account_stmt 	hstmt = NULL;

	ACCOUNT_RETURN_VAL((account != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));

	if (g_slist_length( account->capablity_list)==0) {
		ACCOUNT_ERROR( "_account_update_capability_by_user_name, no capability\n");
		return ACCOUNT_ERROR_NONE;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) from %s where package_name= '%s' and user_name='%s'", ACCOUNT_TABLE, package_name, user_name);

	rc = _account_get_record_count(query);

	if (rc <= 0) {
		ACCOUNT_SLOGI( "_account_update_capability_by_user_name : related account item is not existed rc=%d , %s ", rc, _account_db_err_msg());
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE package_name=? and user_name=? ", CAPABILITY_TABLE);
	hstmt = _account_prepare_query(query);
	count = 1;
	_account_query_bind_text(hstmt, count++, (char*)account->package_name);
	_account_query_bind_text(hstmt, count++, (char*)account->user_name);
	rc = _account_query_step(hstmt);
	if (rc != SQLITE_DONE) {
		ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
		return ACCOUNT_ERROR_DB_FAILED;
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	GSList* iter;

	for (iter = account->capablity_list; iter != NULL; iter = g_slist_next(iter)) {
		int ret;
		count = 1;
		ACCOUNT_MEMSET(query, 0x00, sizeof(query));
		ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s(key, value, package_name, user_name, account_id) VALUES "
				"(?, ?, ?, ?, ?) ", CAPABILITY_TABLE);

		hstmt = _account_prepare_query(query);

		ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg()));

		account_capability_s* cap_data = NULL;
		cap_data = (account_capability_s*)iter->data;

		ret = _account_query_bind_text(hstmt, count++, cap_data->type);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_int(hstmt, count++, cap_data->value);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Integer binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)account->package_name);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)account->user_name);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_int(hstmt, count++, (int)account->id);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Integer binding fail"));

		rc = _account_query_step(hstmt);

		if (rc != SQLITE_DONE) {
			ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
			break;
		}

		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;

	}

	return ACCOUNT_ERROR_NONE;
}

static int _account_query_table_column_int(account_stmt pStmt, int pos)
{
	if(!pStmt){
		ACCOUNT_ERROR("statement is null");
		return -1;
	}

	if(pos < 0){
		ACCOUNT_ERROR("invalid pos");
		return -1;
	}

	return sqlite3_column_int(pStmt, pos);
}

static const char *_account_query_table_column_text(account_stmt pStmt, int pos)
{
	if(!pStmt){
		ACCOUNT_ERROR("statement is null");
		return NULL;
	}

	if(pos < 0){
		ACCOUNT_ERROR("invalid pos");
		return NULL;
	}

	return (const char*)sqlite3_column_text(pStmt, pos);
}

static void _account_db_data_to_text(const char *textbuf, char **output)
{
	if (textbuf && strlen(textbuf)>0) {
		if (*output) {
			free(*output);
			*output = NULL;
		}
		*output = strdup(textbuf);
	}
}

static void _account_convert_column_to_account(account_stmt hstmt, account_s *account_record)
{
	const char *textbuf = NULL;

	account_record->id = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_ID);
	ACCOUNT_DEBUG("account_record->id =[%d]", account_record->id);

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_USER_NAME);
	_account_db_data_to_text(textbuf, &(account_record->user_name));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_EMAIL_ADDRESS);
	_account_db_data_to_text(textbuf, &(account_record->email_address));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_DISPLAY_NAME);
	_account_db_data_to_text(textbuf, &(account_record->display_name));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_ICON_PATH);
	_account_db_data_to_text(textbuf, &(account_record->icon_path));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_SOURCE);
	_account_db_data_to_text(textbuf, &(account_record->source));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_PACKAGE_NAME);
	_account_db_data_to_text(textbuf, &(account_record->package_name));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_ACCESS_TOKEN);
	_account_db_data_to_text(textbuf, &(account_record->access_token));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_DOMAIN_NAME);
	_account_db_data_to_text(textbuf, &(account_record->domain_name));

	account_record->auth_type = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_AUTH_TYPE);

	account_record->secret = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_SECRET);

	account_record->sync_support = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_SYNC_SUPPORT);

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_USER_TEXT_0);
	_account_db_data_to_text(textbuf, &(account_record->user_data_txt[0]));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_USER_TEXT_1);
	_account_db_data_to_text(textbuf, &(account_record->user_data_txt[1]));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_USER_TEXT_2);
	_account_db_data_to_text(textbuf, &(account_record->user_data_txt[2]));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_USER_TEXT_3);
	_account_db_data_to_text(textbuf, &(account_record->user_data_txt[3]));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_USER_TEXT_4);
	_account_db_data_to_text(textbuf, &(account_record->user_data_txt[4]));

	account_record->user_data_int[0] = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_USER_INT_0);
	account_record->user_data_int[1] = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_USER_INT_1);
	account_record->user_data_int[2] = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_USER_INT_2);
	account_record->user_data_int[3] = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_USER_INT_3);
	account_record->user_data_int[4] = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_USER_INT_4);
}

static void _account_convert_column_to_capability(account_stmt hstmt, account_capability_s *capability_record)
{
	const char *textbuf = NULL;

	_INFO("start _account_convert_column_to_capability()");
	capability_record->id = _account_query_table_column_int(hstmt, CAPABILITY_FIELD_ID);

	textbuf = _account_query_table_column_text(hstmt, CAPABILITY_FIELD_KEY);
	_account_db_data_to_text(textbuf, &(capability_record->type));

	capability_record->value = _account_query_table_column_int(hstmt, CAPABILITY_FIELD_VALUE);

	textbuf = _account_query_table_column_text(hstmt, CAPABILITY_FIELD_PACKAGE_NAME);
	_account_db_data_to_text(textbuf, &(capability_record->package_name));

	textbuf = _account_query_table_column_text(hstmt, CAPABILITY_FIELD_USER_NAME);
	_account_db_data_to_text(textbuf, &(capability_record->user_name));

	capability_record->account_id = _account_query_table_column_int(hstmt, CAPABILITY_FIELD_ACCOUNT_ID);
	_INFO("type = %s, value = %d", capability_record->type, capability_record->value);
	_INFO("end _account_convert_column_to_capability()");
}

static void _account_convert_column_to_custom(account_stmt hstmt, account_custom_s *custom_record)
{
	_INFO("start _account_convert_column_to_custom()");
	const char *textbuf = NULL;

	custom_record->account_id = _account_query_table_column_int(hstmt, ACCOUNT_CUSTOM_FIELD_ACCOUNT_ID);

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_CUSTOM_FIELD_APP_ID);
	_account_db_data_to_text(textbuf, &(custom_record->app_id));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_CUSTOM_FIELD_KEY);
	_account_db_data_to_text(textbuf, &(custom_record->key));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_CUSTOM_FIELD_VALUE);
	_account_db_data_to_text(textbuf, &(custom_record->value));
	_INFO("key = %s, value = %s", custom_record->key, custom_record->value);
	_INFO("end _account_convert_column_to_custom()");
}

bool _account_get_capability_text_cb(const char* capability_type, account_capability_state_e capability_value, void *user_data)
{
	account_s *data = (account_s*)user_data;

	account_capability_s *cap_data = (account_capability_s*)malloc(sizeof(account_capability_s));

	if (cap_data == NULL)
		return FALSE;
	ACCOUNT_MEMSET(cap_data, 0, sizeof(account_capability_s));

	cap_data->type = _account_get_text(capability_type);
	cap_data->value = capability_value;
	_INFO("cap_data->type = %s, cap_data->value = %d", cap_data->type, cap_data->value);

	data->capablity_list = g_slist_append(data->capablity_list, (gpointer)cap_data);

	return TRUE;
}


bool _account_get_custom_text_cb(char* key, char* value, void *user_data)
{
	account_s *data = (account_s*)user_data;

	account_custom_s *custom_data = (account_custom_s*)malloc(sizeof(account_custom_s));

	if (custom_data == NULL) {
		ACCOUNT_DEBUG("_account_get_custom_text_cb :: malloc fail\n");
		return FALSE;
	}
	ACCOUNT_MEMSET(custom_data, 0, sizeof(account_custom_s));

	custom_data->account_id = data->id;
	custom_data->app_id = _account_get_text(data->package_name);
	custom_data->key = _account_get_text(key);
	custom_data->value = _account_get_text(value);
	_INFO("custom_data->key = %s, custom_data->value = %s", custom_data->key, custom_data->value);

	data->custom_list = g_slist_append(data->custom_list, (gpointer)custom_data);

	return TRUE;
}


static char *_account_get_text(const char *text_data)
{
	char *text_value = NULL;

	if (text_data != NULL) {
		text_value = strdup(text_data);
	}
	return text_value;
}

static int _account_compare_old_record_by_user_name(account_s *new_account, const char* user_name, const char* package_name)
{
	int				error_code = ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				rc = 0;
	account_s *old_account = NULL;

	ACCOUNT_RETURN_VAL((new_account != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT IS NULL"));
	ACCOUNT_RETURN_VAL((user_name != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("USER NAME IS NULL"));
	ACCOUNT_RETURN_VAL((package_name != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("PACKAGE NAME IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	old_account = (account_s*)calloc(1, sizeof(account_s));
	if(!old_account) {
		ACCOUNT_FATAL("Memory alloc fail\n");
		return ACCOUNT_ERROR_OUT_OF_MEMORY;
	}

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE user_name = '%s' and package_name='%s'", ACCOUNT_TABLE, user_name, package_name);
	hstmt = _account_prepare_query(query);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	while (rc == SQLITE_ROW) {
		_account_convert_column_to_account(hstmt, old_account);
		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_CATCH_ERROR((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	// get capability
	error_code = _account_query_capability_by_account_id(_account_get_capability_text_cb, old_account->id, (void*)old_account);
	ACCOUNT_CATCH_ERROR((error_code == ACCOUNT_ERROR_NONE), {}, error_code, ("account_query_capability_by_account_id error"));

	// get custom text
	error_code = _account_query_custom_by_account_id(_account_get_custom_text_cb, old_account->id, (void*)old_account);
	ACCOUNT_CATCH_ERROR((error_code == ACCOUNT_ERROR_NONE), {}, error_code, ("_account_query_custom_by_account_id error"));

	// compare
	new_account->id = old_account->id;

	//user name
	if(!new_account->user_name) {
		if(old_account->user_name)
			new_account->user_name = _account_get_text(old_account->user_name);
	}

	// display name
	if(!new_account->display_name) {
		if(old_account->display_name)
			new_account->display_name = _account_get_text(old_account->display_name);
	}

	// email address
	if(!new_account->email_address) {
		if(old_account->email_address)
			new_account->email_address = _account_get_text(old_account->email_address);
	}

	// domain name
	if(!new_account->domain_name) {
		if(old_account->domain_name)
			new_account->domain_name = _account_get_text(old_account->domain_name);
	}

	// icon path
	if(!new_account->icon_path) {
		if(old_account->icon_path)
			new_account->icon_path = _account_get_text(old_account->icon_path);
	}

	// source
	if(!new_account->source) {
		if(old_account->source)
			new_account->source = _account_get_text(old_account->source);
	}

	_ACCOUNT_FREE(new_account->package_name);
	new_account->package_name = _account_get_text(old_account->package_name);

	// access token
	if(!new_account->access_token) {
		if(old_account->access_token)
			new_account->access_token = _account_get_text(old_account->access_token);
	}

	// auth type
	if(new_account->auth_type == ACCOUNT_AUTH_TYPE_INVALID) {
		new_account->auth_type = old_account->auth_type;
	}

	//secret
	if(new_account->secret== ACCOUNT_SECRECY_INVALID) {
		new_account->secret = old_account->secret;
	}

	// sync support
	if(new_account->sync_support == ACCOUNT_SYNC_INVALID) {
		new_account->sync_support = old_account->sync_support;
	}

	// TODO user text
	int i;
	for(i=0;i<USER_TXT_CNT;i++) {
		if(!new_account->user_data_txt[i]) {
			if(old_account->user_data_txt[i])
				new_account->user_data_txt[i] = _account_get_text(old_account->user_data_txt[i]);
		}
	}

	// TODO user int
	for(i=0;i<USER_INT_CNT;i++) {
		if(new_account->user_data_int[i] == 0) {
				new_account->user_data_int[i] = old_account->user_data_int[i];
		}
	}

	// capability

	// user custom table

CATCH:
	if (old_account) {
		_account_free_account_items(old_account);
		_ACCOUNT_FREE(old_account);
	}

	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	return ACCOUNT_ERROR_NONE;
}



static int _account_update_account_by_user_name(int pid, account_s *account, const char *user_name, const char *package_name)
{
	int				rc = 0, binding_count = 0, count = 0;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				error_code = ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;

	ACCOUNT_RETURN_VAL((user_name != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("user_name is NULL.\n"));
	ACCOUNT_RETURN_VAL((package_name!= NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("package_name is NULL.\n"));

	char* current_appid = NULL;
	char* verified_appid = NULL;

	current_appid = _account_get_current_appid(pid);
	error_code = _account_check_account_type_with_appid_group(current_appid, &verified_appid);

	_ACCOUNT_FREE(current_appid);
	_ACCOUNT_FREE(verified_appid);

	if(error_code != ACCOUNT_ERROR_NONE){
		ACCOUNT_ERROR("No permission to update\n");
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	_account_compare_old_record_by_user_name(account, user_name, package_name);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (!account->package_name) {
		ACCOUNT_ERROR("Package name is mandetory field, it can not be NULL!!!!\n");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if (!account->user_name && !account->display_name && !account->email_address) {
		ACCOUNT_ERROR("One field should be set among user name, display name, email address\n");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE user_name='%s' and package_name='%s'"
			, ACCOUNT_TABLE, user_name, package_name);

	count = _account_get_record_count(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (count <= 0) {
		ACCOUNT_SLOGI("_account_update_account_by_user_name : The account not exist!, count = %d, user_name=%s, package_name=%s\n",
			count, user_name, package_name);
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	//TODO: Is it required to update id ? As of now I can only think of falied rollback cases (between account and gSSO DB)
	ACCOUNT_SNPRINTF(query, sizeof(query), "UPDATE %s SET user_name=?, email_address =?, display_name =?, "
			"icon_path =?, source =?, package_name =? , access_token =?, domain_name =?, auth_type =?, secret =?, sync_support =?,"
			"txt_custom0=?, txt_custom1=?, txt_custom2=?, txt_custom3=?, txt_custom4=?, "
			"int_custom0=?, int_custom1=?, int_custom2=?, int_custom3=?, int_custom4=? WHERE user_name=? and package_name=? ", ACCOUNT_TABLE);

	hstmt = _account_prepare_query(query);
	if( _account_db_err_code() == SQLITE_PERM ){
		_account_end_transaction(FALSE);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}
	ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_svc_query_prepare() failed(%s).\n", _account_db_err_msg()));

	binding_count = _account_convert_account_to_sql(account, hstmt, query);

	_account_query_bind_text(hstmt, binding_count++, user_name);
	_account_query_bind_text(hstmt, binding_count++, package_name);
	rc = _account_query_step(hstmt);
	if (rc != SQLITE_DONE) {
		ACCOUNT_ERROR( "account_db_query_step() failed(%d, %s)", rc, _account_db_err_msg());
	}
	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	/*update capability*/
	error_code = _account_update_capability_by_user_name(account, user_name, package_name);

	/* update custom */
	error_code = _account_update_custom(account, account->id);

	return error_code;
}

int _account_insert_to_db(account_s* account, int pid, int *account_id)
{
	_INFO("");
	int		error_code = ACCOUNT_ERROR_NONE;
	int 	ret_transaction = 0;

	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));
	ACCOUNT_RETURN_VAL((account != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));
	ACCOUNT_RETURN_VAL((account_id != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT ID POINTER IS NULL"));

	if (!account->user_name && !account->display_name && !account->email_address) {
		ACCOUNT_ERROR("One field should be set among user name, display name, email address\n");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_s *data = (account_s*)account;
	ACCOUNT_SLOGD("(%s)-(%d) account_insert_to_db: begin_transaction.\n", __FUNCTION__, __LINE__);

	pthread_mutex_lock(&account_mutex);

	/* transaction control required*/
	ret_transaction = _account_begin_transaction();

	if(_account_db_err_code() == SQLITE_PERM){
		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (ret_transaction == ACCOUNT_ERROR_DATABASE_BUSY) {
		ACCOUNT_ERROR("account insert:_account_begin_transaction fail %d\n", ret_transaction);
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}else if (ret_transaction != ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account insert:_account_begin_transaction fail %d\n", ret_transaction);
		pthread_mutex_unlock(&account_mutex);
		return ret_transaction;
	}

	*account_id = _account_get_next_sequence(ACCOUNT_TABLE);
	data->id = *account_id;

	char* appid = NULL;
	appid = _account_get_current_appid(pid);

	if(!appid)
	{
		_INFO("");
		// API caller cannot be recognized
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("App id is not registered in account type DB, transaction ret (%x)!!!!\n", ret_transaction);
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_NOT_REGISTERED_PROVIDER;
	}

	_INFO("");
	char* verified_appid = NULL;
	error_code  = _account_check_account_type_with_appid_group(appid, &verified_appid);//FIX
	_ACCOUNT_FREE(appid);
	if(error_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("error_code = %d", error_code);
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("App id is not registered in account type DB, transaction ret (%x)!!!!\n", ret_transaction);
		_ACCOUNT_FREE(verified_appid);
		pthread_mutex_unlock(&account_mutex);
		return error_code;
	}

	if(verified_appid)
	{
		_INFO("");
		error_code = _account_check_duplicated(data, verified_appid);
		if (error_code != ACCOUNT_ERROR_NONE) {
			_INFO("");
			ret_transaction = _account_end_transaction(FALSE);
			ACCOUNT_DEBUG("_account_check_duplicated(), rollback insert query(%x)!!!!\n", ret_transaction);
			*account_id = -1;
			pthread_mutex_unlock(&account_mutex);
			return error_code;
		}
		if(!_account_check_add_more_account(verified_appid)) {
			ret_transaction = _account_end_transaction(FALSE);
			ACCOUNT_ERROR("No more account cannot be added, transaction ret (%x)!!!!\n", ret_transaction);
			pthread_mutex_unlock(&account_mutex);
			_ACCOUNT_FREE(verified_appid);
			return ACCOUNT_ERROR_NOT_ALLOW_MULTIPLE;
		}

		_ACCOUNT_FREE(data->package_name);
		data->package_name = _account_get_text(verified_appid);
		_ACCOUNT_FREE(verified_appid);
	}

	if(!_account_check_add_more_account(data->package_name))
	{
		_INFO("");
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("No more account cannot be added, transaction ret (%x)!!!!\n", ret_transaction);
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_NOT_ALLOW_MULTIPLE;
	}

	error_code = _account_execute_insert_query(data);

	if (error_code != ACCOUNT_ERROR_NONE)
	{
		_INFO("");
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("INSERT account fail, rollback insert query(%x)!!!!\n", ret_transaction);
		*account_id = -1;
		pthread_mutex_unlock(&account_mutex);
		return error_code;
	}

	_INFO("");
	error_code = _account_insert_capability(data, *account_id);
	if (error_code != ACCOUNT_ERROR_NONE)
	{
		_INFO("");
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("INSERT capability fail, rollback insert capability query(%x)!!!!\n", ret_transaction);
		*account_id = -1;
		pthread_mutex_unlock(&account_mutex);
		return error_code;
	}

	_INFO("");
	error_code = _account_insert_custom(data, *account_id);
	if (error_code != ACCOUNT_ERROR_NONE)
	{
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("INSERT custom fail, rollback insert capability query(%x)!!!!\n", ret_transaction);
		*account_id = -1;
		pthread_mutex_unlock(&account_mutex);
		return error_code;
	}

	_INFO("");

	pthread_mutex_unlock(&account_mutex);
	_account_end_transaction(TRUE);
	ACCOUNT_SLOGD("(%s)-(%d) account _end_transaction.\n", __FUNCTION__, __LINE__);

	char buf[64]={0,};
	ACCOUNT_SNPRINTF(buf, sizeof(buf), "%s:%d", ACCOUNT_NOTI_NAME_INSERT, *account_id);
	_account_insert_delete_update_notification_send(buf);
	_INFO("account _notification_send end.");

	return ACCOUNT_ERROR_NONE;

}

int _account_query_capability_by_account_id(capability_cb callback, int account_id, void *user_data )
{
	int 			error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;

	ACCOUNT_RETURN_VAL((account_id > 0), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT INDEX IS LESS THAN 0"));
	ACCOUNT_RETURN_VAL((callback != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("NO CALLBACK FUNCTION"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE account_id = %d", CAPABILITY_TABLE, account_id);
	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	account_capability_s* capability_record = NULL;

	while (rc == SQLITE_ROW) {
		bool cb_ret = FALSE;
		capability_record = (account_capability_s*) malloc(sizeof(account_capability_s));

		if (capability_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(capability_record, 0x00, sizeof(account_capability_s));

		_account_convert_column_to_capability(hstmt, capability_record);

		cb_ret = callback(capability_record->type, capability_record->value, user_data);

		_account_free_capability_items(capability_record);
		_ACCOUNT_FREE(capability_record);

		ACCOUNT_CATCH_ERROR(cb_ret == TRUE, {}, ACCOUNT_ERROR_NONE, ("Callback func returs FALSE, its iteration is stopped!!!!\n"));

		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);
	return error_code;
}

GSList* _account_get_capability_list_by_account_id(int account_id, int *error_code)
{
	*error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;
	GSList* capability_list = NULL;

	ACCOUNT_RETURN_VAL((account_id > 0), {*error_code = ACCOUNT_ERROR_INVALID_PARAMETER;}, NULL, ("ACCOUNT INDEX IS LESS THAN 0"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {*error_code = ACCOUNT_ERROR_DB_NOT_OPENED;}, NULL, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE account_id = %d", CAPABILITY_TABLE, account_id);
	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		*error_code = ACCOUNT_ERROR_PERMISSION_DENIED;
		return NULL;
	}

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR_P(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	account_capability_s* capability_record = NULL;

	while (rc == SQLITE_ROW) {
		capability_record = (account_capability_s*) malloc(sizeof(account_capability_s));

		if (capability_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(capability_record, 0x00, sizeof(account_capability_s));

		_account_convert_column_to_capability(hstmt, capability_record);

		//cb_ret = callback(capability_record->type, capability_record->value, user_data);

		//_account_free_capability_items(capability_record);
		//_ACCOUNT_FREE(capability_record);

		//ACCOUNT_CATCH_ERROR(cb_ret == TRUE, {}, ACCOUNT_ERROR_NONE, ("Callback func returs FALSE, its iteration is stopped!!!!\n"));

		capability_list = g_slist_append(capability_list, capability_record);
		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {*error_code = rc;}, NULL, ("finalize error"));
	hstmt = NULL;

	*error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL)
	{
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {*error_code = rc;}, NULL, ("finalize error"));
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);
	return capability_list;
}

static int _account_compare_old_record(account_s *new_account, int account_id)
{
	int				error_code = ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				rc = 0;
	account_s *old_account = NULL;

	ACCOUNT_RETURN_VAL((account_id > 0), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT INDEX IS LESS THAN 0"));
	ACCOUNT_RETURN_VAL((new_account != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	old_account = (account_s*)calloc(1, sizeof(account_s));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE _id = %d", ACCOUNT_TABLE, account_id);
	hstmt = _account_prepare_query(query);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	while (rc == SQLITE_ROW) {
		_account_convert_column_to_account(hstmt, old_account);
		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_CATCH_ERROR((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	// get capability
	error_code = _account_query_capability_by_account_id(_account_get_capability_text_cb, old_account->id, (void*)old_account);
	ACCOUNT_CATCH_ERROR((error_code == ACCOUNT_ERROR_NONE), {}, error_code, ("account_query_capability_by_account_id error"));

	// get custom text
	error_code = _account_query_custom_by_account_id(_account_get_custom_text_cb, old_account->id, (void*)old_account);
	ACCOUNT_CATCH_ERROR((error_code == ACCOUNT_ERROR_NONE), {}, error_code, ("_account_query_custom_by_account_id error"));

	// compare

	new_account->id = old_account->id;

	//user name
	if(!new_account->user_name) {
		if(old_account->user_name)
			new_account->user_name = _account_get_text(old_account->user_name);
	}

	// display name
	if(!new_account->display_name) {
		if(old_account->display_name)
			new_account->display_name = _account_get_text(old_account->display_name);
	}

	// email address
	if(!new_account->email_address) {
		if(old_account->email_address)
			new_account->email_address = _account_get_text(old_account->email_address);
	}

	// domain name
	if(!new_account->domain_name) {
		if(old_account->domain_name)
			new_account->domain_name = _account_get_text(old_account->domain_name);
	}

	// icon path
	if(!new_account->icon_path) {
		if(old_account->icon_path)
			new_account->icon_path = _account_get_text(old_account->icon_path);
	}

	// source
	if(!new_account->source) {
		if(old_account->source)
			new_account->source = _account_get_text(old_account->source);
	}

	_ACCOUNT_FREE(new_account->package_name);
	new_account->package_name = _account_get_text(old_account->package_name);

	// access token
	if(!new_account->access_token) {
		if(old_account->access_token)
			new_account->access_token = _account_get_text(old_account->access_token);
	}

	// user text
	int i;
	for(i=0;i<USER_TXT_CNT;i++) {
		if(!new_account->user_data_txt[i]) {
			if(old_account->user_data_txt[i])
				new_account->user_data_txt[i] = _account_get_text(old_account->user_data_txt[i]);
		}
	}

	// auth type
	if(new_account->auth_type == ACCOUNT_AUTH_TYPE_INVALID) {
		new_account->auth_type = old_account->auth_type;
	}

	//secret
	if(new_account->secret== ACCOUNT_SECRECY_INVALID) {
		new_account->secret = old_account->secret;
	}

	// sync support
	if(new_account->sync_support == ACCOUNT_SYNC_INVALID) {
		new_account->sync_support = old_account->sync_support;
	}

	// user int
	for(i=0;i<USER_INT_CNT;i++) {
		if(new_account->user_data_int[i] == 0) {
				new_account->user_data_int[i] = old_account->user_data_int[i];
		}
	}

	// capability

	// user custom table

CATCH:
		if (old_account) {
			_account_free_account_items(old_account);
			_ACCOUNT_FREE(old_account);
		}

		if (hstmt != NULL) {
			rc = _account_query_finalize(hstmt);
			ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
			hstmt = NULL;
		}

	return ACCOUNT_ERROR_NONE;
}

static int _account_get_package_name_from_account_id(int account_id, char **package_name)
{
	int				error_code = ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				rc = 0;
	account_s *old_account = NULL;

	ACCOUNT_RETURN_VAL((account_id > 0), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT INDEX IS LESS THAN 0"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	old_account = (account_s*)calloc(1, sizeof(account_s));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE _id = %d", ACCOUNT_TABLE, account_id);
	hstmt = _account_prepare_query(query);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	while (rc == SQLITE_ROW) {
		_account_convert_column_to_account(hstmt, old_account);
		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_CATCH_ERROR((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	// get package name.
	*package_name = _account_get_text(old_account->package_name);


	CATCH:
		if (old_account) {
			_account_free_account_items(old_account);
			_ACCOUNT_FREE(old_account);
		}

		if (hstmt != NULL) {
			rc = _account_query_finalize(hstmt);
			ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
			hstmt = NULL;
		}

	return error_code;

}

static int _account_update_account(int pid, account_s *account, int account_id)
{
	int				rc = 0, binding_count =0;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				error_code = ACCOUNT_ERROR_NONE, count=0, ret_transaction = 0;
	account_stmt 	hstmt = NULL;

	if (!account->package_name) {
		ACCOUNT_ERROR("Package name is mandetory field, it can not be NULL!!!!\n");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	/* Check permission of requested appid */
	char* current_appid = NULL;
	char *package_name = NULL;

	current_appid = _account_get_current_appid(pid);
	error_code = _account_get_package_name_from_account_id(account_id, &package_name);

	if(error_code != ACCOUNT_ERROR_NONE || package_name == NULL){
		ACCOUNT_ERROR("No package name with account_id\n");
		_ACCOUNT_FREE(current_appid);
		_ACCOUNT_FREE(package_name);
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	error_code = _account_check_appid_group_with_package_name(current_appid, package_name);
	ACCOUNT_DEBUG( "UPDATE:account_id[%d],current_appid[%s]package_name[%s]", account_id, current_appid, package_name); 	// TODO: remove the log later.

	_ACCOUNT_FREE(current_appid);
	_ACCOUNT_FREE(package_name);

	if(error_code != ACCOUNT_ERROR_NONE){
		ACCOUNT_ERROR("No permission to update\n");
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	_account_compare_old_record(account, account_id);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	} else if( _account_db_err_code() == SQLITE_BUSY ){
		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}

	if (!account->user_name && !account->display_name && !account->email_address) {
		ACCOUNT_ERROR("One field should be set among user name, display name, email address\n");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE _id = %d ", ACCOUNT_TABLE, account_id);

	count = _account_get_record_count(query);
	if (count <= 0) {
		ACCOUNT_DEBUG(" Account record not found, count = %d\n", count);
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	/* transaction control required*/
	ret_transaction = _account_begin_transaction();
	if( ret_transaction == ACCOUNT_ERROR_DATABASE_BUSY ){
		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg());
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "UPDATE %s SET user_name=?, email_address =?, display_name =?, "
			"icon_path =?, source =?, package_name =? , access_token =?, domain_name =?, auth_type =?, secret =?, sync_support =?,"
			"txt_custom0=?, txt_custom1=?, txt_custom2=?, txt_custom3=?, txt_custom4=?, "
			"int_custom0=?, int_custom1=?, int_custom2=?, int_custom3=?, int_custom4=? WHERE _id=? ", ACCOUNT_TABLE);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_svc_query_prepare() failed(%s)(%x).\n", _account_db_err_msg(), _account_end_transaction(FALSE)));

	binding_count = _account_convert_account_to_sql(account, hstmt, query);
	_account_query_bind_int(hstmt, binding_count++, account_id);

	rc = _account_query_step(hstmt);
	if (rc != SQLITE_DONE) {
		ACCOUNT_SLOGE( "account_db_query_step() failed(%d, %s)", rc, _account_db_err_msg());
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	_INFO("update query=%s", query);

	/*update capability*/
	error_code = _account_update_capability(account, account_id);
	if(error_code != ACCOUNT_ERROR_NONE && error_code!= ACCOUNT_ERROR_RECORD_NOT_FOUND){
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("update capability Failed, trying to roll back(%x) !!!\n", ret_transaction);
		return error_code;
	}

	/* update custom */
	error_code = _account_update_custom(account, account_id);
	if(error_code != ACCOUNT_ERROR_NONE && error_code!= ACCOUNT_ERROR_RECORD_NOT_FOUND){
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("update capability Failed, trying to roll back(%x) !!!\n", ret_transaction);
		return error_code;
	}

	ret_transaction = _account_end_transaction(TRUE);

	_INFO("update end");
	return error_code;
}


static int _account_update_account_ex(account_s *account, int account_id)
{
	int				rc = 0, binding_count =0;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				error_code = ACCOUNT_ERROR_NONE, count=0, ret_transaction = 0;
	account_stmt 	hstmt = NULL;

	if (!account->package_name) {
		ACCOUNT_ERROR("Package name is mandetory field, it can not be NULL!!!!\n");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	_account_compare_old_record(account, account_id);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (!account->user_name && !account->display_name && !account->email_address) {
		ACCOUNT_ERROR("One field should be set among user name, display name, email address\n");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE _id = %d ", ACCOUNT_TABLE, account_id);

	count = _account_get_record_count(query);
	if (count <= 0) {
		ACCOUNT_DEBUG(" Account record not found, count = %d\n", count);
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	/* transaction control required*/
	ret_transaction = _account_begin_transaction();
	if( ret_transaction == ACCOUNT_ERROR_DATABASE_BUSY ){
		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg());
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "UPDATE %s SET user_name=?, email_address =?, display_name =?, "
			"icon_path =?, source =?, package_name =? , access_token =?, domain_name =?, auth_type =?, secret =?, sync_support =?,"
			"txt_custom0=?, txt_custom1=?, txt_custom2=?, txt_custom3=?, txt_custom4=?, "
			"int_custom0=?, int_custom1=?, int_custom2=?, int_custom3=?, int_custom4=? WHERE _id=? ", ACCOUNT_TABLE);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_svc_query_prepare() failed(%s)(%x).\n", _account_db_err_msg(), _account_end_transaction(FALSE)));

	_INFO("account_update_to_db_by_id_ex_p : before convert() : account_id[%d], user_name=%s", account->id, account->user_name);
	binding_count = _account_convert_account_to_sql(account, hstmt, query);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], user_name=%s", account->id, account->user_name);
	_INFO("account_update_to_db_by_id_ex_p : before bind()");
	rc = _account_query_bind_int(hstmt, binding_count++, account_id);
	_INFO("account_update_to_db_by_id_ex_p : after bind() : ret = %d", rc);

	rc = _account_query_step(hstmt);
	if (rc != SQLITE_DONE) {
		ACCOUNT_SLOGE( "account_db_query_step() failed(%d, %s)", rc, _account_db_err_msg());
	}
	_INFO("account_update_to_db_by_id_ex_p : after query_step() : ret = %d", rc);

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;
	_INFO("account_update_to_db_by_id_ex_p : after query_filnalize() : ret = %d", rc);

	_INFO("account_update_to_db_by_id_ex_p : before update_capability()");
	/*update capability*/
	error_code = _account_update_capability(account, account_id);
	if(error_code != ACCOUNT_ERROR_NONE && error_code!= ACCOUNT_ERROR_RECORD_NOT_FOUND){
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("update capability Failed, trying to roll back(%x) !!!\n", ret_transaction);
		return error_code;
	}
	_INFO("account_update_to_db_by_id_ex_p : after update_capability()");

	_INFO("account_update_to_db_by_id_ex_p : before update_custom()");
	/* update custom */
	error_code = _account_update_custom(account, account_id);
	if(error_code != ACCOUNT_ERROR_NONE && error_code!= ACCOUNT_ERROR_RECORD_NOT_FOUND){
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("update capability Failed, trying to roll back(%x) !!!\n", ret_transaction);
		return error_code;
	}
	_INFO("account_update_to_db_by_id_ex_p : after update_custom()");

	ret_transaction = _account_end_transaction(TRUE);

	return error_code;
}


int _account_update_to_db_by_id(int pid, account_s* account, int account_id)
{
	ACCOUNT_RETURN_VAL((account != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("DATA IS NULL"));
	ACCOUNT_RETURN_VAL((account_id > 0), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Account id is not valid"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));
	int	error_code = ACCOUNT_ERROR_NONE;
	account_s* data = (account_s*)account;

	pthread_mutex_lock(&account_mutex);

	error_code = _account_update_account(pid, data, account_id);

	if(error_code != ACCOUNT_ERROR_NONE) {
		pthread_mutex_unlock(&account_mutex);
		return error_code;
	}

	pthread_mutex_unlock(&account_mutex);

	char buf[64]={0,};
	ACCOUNT_SNPRINTF(buf, sizeof(buf), "%s:%d", ACCOUNT_NOTI_NAME_UPDATE, account_id);
	_account_insert_delete_update_notification_send(buf);

	return ACCOUNT_ERROR_NONE;
}

int _account_update_to_db_by_id_ex(account_s* account, int account_id)
{
	ACCOUNT_RETURN_VAL((account != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("DATA IS NULL"));
	ACCOUNT_RETURN_VAL((account_id > 0), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Account id is not valid"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));
	int	error_code = ACCOUNT_ERROR_NONE;
	account_s* data = account;

	pthread_mutex_lock(&account_mutex);

	_INFO("before update_account_ex() : account_id[%d], user_name=%s", account_id, data->user_name);
	error_code = _account_update_account_ex(data, account_id);
	_INFO("after update_account_ex() : account_id[%d], user_name=%s", account_id, data->user_name);

	if(error_code != ACCOUNT_ERROR_NONE) {
		pthread_mutex_unlock(&account_mutex);
		return error_code;
	}

	pthread_mutex_unlock(&account_mutex);

	char buf[64]={0,};
	ACCOUNT_SNPRINTF(buf, sizeof(buf), "%s:%d", ACCOUNT_NOTI_NAME_UPDATE, account_id);
	_account_insert_delete_update_notification_send(buf);

	return ACCOUNT_ERROR_NONE;
}


int _account_update_to_db_by_user_name(int pid, account_s* account, const char *user_name, const char *package_name)
{
	ACCOUNT_RETURN_VAL((user_name != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("USER NAME IS NULL"));
	ACCOUNT_RETURN_VAL((package_name != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("PACKAGE NAME IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	int	error_code = ACCOUNT_ERROR_NONE;
	account_s *data = (account_s*)account;

	pthread_mutex_lock(&account_mutex);

	error_code = _account_update_account_by_user_name(pid, data, user_name, package_name);

	pthread_mutex_unlock(&account_mutex);

	char buf[64]={0,};
	ACCOUNT_SNPRINTF(buf, sizeof(buf), "%s:%d", ACCOUNT_NOTI_NAME_UPDATE, data->id);
	_account_insert_delete_update_notification_send(buf);

	return error_code;
}

GSList* _account_db_query_all(int pid)
{
	//int 			error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;
	GSList			*account_list = NULL;

	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, NULL, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s ", ACCOUNT_TABLE);
	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return NULL;
	}

	rc = _account_query_step(hstmt);

	account_s *account_record = NULL;

	if (rc != SQLITE_ROW)
	{
		_ERR("The record isn't found");
		goto CATCH;
	}

	while(rc == SQLITE_ROW) {
		account_record = (account_s*) malloc(sizeof(account_s));

		if (account_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(account_record, 0x00, sizeof(account_s));
		_account_convert_column_to_account(hstmt, account_record);
		account_list = g_slist_append(account_list, account_record);
		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, NULL, ("finalize error"));
	hstmt = NULL;

	GSList* iter;

	for (iter = account_list; iter != NULL; iter = g_slist_next(iter)) {
		account_s *account = NULL;
		account = (account_s*)iter->data;
		_account_query_capability_by_account_id(_account_get_capability_text_cb, account->id, (void*)account);
		_account_query_custom_by_account_id(_account_get_custom_text_cb, account->id, (void*)account);
	}

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {_account_gslist_free(account_list);}, NULL, ("finalize error"));
		hstmt = NULL;
	}
	if (account_list)
	{
		_remove_sensitive_info_from_non_owning_account_slist(pid, account_list);
	}
	return account_list;
}

int _account_update_sync_status_by_id(int account_db_id, const int sync_status)
{
	int				error_code = ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				rc = 0;
	int count =1;

	ACCOUNT_RETURN_VAL((account_db_id > 0), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT INDEX IS LESS THAN 0"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));
	if ( (sync_status < 0) || (sync_status > ACCOUNT_SYNC_STATUS_RUNNING)) {
		ACCOUNT_SLOGE("(%s)-(%d) sync_status is less than 0 or more than enum max.\n", __FUNCTION__, __LINE__);
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	pthread_mutex_lock(&account_mutex);

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) from %s where _id=%d", ACCOUNT_TABLE, account_db_id);

	rc = _account_get_record_count(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (rc <= 0) {
		ACCOUNT_SLOGE( "account_update_sync_status_by_id : related account item is not existed rc=%d , %s", rc, _account_db_err_msg());
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "UPDATE %s SET sync_support=? WHERE _id = %d", ACCOUNT_TABLE, account_db_id);
	hstmt = _account_prepare_query(query);

	_account_query_bind_int(hstmt, count, sync_status);

	rc = _account_query_step(hstmt);

	if( _account_db_err_code() == SQLITE_PERM ){
		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_DB_FAILED,
				("account_db_query_step() failed(%d, %s)", rc, _account_db_err_msg()));

	rc = _account_query_finalize(hstmt);
	if (rc != ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("_account_query_finalize error");
		pthread_mutex_unlock(&account_mutex);
		return rc;
	}
	char buf[64]={0,};
	ACCOUNT_SNPRINTF(buf, sizeof(buf), "%s:%d", ACCOUNT_NOTI_NAME_SYNC_UPDATE, account_db_id);
	_account_insert_delete_update_notification_send(buf);

	hstmt = NULL;
	error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);
	return error_code;
}

int _account_query_account_by_account_id(int pid, int account_db_id, account_s *account_record)
{
	_INFO("_account_query_account_by_account_id() start, account_db_id=[%d]", account_db_id);

	int				error_code = ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				rc = 0;

	ACCOUNT_RETURN_VAL((account_db_id > 0), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT INDEX IS LESS THAN 0"));
	ACCOUNT_RETURN_VAL(account_record != NULL, {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_DEBUG("starting db operations");

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE _id = %d", ACCOUNT_TABLE, account_db_id);
	hstmt = _account_prepare_query(query);
	rc = _account_db_err_code();
	_INFO("after _account_prepare_query, rc=[%d]", rc);

	if( rc == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	ACCOUNT_DEBUG("before _account_query_step");
	rc = _account_query_step(hstmt);
	ACCOUNT_DEBUG("after _account_query_step returned [%d]", rc);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	while (rc == SQLITE_ROW) {
		ACCOUNT_DEBUG("before _account_convert_column_to_account");
		_account_convert_column_to_account(hstmt, account_record);
		ACCOUNT_DEBUG("after _account_convert_column_to_account");
		ACCOUNT_DEBUG("user_name = %s, user_txt[0] = %s, user_int[1] = %d", account_record->user_name, account_record->user_data_txt[0], account_record->user_data_int[1]);
		rc = _account_query_step(hstmt);
	}

	ACCOUNT_DEBUG("account_record->id=[%d]", account_record->id);

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));

	ACCOUNT_DEBUG("before _account_query_capability_by_account_id");
	_account_query_capability_by_account_id(_account_get_capability_text_cb, account_record->id, (void*)account_record);
	ACCOUNT_DEBUG("after _account_query_capability_by_account_id");

	ACCOUNT_DEBUG("before _account_query_custom_by_account_id");
	_account_query_custom_by_account_id(_account_get_custom_text_cb, account_record->id, (void*)account_record);
	ACCOUNT_DEBUG("after _account_query_custom_by_account_id");

	hstmt = NULL;
	error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	if (account_record)
	{
		_remove_sensitive_info_from_non_owning_account(pid, account_record);
	}
	pthread_mutex_unlock(&account_mutex);
	ACCOUNT_DEBUG("_account_query_account_by_account_id end [%d]", error_code);
	return error_code;
}

GList* _account_query_account_by_user_name(int pid, const char *user_name, int *error_code)
{
	*error_code = ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				rc = 0;
	account_s *account_head = NULL;

	if (user_name == NULL)
	{
		_ERR("USER NAME IS NULL");
		*error_code = ACCOUNT_ERROR_INVALID_PARAMETER;
		goto CATCH;
	}

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE user_name = ?", ACCOUNT_TABLE);

	hstmt = _account_prepare_query(query);

	if (_account_db_err_code() == SQLITE_PERM)
	{
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		*error_code = ACCOUNT_ERROR_PERMISSION_DENIED;
		goto CATCH;
	}

	int binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, user_name);

	rc = _account_query_step(hstmt);

	if (rc != SQLITE_ROW)
	{
		_ERR("The record isn't found");
		*error_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		goto CATCH;
	}

	int tmp = 0;

	account_head = (account_s*) malloc(sizeof(account_s));
	if (account_head == NULL) {
		ACCOUNT_FATAL("malloc Failed");
		if (hstmt != NULL) {
			rc = _account_query_finalize(hstmt);

			if (rc != ACCOUNT_ERROR_NONE)
			{
				_ERR("finalize error");
				*error_code = rc;
				goto CATCH;
			}
			hstmt = NULL;
		}
		*error_code = ACCOUNT_ERROR_OUT_OF_MEMORY;
		goto CATCH;
	}
	ACCOUNT_MEMSET(account_head, 0x00, sizeof(account_s));

	while (rc == SQLITE_ROW) {
		account_s* account_record = NULL;

		account_record = (account_s*) malloc(sizeof(account_s));

		if (account_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}
		ACCOUNT_MEMSET(account_record, 0x00, sizeof(account_s));

		_account_convert_column_to_account(hstmt, account_record);

		account_head->account_list = g_list_append(account_head->account_list, account_record);

		rc = _account_query_step(hstmt);
		tmp++;
	}

	rc = _account_query_finalize(hstmt);

	if (rc != ACCOUNT_ERROR_NONE)
	{
		_ERR("finalize error");
		*error_code = rc;
		goto CATCH;
	}

	hstmt = NULL;

	GList *iter;


	tmp = g_list_length(account_head->account_list);

	for (iter = account_head->account_list; iter != NULL; iter = g_list_next(iter)) {
		account_h account;
		account = (account_h)iter->data;

		account_s *testaccount = (account_s*)account;

		_account_query_capability_by_account_id(_account_get_capability_text_cb, testaccount->id, (void*)testaccount);
		_account_query_custom_by_account_id(_account_get_custom_text_cb, testaccount->id, (void*)testaccount);

	}

	*error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		if (rc != ACCOUNT_ERROR_NONE)
		{
			_ERR("finalize error");
			*error_code = rc;
		}
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);
	if (account_head)
	{
		_remove_sensitive_info_from_non_owning_account_list(pid, account_head->account_list);
		GList* result = account_head->account_list;
		_ACCOUNT_FREE(account_head);
		return result;
	}
	return NULL;
}

GList*
_account_query_account_by_capability(int pid, const char* capability_type, const int capability_value, int *error_code)
{
	*error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;

	ACCOUNT_RETURN_VAL((capability_type != NULL), {*error_code = ACCOUNT_ERROR_INVALID_PARAMETER;}, NULL, ("capability_type IS NULL"));

	if ((capability_value  < 0) || (capability_value > ACCOUNT_CAPABILITY_ENABLED)) {
		ACCOUNT_SLOGE("(%s)-(%d) capability_value is not equal to 0 or 1.\n", __FUNCTION__, __LINE__);
		*error_code = ACCOUNT_ERROR_INVALID_PARAMETER;
		return NULL;
	}

	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {*error_code = ACCOUNT_ERROR_DB_NOT_OPENED;}, NULL, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE _id IN (SELECT account_id from %s WHERE key=? AND value=?)", ACCOUNT_TABLE, CAPABILITY_TABLE);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		*error_code = ACCOUNT_ERROR_PERMISSION_DENIED;
		return NULL;
	}

	int binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, capability_type);
	_account_query_bind_int(hstmt, binding_count++, capability_value);

	rc = _account_query_step(hstmt);

	account_s* account_head = NULL;

	ACCOUNT_CATCH_ERROR_P(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	int tmp = 0;

	account_head = (account_s*) malloc(sizeof(account_s));
	if (account_head == NULL) {
		ACCOUNT_FATAL("malloc Failed");
		if (hstmt != NULL) {
			rc = _account_query_finalize(hstmt);
			ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {*error_code = rc;}, NULL, ("finalize error"));
			hstmt = NULL;
		}
		*error_code = ACCOUNT_ERROR_OUT_OF_MEMORY;
		return NULL;
	}
	ACCOUNT_MEMSET(account_head, 0x00, sizeof(account_s));

	while (rc == SQLITE_ROW) {
		account_s* account_record = NULL;

		account_record = (account_s*) malloc(sizeof(account_s));

		if (account_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}
		ACCOUNT_MEMSET(account_record, 0x00, sizeof(account_s));

		_account_convert_column_to_account(hstmt, account_record);

		account_head->account_list = g_list_append(account_head->account_list, account_record);

		rc = _account_query_step(hstmt);
		tmp++;
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_CATCH_ERROR_P((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	GList *iter;


	tmp = g_list_length(account_head->account_list);

	for (iter = account_head->account_list; iter != NULL; iter = g_list_next(iter)) {
		account_h account = NULL;
		account = (account_h)iter->data;
		account_s* testaccount = (account_s*)account;

		_account_query_capability_by_account_id(_account_get_capability_text_cb, testaccount->id, (void*)testaccount);
		_account_query_custom_by_account_id(_account_get_custom_text_cb, testaccount->id, (void*)testaccount);

	}


	*error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		if ( rc != ACCOUNT_ERROR_NONE ) {
			*error_code = rc;
			_ERR("finalize error");
		}
		hstmt = NULL;
	}

	if( *error_code != ACCOUNT_ERROR_NONE && account_head ) {
		_account_glist_free(account_head->account_list);
		_ACCOUNT_FREE(account_head);
		account_head = NULL;
	}

	pthread_mutex_unlock(&account_mutex);

	if (account_head)
	{
		_remove_sensitive_info_from_non_owning_account_list(pid, account_head->account_list);
		GList* result = account_head->account_list;
		_ACCOUNT_FREE(account_head);
		return result;
	}
	return NULL;
}

GList* _account_query_account_by_capability_type(int pid, const char* capability_type, int *error_code)
{
	*error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;

	ACCOUNT_RETURN_VAL((capability_type != NULL), {*error_code = ACCOUNT_ERROR_INVALID_PARAMETER;}, NULL, ("capability_type IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {*error_code = ACCOUNT_ERROR_DB_NOT_OPENED;},
					   NULL, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE _id IN (SELECT account_id from %s WHERE key=?)", ACCOUNT_TABLE, CAPABILITY_TABLE);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		*error_code = ACCOUNT_ERROR_PERMISSION_DENIED;
		return NULL;
	}

	int binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, capability_type);

	rc = _account_query_step(hstmt);

	account_s* account_head = NULL;

	ACCOUNT_CATCH_ERROR_P(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	int tmp = 0;

	account_head = (account_s*) malloc(sizeof(account_s));
	if (account_head == NULL) {
		ACCOUNT_FATAL("malloc Failed");
		if (hstmt != NULL) {
			rc = _account_query_finalize(hstmt);
			ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {*error_code = rc;}, NULL, ("finalize error"));
			hstmt = NULL;
		}
		*error_code = ACCOUNT_ERROR_OUT_OF_MEMORY;
		return NULL;
	}
	ACCOUNT_MEMSET(account_head, 0x00, sizeof(account_s));

	while (rc == SQLITE_ROW) {
		account_s* account_record = NULL;

		account_record = (account_s*) malloc(sizeof(account_s));

		if (account_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}
		ACCOUNT_MEMSET(account_record, 0x00, sizeof(account_s));

		_account_convert_column_to_account(hstmt, account_record);

		account_head->account_list = g_list_append(account_head->account_list, account_record);

		rc = _account_query_step(hstmt);
		tmp++;
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_CATCH_ERROR_P((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	GList *iter;


	tmp = g_list_length(account_head->account_list);

	for (iter = account_head->account_list; iter != NULL; iter = g_list_next(iter)) {
		account_s* testaccount = (account_s*)iter->data;

		_account_query_capability_by_account_id(_account_get_capability_text_cb, testaccount->id, (void*)testaccount);
		_account_query_custom_by_account_id(_account_get_custom_text_cb, testaccount->id, (void*)testaccount);

	}

	*error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL)
	{
		rc = _account_query_finalize(hstmt);
		if (rc != ACCOUNT_ERROR_NONE) {
			*error_code = rc;
			_ERR("finalize error");
		}
		hstmt = NULL;
	}

	if( (*error_code != ACCOUNT_ERROR_NONE) && account_head ) {
		_account_glist_free(account_head->account_list);
		_ACCOUNT_FREE(account_head);
		account_head = NULL;
	}

	pthread_mutex_unlock(&account_mutex);

	if (account_head)
	{
		_remove_sensitive_info_from_non_owning_account_list(pid, account_head->account_list);
		GList* result = account_head->account_list;
		_ACCOUNT_FREE(account_head);
		return result;
	}
	return NULL;
}

GList* _account_query_account_by_package_name(int pid,const char* package_name, int *error_code)
{
	_INFO("_account_query_account_by_package_name");

	*error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;

	ACCOUNT_RETURN_VAL((package_name != NULL), {*error_code = ACCOUNT_ERROR_INVALID_PARAMETER;}, NULL, ("PACKAGE NAME IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {*error_code = ACCOUNT_ERROR_DB_NOT_OPENED;}, NULL, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE package_name=?", ACCOUNT_TABLE);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		*error_code = ACCOUNT_ERROR_PERMISSION_DENIED;
		return NULL;
	}

	int binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, package_name);

	rc = _account_query_step(hstmt);

	account_s* account_head = NULL;

	ACCOUNT_CATCH_ERROR_P(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.(%s)\n", package_name));

	int tmp = 0;

	account_head = (account_s*) malloc(sizeof(account_s));
	if (account_head == NULL) {
		ACCOUNT_FATAL("malloc Failed");
		if (hstmt != NULL) {
			rc = _account_query_finalize(hstmt);
			ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {*error_code = rc;}, NULL, ("finalize error"));
			hstmt = NULL;
		}
		*error_code = ACCOUNT_ERROR_OUT_OF_MEMORY;
		return NULL;
	}
	ACCOUNT_MEMSET(account_head, 0x00, sizeof(account_s));

	while (rc == SQLITE_ROW) {
		account_s* account_record = NULL;

		account_record = (account_s*) malloc(sizeof(account_s));

		if (account_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}
		ACCOUNT_MEMSET(account_record, 0x00, sizeof(account_s));

		_account_convert_column_to_account(hstmt, account_record);

		_INFO("Adding account_list");
		account_head->account_list = g_list_append(account_head->account_list, account_record);

		rc = _account_query_step(hstmt);
		tmp++;
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_CATCH_ERROR_P((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	GList *iter;

	tmp = g_list_length(account_head->account_list);

	for (iter = account_head->account_list; iter != NULL; iter = g_list_next(iter)) {
		account_s* testaccount = (account_s*)iter->data;

		_account_query_capability_by_account_id(_account_get_capability_text_cb, testaccount->id, (void*)testaccount);
		_account_query_custom_by_account_id(_account_get_custom_text_cb, testaccount->id, (void*)testaccount);
	}

	*error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL)
	{
		rc = _account_query_finalize(hstmt);
		if (rc != ACCOUNT_ERROR_NONE) {
			*error_code = rc;
			_ERR("finalize error");
		}
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);

	if( (*error_code != ACCOUNT_ERROR_NONE) && account_head ) {
		_account_glist_free(account_head->account_list);
		_ACCOUNT_FREE(account_head);
		account_head = NULL;
	}

	if ((*error_code == ACCOUNT_ERROR_NONE) && account_head != NULL)
	{
		_INFO("Returning account_list");
		_remove_sensitive_info_from_non_owning_account_list(pid,account_head->account_list);
		GList* result = account_head->account_list;
		_ACCOUNT_FREE(account_head);
		return result;
	}
	return NULL;
}

int _account_delete(int pid, int account_id)
{
	int				error_code = ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				rc = 0;
	int				ret_transaction = 0;
	bool			is_success = FALSE;

	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	int count = -1;
	/* Check requested ID to delete */
	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE _id=%d", ACCOUNT_TABLE, account_id);

	count = _account_get_record_count(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (count <= 0) {
		ACCOUNT_ERROR("account id(%d) is not exist. count(%d)\n", account_id, count);
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	/* Check permission of requested appid */
	char* current_appid = NULL;
	char *package_name = NULL;

	current_appid = _account_get_current_appid(pid);

	error_code = _account_get_package_name_from_account_id(account_id, &package_name);

	if(error_code != ACCOUNT_ERROR_NONE){
		ACCOUNT_ERROR("No package name with account_id\n");
		_ACCOUNT_FREE(current_appid);
		_ACCOUNT_FREE(package_name);
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}
	ACCOUNT_DEBUG( "DELETE:account_id[%d],current_appid[%s]package_name[%s]", account_id, current_appid, package_name);

	error_code = _account_check_appid_group_with_package_name(current_appid, package_name);

	_ACCOUNT_FREE(current_appid);
	_ACCOUNT_FREE(package_name);

	if(error_code != ACCOUNT_ERROR_NONE){
		ACCOUNT_ERROR("No permission to delete\n");
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	/* transaction control required*/
	ret_transaction = _account_begin_transaction();

	if( _account_db_err_code() == SQLITE_PERM ){
		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if( ret_transaction == ACCOUNT_ERROR_DATABASE_BUSY ){
		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg());
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}

	if (ret_transaction != ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account_delete:_account_begin_transaction fail %d\n", ret_transaction);
		pthread_mutex_unlock(&account_mutex);
		return ret_transaction;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE account_id = %d", CAPABILITY_TABLE, account_id);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg()));

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	rc = _account_query_finalize(hstmt);

	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	ACCOUNT_MEMSET(query, 0, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE _id = %d", ACCOUNT_TABLE, account_id);

	hstmt = _account_prepare_query(query);
	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg()));

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found. id=%d, rc=%d\n", account_id, rc));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	/* delete custom data */
	ACCOUNT_MEMSET(query, 0, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE AccountId = %d", ACCOUNT_CUSTOM_TABLE, account_id);

	hstmt = _account_prepare_query(query);

	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg()));

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found. id=%d, rc=%d\n", account_id, rc));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_CATCH_ERROR(rc == ACCOUNT_ERROR_NONE, {}, rc, ("finalize error", account_id, rc));
	hstmt = NULL;

	is_success = TRUE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		if(rc != ACCOUNT_ERROR_NONE ){
			ACCOUNT_ERROR("rc (%d)", rc);
			is_success = FALSE;
		}

		hstmt = NULL;
	}

	ret_transaction = _account_end_transaction(is_success);

	if (ret_transaction != ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account_delete:_account_end_transaction fail %d, is_success=%d\n", ret_transaction, is_success);
	} else {
		if (is_success == true) {
			char buf[64]={0,};
			ACCOUNT_SNPRINTF(buf, sizeof(buf), "%s:%d", ACCOUNT_NOTI_NAME_DELETE, account_id);
			_account_insert_delete_update_notification_send(buf);
		}
	}

	pthread_mutex_unlock(&account_mutex);

	return error_code;

}

static int _account_query_account_by_username_and_package(const char* username, const char* package_name, account_h *account)
{
	//FIXME
	//return -1;
	int				error_code = ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				rc = 0;
	int				binding_count = 1;

	ACCOUNT_RETURN_VAL((username != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("username IS NULL"));
	ACCOUNT_RETURN_VAL((package_name != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("package_name IS NULL"));
	ACCOUNT_RETURN_VAL((*account != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE user_name = ? and package_name = ?", ACCOUNT_TABLE);
	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	_account_query_bind_text(hstmt, binding_count++, username);
	_account_query_bind_text(hstmt, binding_count++, package_name);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	account_s *account_record = (account_s *)(*account);

	while (rc == SQLITE_ROW) {
		_account_convert_column_to_account(hstmt, account_record);
		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	_account_query_capability_by_account_id(_account_get_capability_text_cb, account_record->id, (void*)account_record);
	_account_query_custom_by_account_id(_account_get_custom_text_cb, account_record->id, (void*)account_record);

	hstmt = NULL;
	error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);
	return error_code;
}

int _account_create(account_h *account)
{
	if (!account) {
		ACCOUNT_SLOGE("(%s)-(%d) account is NULL.\n", __FUNCTION__, __LINE__);
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_s *data = (account_s*)malloc(sizeof(account_s));

	if (data == NULL) {
		ACCOUNT_FATAL("Memory Allocation Failed");
		return ACCOUNT_ERROR_OUT_OF_MEMORY;
	}
	ACCOUNT_MEMSET(data, 0, sizeof(account_s));

	/*Setting account as visible by default*/
	data->secret = ACCOUNT_SECRECY_VISIBLE;

	/*Setting account as not supporting sync by default*/
	data->sync_support = ACCOUNT_SYNC_NOT_SUPPORT;

	*account = (account_h)data;

	return ACCOUNT_ERROR_NONE;
}

int _account_destroy(account_h account)
{
	account_s *data = (account_s*)account;

	ACCOUNT_RETURN_VAL((data != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Account handle is null!"));

	_account_free_account_items(data);
	_ACCOUNT_FREE(data);

	return ACCOUNT_ERROR_NONE;
}

int _account_get_account_id(account_s* account, int *account_id)
{
	if (!account) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}
	if (!account_id) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	*account_id = account->id;

	return ACCOUNT_ERROR_NONE;
}

int _account_delete_from_db_by_user_name(int pid, const char *user_name, const char *package_name)
{
	_INFO("[%s][%s]", user_name, package_name);

	int 			error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;
	int 			ret_transaction = 0;
	bool			is_success = FALSE;
	account_h		account = NULL;
	int 			binding_count = 1;
	int				account_id = -1;

	ACCOUNT_RETURN_VAL((user_name != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("user_name is null!"));
	ACCOUNT_RETURN_VAL((package_name != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("package_name is null!"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	/* Check permission of requested appid */
	char* current_appid = NULL;
	char* package_name_temp = NULL;

	current_appid = _account_get_current_appid(pid);

	package_name_temp = _account_get_text(package_name);

	ACCOUNT_DEBUG( "DELETE:user_name[%s],current_appid[%s], package_name[%s]", user_name, current_appid, package_name_temp);

	error_code = _account_check_appid_group_with_package_name(current_appid, package_name_temp);

	_ACCOUNT_FREE(current_appid);
	_ACCOUNT_FREE(package_name_temp);

	if(error_code != ACCOUNT_ERROR_NONE){
		ACCOUNT_ERROR("No permission to delete\n");
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	rc = _account_create(&account);
	rc = _account_query_account_by_username_and_package(user_name, package_name, &account);

	_INFO("");

	if( _account_db_err_code() == SQLITE_PERM )
	{
		_account_destroy(account);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	_INFO("");
	account_s* account_data = (account_s*)account;

	rc = _account_get_account_id(account_data, &account_id);

	rc = _account_destroy(account);

	/* transaction control required*/
	ret_transaction = _account_begin_transaction();

	if( _account_db_err_code() == SQLITE_PERM )
	{
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	_INFO("");
	if( ret_transaction == ACCOUNT_ERROR_DATABASE_BUSY )
	{
		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg());
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}
	else if (ret_transaction != ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account_delete:_account_begin_transaction fail %d\n", ret_transaction);
		pthread_mutex_unlock(&account_mutex);
		return ret_transaction;
	}

	/* delete custom data */
	ACCOUNT_MEMSET(query, 0, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE AccountId = ?", ACCOUNT_CUSTOM_TABLE);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		_account_end_transaction(FALSE);
		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg()));

	_account_query_bind_int(hstmt, binding_count++, account_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	/* delete capability */
	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE user_name = ? and package_name = ?", CAPABILITY_TABLE);

	hstmt = _account_prepare_query(query);

	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg()));

	binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, user_name);
	_account_query_bind_text(hstmt, binding_count++, package_name);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	ACCOUNT_MEMSET(query, 0, sizeof(query));

	_INFO("");
	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE user_name = ? and package_name = ?", ACCOUNT_TABLE);

	hstmt = _account_prepare_query(query);
	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg()));

	_INFO("");
	binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, user_name);
	_account_query_bind_text(hstmt, binding_count++, package_name);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found. user_name=%s, package_name=%s, rc=%d\n", user_name, package_name, rc));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	is_success = TRUE;

	hstmt = NULL;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	ret_transaction = _account_end_transaction(is_success);

	if (ret_transaction != ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account_svc_delete:_account_svc_end_transaction fail %d, is_success=%d\n", ret_transaction, is_success);
	} else {
		if (is_success == true) {
			char buf[64]={0,};
			ACCOUNT_SNPRINTF(buf, sizeof(buf), "%s:%d", ACCOUNT_NOTI_NAME_DELETE, account_id);
			_account_insert_delete_update_notification_send(buf);
		}
	}

	pthread_mutex_unlock(&account_mutex);

	return error_code;
}

int _account_delete_from_db_by_package_name(int pid, const char *package_name, gboolean permission)
{
	_INFO("_account_delete_from_db_by_package_name");
	int 			error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;
	int 			ret_transaction = 0;
	bool			is_success = FALSE;
	int 			binding_count = 1;
	GSList			*account_id_list = NULL;
	int				ret = -1;

	ACCOUNT_RETURN_VAL((package_name != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("package_name is null!"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	// It only needs list of ids, does not need to query sensitive info. So sending 0
	GList* account_list_temp = _account_query_account_by_package_name(getpid(), package_name, &ret);
	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if(ret != ACCOUNT_ERROR_NONE){
		_ERR("_account_query_account_by_package_name failed ret=[%d]", ret);
		return ret;
	}

	/* Check permission of requested appid */
	if(permission){
		char* current_appid = NULL;
		char* package_name_temp = NULL;

		current_appid = _account_get_current_appid(pid);

		package_name_temp = _account_get_text(package_name);

		ACCOUNT_DEBUG( "DELETE: current_appid[%s], package_name[%s]", current_appid, package_name_temp);

		error_code = _account_check_appid_group_with_package_name(current_appid, package_name_temp);

		_ACCOUNT_FREE(current_appid);
		_ACCOUNT_FREE(package_name_temp);

		if(error_code != ACCOUNT_ERROR_NONE){
			ACCOUNT_ERROR("No permission to delete\n");
			_account_glist_free(account_list_temp);
			return ACCOUNT_ERROR_PERMISSION_DENIED;
		}
	}

	GList *account_list = g_list_first(account_list_temp);
	_INFO("account_list_temp length=[%d]",g_list_length(account_list));

	GList* iter = NULL;
	for (iter = account_list; iter != NULL; iter = g_list_next(iter))
	{
		_INFO("iterating account_list");
		account_s *account = NULL;
		_INFO("Before iter->data");
		account = (account_s*)iter->data;
		_INFO("After iter->data");
		if (account != NULL)
		{
			char id[256] = {0, };

			ACCOUNT_MEMSET(id, 0, 256);

			ACCOUNT_SNPRINTF(id, 256, "%d", account->id);

			_INFO("Adding account id [%s]", id);
			account_id_list = g_slist_append(account_id_list, g_strdup(id));
		}
	}

	_account_glist_free(account_list_temp);

	/* transaction control required*/
	ret_transaction = _account_begin_transaction();

	if( _account_db_err_code() == SQLITE_PERM ){
		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if( ret_transaction == ACCOUNT_ERROR_DATABASE_BUSY ){
		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg());
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}else if (ret_transaction != ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account_delete:_account_begin_transaction fail %d\n", ret_transaction);
		pthread_mutex_unlock(&account_mutex);
		return ret_transaction;
	}

	/* delete custom table  */
	ACCOUNT_MEMSET(query, 0, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE AppId = ?", ACCOUNT_CUSTOM_TABLE);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		_account_end_transaction(FALSE);
		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg()));

	binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, package_name);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	/* delete capability table */
	ACCOUNT_MEMSET(query, 0, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE package_name = ?", CAPABILITY_TABLE);

	hstmt = _account_prepare_query(query);

	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg()));

	binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, package_name);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	/* delete account table */
	ACCOUNT_MEMSET(query, 0, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE package_name = ?", ACCOUNT_TABLE);

	hstmt = _account_prepare_query(query);
	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg()));

	binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, package_name);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found. package_name=%s, rc=%d\n", package_name, rc));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	is_success = TRUE;

	hstmt = NULL;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	ret_transaction = _account_end_transaction(is_success);

	if (ret_transaction != ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account_delete:_account_end_transaction fail %d, is_success=%d\n", ret_transaction, is_success);
	} else {
		if (is_success == true) {
			GSList* gs_iter = NULL;
			for (gs_iter = account_id_list; gs_iter != NULL; gs_iter = g_slist_next(gs_iter)) {
				char* p_tmpid = NULL;
				p_tmpid = (char*)gs_iter->data;
				char buf[64]={0,};
				ACCOUNT_SNPRINTF(buf, sizeof(buf), "%s:%s", ACCOUNT_NOTI_NAME_DELETE, p_tmpid);
				ACCOUNT_SLOGD("%s", buf);
				_account_insert_delete_update_notification_send(buf);
				_ACCOUNT_FREE(p_tmpid);
			}
			g_slist_free(account_id_list);
		}
	}

	pthread_mutex_unlock(&account_mutex);

	_INFO("_account_delete_from_db_by_package_name end");
	return error_code;
}

int _account_get_total_count_from_db(gboolean include_hidden, int *count)
{
	if (!count) {
		ACCOUNT_SLOGE("(%s)-(%d) count is NULL.\n", __FUNCTION__, __LINE__);
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if(!g_hAccountDB){
		ACCOUNT_ERROR("DB is not opened\n");
		return ACCOUNT_ERROR_DB_NOT_OPENED;
	}

	char query[1024] = {0, };
	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	if (include_hidden)
	{
		ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from %s", ACCOUNT_TABLE);
	}
	else
	{
		ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from %s where secret = %d", ACCOUNT_TABLE, ACCOUNT_SECRECY_VISIBLE);
	}

	*count = _account_get_record_count(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	int rc = -1;
	int ncount = 0;
	account_stmt pStmt = NULL;

	rc = sqlite3_prepare_v2(g_hAccountDB, query, strlen(query), &pStmt, NULL);
	if (SQLITE_OK != rc) {
		ACCOUNT_SLOGE("sqlite3_prepare_v2() failed(%d, %s).", rc, _account_db_err_msg());
		sqlite3_finalize(pStmt);
		return ACCOUNT_ERROR_DB_FAILED;
	}

	rc = sqlite3_step(pStmt);
	if (SQLITE_ROW != rc) {
		ACCOUNT_ERROR("[ERROR] sqlite3_step() failed\n");
		sqlite3_finalize(pStmt);
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	ncount = sqlite3_column_int(pStmt, 0);

	*count = ncount;

	sqlite3_finalize(pStmt);

	if (ncount < 0) {
		ACCOUNT_ERROR("[ERROR] Number of account : %d, End", ncount);
		return ACCOUNT_ERROR_DB_FAILED;
	}

	return ACCOUNT_ERROR_NONE;
}

int account_type_create(account_type_h *account_type)
{
	if (!account_type) {
		ACCOUNT_SLOGE("(%s)-(%d) account type handle is NULL.\n", __FUNCTION__, __LINE__);
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_type_s *data = (account_type_s*)malloc(sizeof(account_type_s));

	if (data == NULL) {
		ACCOUNT_ERROR("Memory Allocation Failed");
		return ACCOUNT_ERROR_OUT_OF_MEMORY;
	}

	ACCOUNT_MEMSET(data, 0, sizeof(account_type_s));

	*account_type = (account_type_h)data;

	return ACCOUNT_ERROR_NONE;
}

int account_type_destroy(account_type_h account_type)
{
	account_type_s *data = (account_type_s*)account_type;

	ACCOUNT_RETURN_VAL((data != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Account type handle is null!"));

	_account_type_free_account_type_items(data);
	_ACCOUNT_FREE(data);

	return ACCOUNT_ERROR_NONE;
}

//app_id mandatory field
int account_type_set_app_id(account_type_h account_type, const char *app_id)
{
	if (!account_type) {
		ACCOUNT_SLOGE("(%s)-(%d) account_type handle is NULL.\n", __FUNCTION__, __LINE__);
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if (!app_id) {
		ACCOUNT_SLOGE("(%s)-(%d) app_id is NULL.\n", __FUNCTION__, __LINE__);
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_type_s *data = (account_type_s*)account_type;

	_ACCOUNT_FREE(data->app_id);
	data->app_id = _account_get_text(app_id);

	return ACCOUNT_ERROR_NONE;
}

//service_provider_id mandatory field
int account_type_set_service_provider_id(account_type_h account_type, const char *service_provider_id)
{
	if (!account_type) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if (!service_provider_id) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_type_s *data = (account_type_s*)account_type;

	_ACCOUNT_FREE(data->service_provider_id);
	data->service_provider_id = _account_get_text(service_provider_id);

	return ACCOUNT_ERROR_NONE;
}

int account_type_set_icon_path(account_type_h account_type, const char *icon_path)
{
	if (!account_type) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if (!icon_path) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_type_s *data = (account_type_s*)account_type;

	_ACCOUNT_FREE(data->icon_path);
	data->icon_path = _account_get_text(icon_path);

	return ACCOUNT_ERROR_NONE;
}

int account_type_set_small_icon_path(account_type_h account_type, const char *small_icon_path)
{
	if (!account_type) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if (!small_icon_path) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_type_s *data = (account_type_s*)account_type;

	_ACCOUNT_FREE(data->small_icon_path);
	data->small_icon_path = _account_get_text(small_icon_path);

	return ACCOUNT_ERROR_NONE;
}

int account_type_set_multiple_account_support(account_type_h account_type, const bool multiple_account_support)
{
	ACCOUNT_RETURN_VAL((account_type != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("(%s)-(%d) account handle is NULL.\n",  __FUNCTION__, __LINE__));

	account_type_s *data = (account_type_s*)account_type;

	data->multiple_account_support = multiple_account_support;

	return ACCOUNT_ERROR_NONE;
}

// unset?
int account_type_set_label(account_type_h account_type, const char* label, const char* locale)
{
	if (!account_type) {
		ACCOUNT_SLOGE("(%s)-(%d) account_type handle is NULL.\n", __FUNCTION__, __LINE__);
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if(!label || !locale) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_type_s *data = (account_type_s*)account_type;
	label_s *label_data = (label_s*)malloc(sizeof(label_s));

	if (label_data == NULL) {
		return ACCOUNT_ERROR_OUT_OF_MEMORY;
	}
	ACCOUNT_MEMSET(label_data, 0, sizeof(label_s));

	label_data->label = _account_get_text(label);
	label_data->locale = _account_get_text(locale);

	data->label_list = g_slist_append(data->label_list, (gpointer)label_data);

	return ACCOUNT_ERROR_NONE;
}

int account_type_get_app_id(account_type_h account_type, char **app_id)
{
	if (!account_type) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if (!app_id) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_type_s *data = (account_type_s*)account_type;

	(*app_id) = NULL;
	*app_id = _account_get_text(data->app_id);

	return ACCOUNT_ERROR_NONE;
}

int account_type_get_service_provider_id(account_type_h account_type, char **service_provider_id)
{
	if (!account_type) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if (!service_provider_id) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_type_s *data = (account_type_s*)account_type;

	(*service_provider_id) = NULL;
	*service_provider_id = _account_get_text(data->service_provider_id);

	return ACCOUNT_ERROR_NONE;
}

int account_type_get_icon_path(account_type_h account_type, char **icon_path)
{
	if (!account_type) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if (!icon_path) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_type_s *data = (account_type_s*)account_type;

	(*icon_path) = NULL;
	*icon_path = _account_get_text(data->icon_path);

	return ACCOUNT_ERROR_NONE;
}

int account_type_get_small_icon_path(account_type_h account_type, char **small_icon_path)
{
	if (!account_type) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if (!small_icon_path) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_type_s *data = (account_type_s*)account_type;

	(*small_icon_path) = NULL;
	*small_icon_path = _account_get_text(data->small_icon_path);

	return ACCOUNT_ERROR_NONE;
}

int account_type_get_multiple_account_support(account_type_h account_type, int *multiple_account_support)
{
	if (!account_type) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}
	if (!multiple_account_support) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	account_type_s *data = (account_type_s*)account_type;

	*multiple_account_support = data->multiple_account_support;

	return ACCOUNT_ERROR_NONE;
}

int account_type_get_label_by_locale(account_type_h account_type, const char* locale, char** label)
{
	ACCOUNT_RETURN_VAL((account_type != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));
	ACCOUNT_RETURN_VAL((label != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("INVALID PARAMETER"));

	GSList *iter;
	account_type_s *data = (account_type_s*)account_type;

	for (iter = data->label_list; iter != NULL; iter = g_slist_next(iter)) {
		label_s *label_data = NULL;

		label_data = (label_s*)iter->data;

		*label = NULL;

		if(!strcmp(locale, label_data->locale)) {
			*label = _account_get_text(label_data->label);
			return ACCOUNT_ERROR_NONE;
		}
	}

	return ACCOUNT_ERROR_RECORD_NOT_FOUND;
}

int account_type_get_label(account_type_h account_type, account_label_cb callback, void *user_data)
{
	ACCOUNT_RETURN_VAL((account_type != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));
	ACCOUNT_RETURN_VAL((callback != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("NO CALLBACK FUNCTION"));

	GSList *iter;
	account_type_s *data = (account_type_s*)account_type;

	for (iter = data->label_list; iter != NULL; iter = g_slist_next(iter)) {
		label_s *label_data = NULL;

		label_data = (label_s*)iter->data;

		if(callback(label_data->app_id, label_data->label, label_data->locale, user_data)!=TRUE) {
			ACCOUNT_DEBUG("Callback func returs FALSE, its iteration is stopped!!!!\n");
			return ACCOUNT_ERROR_NONE;
		}
	}

	return ACCOUNT_ERROR_NONE;
}

static gboolean _account_type_check_duplicated(account_type_s *data)
{
	char query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int count = 0;

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE AppId='%s'"
			, ACCOUNT_TYPE_TABLE, data->app_id);

	count = _account_get_record_count(query);
	if (count > 0) {
		return TRUE;
	}

	return FALSE;
}

static int _account_type_convert_account_to_sql(account_type_s *account_type, account_stmt hstmt, char *sql_value)
{
	_INFO("");

	int count = 1;

	/*Caution : Keep insert query orders.*/

	/* 1. app id*/
	_account_query_bind_text(hstmt, count++, (char*)account_type->app_id);

	/* 2. service provider id*/
	_account_query_bind_text(hstmt, count++, (char*)account_type->service_provider_id);

	/* 3. icon path*/
	_account_query_bind_text(hstmt, count++, (char*)account_type->icon_path);

	/* 4. small icon path*/
	_account_query_bind_text(hstmt, count++, (char*)account_type->small_icon_path);

	/* 5. multiple accont support*/
	_account_query_bind_int(hstmt, count++, account_type->multiple_account_support);

	_INFO("");

	return count;
}


static int _account_type_execute_insert_query(account_type_s *account_type)
{
	_INFO("");

	int				rc = 0;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				error_code = ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;

	/* check mandatory field */
	// app id & service provider id
	if (!account_type->app_id) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s( AppId, ServiceProviderId , IconPath , SmallIconPath , MultipleAccountSupport ) values "
			"(?, ?, ?, ?, ?)",	ACCOUNT_TYPE_TABLE);

	_INFO("");
	hstmt = _account_prepare_query(query);
	_INFO("");

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	} else if( _account_db_err_code() == SQLITE_BUSY ){
		ACCOUNT_ERROR( "Database Busy(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}

	ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg()));

	_INFO("");
	_account_type_convert_account_to_sql(account_type, hstmt, query);
	_INFO("");

	rc = _account_query_step(hstmt);
	if (rc == SQLITE_BUSY) {
		ACCOUNT_ERROR( "account_db_query_step() failed(%d, %s)", rc, _account_db_err_msg());
		error_code = ACCOUNT_ERROR_DATABASE_BUSY;
	} else if (rc != SQLITE_DONE) {
		ACCOUNT_ERROR( "account_db_query_step() failed(%d, %s)", rc, _account_db_err_msg());
		error_code = ACCOUNT_ERROR_DB_FAILED;
	}

	_INFO("");
	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	_INFO("");
	return error_code;
}

static int _account_type_insert_label(account_type_s *account_type)
{
	int 			rc, count = 1;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	account_stmt 	hstmt = NULL;

	ACCOUNT_RETURN_VAL((account_type != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));

	if (g_slist_length( account_type->label_list)==0) {
		ACCOUNT_ERROR( "_account_type_insert_label, no label\n");
		return ACCOUNT_ERROR_NONE;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) from %s where AppId = '%s'", ACCOUNT_TYPE_TABLE, account_type->app_id);

	rc = _account_get_record_count(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (rc <= 0) {
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	/* insert query*/
	GSList *iter;

	for (iter = account_type->label_list; iter != NULL; iter = g_slist_next(iter)) {
		int ret;
		count = 1;
		ACCOUNT_MEMSET(query, 0x00, sizeof(query));
		ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s(AppId, Label, Locale) VALUES "
				"(?, ?, ?) ", LABEL_TABLE);

		hstmt = _account_prepare_query(query);

		ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg()));

		label_s* label_data = NULL;
		label_data = (label_s*)iter->data;

		ret = _account_query_bind_text(hstmt, count++, account_type->app_id);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, label_data->label);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)label_data->locale);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));

		rc = _account_query_step(hstmt);

		if (rc != SQLITE_DONE) {
			ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
			break;
		}

		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;

	}

	return ACCOUNT_ERROR_NONE;
}

static void _account_type_convert_column_to_provider_feature(account_stmt hstmt, provider_feature_s *feature_record)
{
	const char *textbuf = NULL;

	textbuf = _account_query_table_column_text(hstmt, PROVIDER_FEATURE_FIELD_APP_ID);
	_account_db_data_to_text(textbuf, &(feature_record->app_id));

	textbuf = _account_query_table_column_text(hstmt, PROVIDER_FEATURE_FIELD_KEY);
	_account_db_data_to_text(textbuf, &(feature_record->key));

}

GSList* _account_type_query_provider_feature_by_app_id(const char* app_id, int *error_code)
{
	_INFO("_account_type_query_provider_feature_by_app_id");
	*error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0, binding_count = 1;
	GSList* feature_list = NULL;

	ACCOUNT_RETURN_VAL((app_id != NULL), {*error_code = ACCOUNT_ERROR_INVALID_PARAMETER;}, NULL, ("APP ID IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {*error_code = ACCOUNT_ERROR_DB_NOT_OPENED;}, NULL, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE app_id = ?", PROVIDER_FEATURE_TABLE);
	_INFO("account query=[%s]", query);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		*error_code = ACCOUNT_ERROR_PERMISSION_DENIED;
		return NULL;
	}

	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {*error_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;}, NULL, ("The record isn't found.\n"));

	provider_feature_s* feature_record = NULL;

	while (rc == SQLITE_ROW) {

		feature_record = (provider_feature_s*) malloc(sizeof(provider_feature_s));

		if (feature_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(feature_record, 0x00, sizeof(provider_feature_s));

		_account_type_convert_column_to_provider_feature(hstmt, feature_record);

		_INFO("Adding account feature_list");
		feature_list = g_slist_append(feature_list, feature_record);

		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {*error_code = rc;}, NULL, ("account finalize error"));
	hstmt = NULL;

	*error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {*error_code = rc;}, NULL, ("account finalize error"));
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);

	_INFO("Returning account feature_list");
	return feature_list;
}

int account_type_query_provider_feature_by_app_id(provider_feature_cb callback, const char* app_id, void *user_data )
{
	int 			error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0, binding_count = 1;

	ACCOUNT_RETURN_VAL((app_id != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("APP ID IS NULL"));
	ACCOUNT_RETURN_VAL((callback != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("NO CALLBACK FUNCTION"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE app_id = ?", PROVIDER_FEATURE_TABLE);
	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	provider_feature_s* feature_record = NULL;

	while (rc == SQLITE_ROW) {
		bool cb_ret = FALSE;
		feature_record = (provider_feature_s*) malloc(sizeof(provider_feature_s));

		if (feature_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(feature_record, 0x00, sizeof(provider_feature_s));

		_account_type_convert_column_to_provider_feature(hstmt, feature_record);

		cb_ret = callback(feature_record->app_id, feature_record->key, user_data);

		_account_type_free_feature_items(feature_record);
		_ACCOUNT_FREE(feature_record);

		ACCOUNT_CATCH_ERROR(cb_ret == TRUE, {}, ACCOUNT_ERROR_NONE, ("Callback func returs FALSE, its iteration is stopped!!!!\n"));

		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);
	return error_code;
}

bool _account_type_query_supported_feature(const char* app_id, const char* capability, int *error_code)
{
	_INFO("_account_type_query_supported_feature start");

	*error_code = ACCOUNT_ERROR_NONE;

	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			record_count = 0;

	if (app_id == NULL || capability == NULL)
	{
		*error_code = ACCOUNT_ERROR_INVALID_PARAMETER;
		return false;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s where app_id='%s' and key='%s'", PROVIDER_FEATURE_TABLE, app_id, capability);

	record_count = _account_get_record_count(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		*error_code = ACCOUNT_ERROR_PERMISSION_DENIED;
		return false;
	}

	if (record_count <= 0)
	{
		*error_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		return false;
	}

	_INFO("_account_type_query_supported_feature end");
	return true;

}


int account_type_get_provider_feature_all(account_type_h account_type, provider_feature_cb callback, void* user_data)
{
	ACCOUNT_RETURN_VAL((account_type != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));
	ACCOUNT_RETURN_VAL((callback != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("NO CALLBACK FUNCTION"));

	GSList *iter;
	account_type_s *data = (account_type_s*)account_type;

	for (iter = data->provider_feature_list; iter != NULL; iter = g_slist_next(iter)) {
		provider_feature_s *feature_data = NULL;

		feature_data = (provider_feature_s*)iter->data;

		if(callback(feature_data->app_id, feature_data->key, user_data)!=TRUE) {
			ACCOUNT_DEBUG("Callback func returs FALSE, its iteration is stopped!!!!\n");
			return ACCOUNT_ERROR_NONE;
		}
	}

	return ACCOUNT_ERROR_NONE;
}

int account_type_set_provider_feature(account_type_h account_type, const char* provider_feature)
{
	ACCOUNT_RETURN_VAL((account_type != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("account type handle is null"));
	ACCOUNT_RETURN_VAL((provider_feature != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("provider_feature is null"));

	account_type_s *data = (account_type_s*)account_type;

	GSList *iter = NULL;
	bool b_is_new = TRUE;

	for(iter = data->provider_feature_list; iter != NULL; iter = g_slist_next(iter)) {
		provider_feature_s *feature_data = NULL;
		feature_data = (provider_feature_s*)iter->data;

		if(!strcmp(feature_data->key, provider_feature)) {
			b_is_new = FALSE;
			break;
		}
	}

	if(b_is_new) {
		provider_feature_s* feature_data = (provider_feature_s*)malloc(sizeof(provider_feature_s));

		if (feature_data == NULL)
			return ACCOUNT_ERROR_OUT_OF_MEMORY;
		ACCOUNT_MEMSET(feature_data, 0, sizeof(provider_feature_s));

		feature_data->key = _account_get_text(provider_feature);
		data->provider_feature_list = g_slist_append(data->provider_feature_list, (gpointer)feature_data);
	}

	return ACCOUNT_ERROR_NONE;
}

static int _account_type_insert_provider_feature(account_type_s *account_type, const char* app_id)
{
	int 			rc, count = 1;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	account_stmt 	hstmt = NULL;

	ACCOUNT_RETURN_VAL((account_type != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));
	ACCOUNT_RETURN_VAL((app_id != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("APP ID IS NULL"));

	if (g_slist_length( account_type->provider_feature_list)==0) {
		ACCOUNT_ERROR( "no capability\n");
		return ACCOUNT_ERROR_NONE;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) from %s where AppId='%s'", ACCOUNT_TYPE_TABLE, app_id);

	rc = _account_get_record_count(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (rc <= 0) {
		ACCOUNT_SLOGI( "related account type item is not existed rc=%d , %s", rc, _account_db_err_msg());
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	/* insert query*/

	GSList *iter;

	for (iter = account_type->provider_feature_list; iter != NULL; iter = g_slist_next(iter)) {
		int ret;
		count = 1;
		ACCOUNT_MEMSET(query, 0x00, sizeof(query));
		ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s(app_id, key) VALUES "
				"(?, ?) ", PROVIDER_FEATURE_TABLE);

		hstmt = _account_prepare_query(query);

		ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg()));

		provider_feature_s* feature_data = NULL;
		feature_data = (provider_feature_s*)iter->data;

		ret = _account_query_bind_text(hstmt, count++, app_id);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, feature_data->key);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Integer binding fail"));

		rc = _account_query_step(hstmt);

		if (rc != SQLITE_DONE) {
			ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
			break;
		}

		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;

	}

	return ACCOUNT_ERROR_NONE;
}

int _account_type_insert_to_db(account_type_s* account_type, int* account_type_id)
{
	_INFO("");

	int		error_code = ACCOUNT_ERROR_NONE, ret_transaction = 0;

	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));
	ACCOUNT_RETURN_VAL((account_type != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT TYPE HANDLE IS NULL"));
	ACCOUNT_RETURN_VAL((account_type_id != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT TYPE ID POINTER IS NULL"));

	account_type_s *data = (account_type_s*)account_type;

	pthread_mutex_lock(&account_mutex);


	/* transaction control required*/
	ret_transaction = _account_begin_transaction();

	_INFO("");

	if( _account_db_err_code() == SQLITE_PERM ){
		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	_INFO("");
	if( ret_transaction == ACCOUNT_ERROR_DATABASE_BUSY ){
		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg());
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	} else if (ret_transaction != ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("_account_begin_transaction fail %d\n", ret_transaction);
		pthread_mutex_unlock(&account_mutex);
		return ret_transaction;
	}

	_INFO("");
	if (_account_type_check_duplicated(data)) {
		_INFO("");
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("Duplicated, rollback insert query(%x)!!!!\n", ret_transaction);
		*account_type_id = -1;
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_DUPLICATED;
	} else {
		_INFO("");
		*account_type_id = _account_get_next_sequence(ACCOUNT_TYPE_TABLE);

		error_code = _account_type_execute_insert_query(data);

		if (error_code != ACCOUNT_ERROR_NONE){
			error_code = ACCOUNT_ERROR_DUPLICATED;
			ret_transaction = _account_end_transaction(FALSE);
			ACCOUNT_ERROR("Insert fail, rollback insert query(%x)!!!!\n", ret_transaction);
			*account_type_id = -1;
			pthread_mutex_unlock(&account_mutex);
			return error_code;
		}
	}

	_INFO("");
	error_code = _account_type_insert_provider_feature(data, data->app_id);
	if(error_code != ACCOUNT_ERROR_NONE) {
		_INFO("");
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("Insert provider feature fail(%x), rollback insert query(%x)!!!!\n", error_code, ret_transaction);
		pthread_mutex_unlock(&account_mutex);
		return error_code;
	}
	_INFO("");
	error_code = _account_type_insert_label(data);
	if(error_code != ACCOUNT_ERROR_NONE) {
		_INFO("");
		ret_transaction = _account_end_transaction(FALSE);
		ACCOUNT_ERROR("Insert label fail(%x), rollback insert query(%x)!!!!\n", error_code, ret_transaction);
		pthread_mutex_unlock(&account_mutex);
		return error_code;
	}

	ret_transaction = _account_end_transaction(TRUE);
	_INFO("");
	pthread_mutex_unlock(&account_mutex);

	_INFO("");
	return ACCOUNT_ERROR_NONE;
}

static int _account_type_update_provider_feature(account_type_s *account_type, const char* app_id)
{
	int 			rc, count = 1;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	account_stmt	hstmt = NULL;

	ACCOUNT_RETURN_VAL((account_type != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));

	if (g_slist_length( account_type->provider_feature_list)==0) {
		ACCOUNT_ERROR( "no feature\n");
		return ACCOUNT_ERROR_NONE;
	}

	ACCOUNT_DEBUG( "app id", app_id);

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE app_id=? ", PROVIDER_FEATURE_TABLE);
	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	count = 1;
	_account_query_bind_text(hstmt, count++, app_id);
	rc = _account_query_step(hstmt);

	if (rc != SQLITE_DONE) {
		ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
		return ACCOUNT_ERROR_DB_FAILED;
	}
	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	GSList *iter;

	for (iter = account_type->provider_feature_list; iter != NULL; iter = g_slist_next(iter)) {
		int ret;
		count = 1;
		ACCOUNT_MEMSET(query, 0x00, sizeof(query));
		ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s(app_id, key) VALUES "
				"(?, ?) ", PROVIDER_FEATURE_TABLE);

		hstmt = _account_prepare_query(query);

		ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg()));

		provider_feature_s* feature_data = NULL;
		feature_data = (provider_feature_s*)iter->data;

		ret = _account_query_bind_text(hstmt, count++, account_type->app_id);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, feature_data->key);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));

		rc = _account_query_step(hstmt);

		if (rc != SQLITE_DONE) {
			ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
			break;
		}
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	return ACCOUNT_ERROR_NONE;
}

static int _account_type_update_label(account_type_s *account_type, const char* app_id)
{
	int 			rc, count = 1;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	account_stmt 	hstmt = NULL;

	ACCOUNT_RETURN_VAL((account_type != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));

	if (g_slist_length( account_type->label_list)==0) {
		return ACCOUNT_ERROR_NONE;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE AppId=? ", LABEL_TABLE);
	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	count = 1;
	_account_query_bind_text(hstmt, count++, app_id);
	rc = _account_query_step(hstmt);

	if (rc != SQLITE_DONE) {
		ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
		return ACCOUNT_ERROR_DB_FAILED;
	}
	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	GSList *iter;

	for (iter = account_type->label_list; iter != NULL; iter = g_slist_next(iter)) {
		int ret;
		count = 1;
		ACCOUNT_MEMSET(query, 0x00, sizeof(query));
		ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s(AppId, Label, Locale) VALUES "
				"(?, ?, ?) ", LABEL_TABLE);

		hstmt = _account_prepare_query(query);

		ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg()));

		label_s* label_data = NULL;
		label_data = (label_s*)iter->data;

		ret = _account_query_bind_text(hstmt, count++, account_type->app_id);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, label_data->label);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, label_data->locale);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));

		rc = _account_query_step(hstmt);

		if (rc != SQLITE_DONE) {
			ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
			break;
		}
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	return ACCOUNT_ERROR_NONE;
}


static int _account_type_update_account(account_type_s *account_type, const char* app_id)
{
	int				rc = 0, binding_count =1;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				error_code = ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;

	if (!account_type->app_id) {
		ACCOUNT_ERROR("app id is mandetory field, it can not be NULL!!!!\n");
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "UPDATE %s SET AppId=?, ServiceProviderId=?, IconPath=?, "
			"SmallIconPath=?, MultipleAccountSupport=? WHERE AppId=? ", ACCOUNT_TYPE_TABLE);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	} else if (_account_db_err_code() == SQLITE_BUSY){
		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}

	ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_svc_query_prepare() failed(%s).\n", _account_db_err_msg()));

	binding_count = _account_type_convert_account_to_sql(account_type, hstmt, query);
	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	if (rc != SQLITE_DONE) {
		ACCOUNT_ERROR( "account_db_query_step() failed(%d, %s)", rc, _account_db_err_msg());
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	/*update label*/
	error_code = _account_type_update_label(account_type, app_id);
	/* update provider feature */
	error_code = _account_type_update_provider_feature(account_type, app_id);

	return error_code;
}

int _account_type_update_to_db_by_app_id(account_type_s* account_type, const char* app_id)
{
	ACCOUNT_RETURN_VAL((account_type != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("DATA IS NULL"));
	ACCOUNT_RETURN_VAL((app_id != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("APP ID IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	int	error_code = ACCOUNT_ERROR_NONE;
	account_type_s* data = account_type;

	pthread_mutex_lock(&account_mutex);

	error_code = _account_type_update_account(data, app_id);

	pthread_mutex_unlock(&account_mutex);

	return error_code;
}

int _account_type_delete_by_app_id(const char* app_id)
{
	int 			error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0, count = -1;
	int 			ret_transaction = 0;
	int				binding_count = 1;
	bool			is_success = FALSE;

	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));
	ACCOUNT_RETURN_VAL((app_id != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("The database isn't connected."));

	/* Check requested ID to delete */
	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE AppId = '%s'", ACCOUNT_TYPE_TABLE, app_id);

	count = _account_get_record_count(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (count <= 0) {
		ACCOUNT_SLOGE("app id(%s) is not exist. count(%d)\n", app_id, count);
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	/* transaction control required*/
	ret_transaction = _account_begin_transaction();

	if( ret_transaction == ACCOUNT_ERROR_DATABASE_BUSY ){
		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg());
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}else if (ret_transaction != ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account_delete:_account_begin_transaction fail %d\n", ret_transaction);
		pthread_mutex_unlock(&account_mutex);
		return ret_transaction;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE AppId = ?", LABEL_TABLE);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg()));

	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	binding_count = 1;
	ACCOUNT_MEMSET(query, 0, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE app_id = ? ", PROVIDER_FEATURE_TABLE);

	hstmt = _account_prepare_query(query);
	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg()));

	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found. AppId=%s, rc=%d\n", app_id, rc));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	is_success = TRUE;

	hstmt = NULL;

	binding_count = 1;
	ACCOUNT_MEMSET(query, 0, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE AppId = ? ", ACCOUNT_TYPE_TABLE);

	hstmt = _account_prepare_query(query);
	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg()));

	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found. AppId=%s, rc=%d\n", app_id, rc));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	is_success = TRUE;

	hstmt = NULL;

	CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	ret_transaction = _account_end_transaction(is_success);

	if (ret_transaction != ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account_svc_delete:_account_svc_end_transaction fail %d, is_success=%d\n", ret_transaction, is_success);
	}

	pthread_mutex_unlock(&account_mutex);

	return error_code;
}

static void _account_type_convert_column_to_account_type(account_stmt hstmt, account_type_s *account_type_record)
{
	const char *textbuf = NULL;

	account_type_record->id = _account_query_table_column_int(hstmt, ACCOUNT_TYPE_FIELD_ID);

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_TYPE_FIELD_APP_ID);
	_account_db_data_to_text(textbuf, &(account_type_record->app_id));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_TYPE_FIELD_SERVICE_PROVIDER_ID);
	_account_db_data_to_text(textbuf, &(account_type_record->service_provider_id));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_TYPE_FIELD_ICON_PATH);
	_account_db_data_to_text(textbuf, &(account_type_record->icon_path));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_TYPE_FIELD_SMALL_ICON_PATH);
	_account_db_data_to_text(textbuf, &(account_type_record->small_icon_path));

	account_type_record->multiple_account_support = _account_query_table_column_int(hstmt, ACCOUNT_TYPE_FIELD_MULTIPLE_ACCOUNT_SUPPORT);

}

static void _account_type_convert_column_to_label(account_stmt hstmt, label_s *label_record)
{
	const char *textbuf = NULL;

	textbuf = _account_query_table_column_text(hstmt, LABEL_FIELD_APP_ID);
	_account_db_data_to_text(textbuf, &(label_record->app_id));

	textbuf = _account_query_table_column_text(hstmt, LABEL_FIELD_LABEL);
	_account_db_data_to_text(textbuf, &(label_record->label));

	textbuf = _account_query_table_column_text(hstmt, LABEL_FIELD_LOCALE);
	_account_db_data_to_text(textbuf, &(label_record->locale));

}

GSList* _account_type_get_label_list_by_app_id(const char* app_id, int *error_code )
{
	*error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0, binding_count = 1;
	GSList* label_list = NULL;

	ACCOUNT_RETURN_VAL((app_id != NULL), {*error_code = ACCOUNT_ERROR_INVALID_PARAMETER;}, NULL, ("APP ID IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {*error_code = ACCOUNT_ERROR_DB_NOT_OPENED;}, NULL, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE AppId = ?", LABEL_TABLE);
	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		*error_code = ACCOUNT_ERROR_PERMISSION_DENIED;
		return NULL;
	}

	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR_P(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	label_s* label_record = NULL;

	while (rc == SQLITE_ROW) {
		label_record = (label_s*) malloc(sizeof(label_s));

		if (label_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(label_record, 0x00, sizeof(label_s));

		_account_type_convert_column_to_label(hstmt, label_record);

		_INFO("Adding account label_list");
		label_list = g_slist_append (label_list, label_record);

		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {*error_code = rc;}, NULL, ("finalize error"));
	hstmt = NULL;

	*error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {*error_code = rc;}, NULL, ("finalize error"));
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);
	_INFO("Returning account label_list");
	return label_list;
}

int account_type_query_label_by_app_id(account_label_cb callback, const char* app_id, void *user_data )
{
	int 			error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0, binding_count = 1;

	ACCOUNT_RETURN_VAL((app_id != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("APP ID IS NULL"));
	ACCOUNT_RETURN_VAL((callback != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("NO CALLBACK FUNCTION"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE AppId = ?", LABEL_TABLE);
	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	label_s* label_record = NULL;

	while (rc == SQLITE_ROW) {
		bool cb_ret = FALSE;
		label_record = (label_s*) malloc(sizeof(label_s));

		if (label_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(label_record, 0x00, sizeof(label_s));

		_account_type_convert_column_to_label(hstmt, label_record);

		cb_ret = callback(label_record->app_id, label_record->label , label_record->locale, user_data);

		_account_type_free_label_items(label_record);
		_ACCOUNT_FREE(label_record);

		ACCOUNT_CATCH_ERROR(cb_ret == TRUE, {}, ACCOUNT_ERROR_NONE, ("Callback func returs FALSE, its iteration is stopped!!!!\n"));

		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);
	return error_code;
}

int _account_type_label_get_app_id(label_h label, char **app_id)
{
	if (!label) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if (!app_id) {
		return ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	label_s *data = (label_s*)label;

	(*app_id) = NULL;

	*app_id = _account_get_text(data->app_id);

	return ACCOUNT_ERROR_NONE;
}

bool _account_get_label_text_cb(char* app_id, char* label, char* locale, void *user_data)
{
	account_type_s *data = (account_type_s*)user_data;

	label_s *label_data = (label_s*)malloc(sizeof(label_s));

	if (label_data == NULL) {
		ACCOUNT_FATAL("_account_get_label_text_cb : MALLOC FAIL\n");
		return FALSE;
	}
	ACCOUNT_MEMSET(label_data, 0, sizeof(label_s));

	label_data->app_id = _account_get_text(app_id);
	label_data->label = _account_get_text(label);
	label_data->locale = _account_get_text(locale);

	data->label_list = g_slist_append(data->label_list, (gpointer)label_data);

	return TRUE;
}

bool _account_get_provider_feature_cb(char* app_id, char* key, void* user_data)
{
	account_type_s *data = (account_type_s*)user_data;

	provider_feature_s *feature_data = (provider_feature_s*)malloc(sizeof(provider_feature_s));

	if (feature_data == NULL) {
		ACCOUNT_FATAL("_account_get_provider_feature_cb : MALLOC FAIL\n");
		return FALSE;
	}
	ACCOUNT_MEMSET(feature_data, 0, sizeof(provider_feature_s));

	feature_data->app_id = _account_get_text(app_id);
	feature_data->key = _account_get_text(key);

	data->provider_feature_list = g_slist_append(data->provider_feature_list, (gpointer)feature_data);

	return TRUE;
}

int _account_type_query_by_app_id(const char* app_id, account_type_s** account_type_record)
{
	_INFO("_account_type_query_by_app_id start");

	int 			error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0, binding_count = 1;

	ACCOUNT_RETURN_VAL((app_id != 0), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("APP ID IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE AppId = ?", ACCOUNT_TYPE_TABLE);
	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	*account_type_record = create_empty_account_type_instance();

	while (rc == SQLITE_ROW) {
		_account_type_convert_column_to_account_type(hstmt, *account_type_record);
		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	account_type_query_label_by_app_id(_account_get_label_text_cb, app_id, (void*)(*account_type_record));
	account_type_query_provider_feature_by_app_id(_account_get_provider_feature_cb, app_id,(void*)(*account_type_record));

	hstmt = NULL;
	error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);
	_INFO("_account_type_query_by_app_id end [%d]", error_code);
	return error_code;
}

int _account_type_query_app_id_exist(const char* app_id)
{
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;

	ACCOUNT_RETURN_VAL((app_id != 0), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("APP ID IS NULL"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE AppId = '%s'", ACCOUNT_TYPE_TABLE, app_id);
	rc = _account_get_record_count(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (rc <= 0) {
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	return ACCOUNT_ERROR_NONE;
}

GSList* _account_type_query_by_provider_feature(const char* key, int *error_code)
{
	*error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;
	GSList			*account_type_list = NULL;

	if(key == NULL)
	{
		ACCOUNT_ERROR("capability_type IS NULL.");
		*error_code = ACCOUNT_ERROR_INVALID_PARAMETER;
		goto CATCH;
	}

	if(g_hAccountDB == NULL)
	{
		ACCOUNT_ERROR("The database isn't connected.");
		*error_code = ACCOUNT_ERROR_DB_NOT_OPENED;
		goto CATCH;
	}

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE AppId IN (SELECT app_id from %s WHERE key=?)", ACCOUNT_TYPE_TABLE, PROVIDER_FEATURE_TABLE);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM )
	{
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		*error_code = ACCOUNT_ERROR_PERMISSION_DENIED;
		goto CATCH;
	}

	int binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, key);

	rc = _account_query_step(hstmt);

	account_type_s *account_type_record = NULL;

	if(rc != SQLITE_ROW)
	{
		ACCOUNT_ERROR("The record isn't found.");
		*error_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		goto CATCH;
	}

	while(rc == SQLITE_ROW) {
		account_type_record = (account_type_s*) malloc(sizeof(account_type_s));

		if (account_type_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(account_type_record, 0x00, sizeof(account_type_s));
		_account_type_convert_column_to_account_type(hstmt, account_type_record);
		account_type_list = g_slist_append(account_type_list, account_type_record);
		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	if (rc != ACCOUNT_ERROR_NONE )
	{
		_account_type_gslist_free(account_type_list);
		ACCOUNT_ERROR("finalize error(%s)", rc);
		*error_code = rc;
		goto CATCH;
	}
	hstmt = NULL;

	GSList* iter;

	for (iter = account_type_list; iter != NULL; iter = g_slist_next(iter)) {
		account_type_s *account_type = NULL;
		account_type = (account_type_s*)iter->data;
		account_type_query_label_by_app_id(_account_get_label_text_cb,account_type->app_id,(void*)account_type);
		account_type_query_provider_feature_by_app_id(_account_get_provider_feature_cb, account_type->app_id,(void*)account_type);
	}

	*error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		if (rc != ACCOUNT_ERROR_NONE)
		{
			*error_code = rc;
			return NULL;
		}
		hstmt = NULL;
	}

	return account_type_list;
}


GSList* _account_type_query_all(void)
{
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;
	GSList			*account_type_list = NULL;

	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, NULL, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s ", ACCOUNT_TYPE_TABLE);
	hstmt = _account_prepare_query(query);

	rc = _account_query_step(hstmt);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return NULL;
	}

	account_type_s *account_type_record = NULL;

	if (rc != SQLITE_ROW)
	{
		_INFO("[ACCOUNT_ERROR_RECORD_NOT_FOUND]The record isn't found.");
		goto CATCH;
	}

	while(rc == SQLITE_ROW) {
		account_type_record = (account_type_s*) malloc(sizeof(account_type_s));

		if (account_type_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(account_type_record, 0x00, sizeof(account_type_s));
		_account_type_convert_column_to_account_type(hstmt, account_type_record);
		account_type_list = g_slist_append(account_type_list, account_type_record);
		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, NULL, ("finalize error"));
	hstmt = NULL;

	GSList* iter;

	for (iter = account_type_list; iter != NULL; iter = g_slist_next(iter)) {
		account_type_s *account_type = NULL;
		account_type = (account_type_s*)iter->data;
		account_type_query_label_by_app_id(_account_get_label_text_cb,account_type->app_id,(void*)account_type);
		account_type_query_provider_feature_by_app_id(_account_get_provider_feature_cb, account_type->app_id,(void*)account_type);
	}

CATCH:
	if (hstmt != NULL)
	{
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {_account_type_gslist_free(account_type_list);}, NULL, ("finalize error"));
		hstmt = NULL;
	}

	return account_type_list;
}

// output parameter label must be free
int _account_type_query_label_by_locale(const char* app_id, const char* locale, char **label)
{
	int 			error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0, binding_count = 1;
	char*			converted_locale = NULL;

	ACCOUNT_RETURN_VAL((app_id != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("NO APP ID"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));
	ACCOUNT_RETURN_VAL((label != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("label char is null"));
	ACCOUNT_RETURN_VAL((locale != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("locale char is null"));
	//Making label newly created

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	converted_locale = _account_get_text(locale);
	gchar** tokens = g_strsplit(converted_locale, "-", 2);

	if(tokens != NULL) {
		if((char*)(tokens[1]) != NULL) {
			char* upper_token = g_ascii_strup(tokens[1], strlen(tokens[1]));
			if(upper_token != NULL) {
				_ACCOUNT_FREE(converted_locale);
				converted_locale = g_strdup_printf("%s_%s", tokens[0], upper_token);
			}
			_ACCOUNT_FREE(upper_token);
		}
	}
	g_strfreev(tokens);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE AppId = ? AND Locale = '%s' ", LABEL_TABLE, converted_locale);
	_ACCOUNT_FREE(converted_locale);

	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	label_s* label_record = NULL;

	while (rc == SQLITE_ROW) {
		label_record = (label_s*) malloc(sizeof(label_s));

		if (label_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(label_record, 0x00, sizeof(label_s));

		_account_type_convert_column_to_label(hstmt,label_record);

		_ACCOUNT_FREE(*label);
		//Making label newly created
		*label = _account_get_text(label_record->label);

		_account_type_free_label_items(label_record);
		_ACCOUNT_FREE(label_record);

		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	error_code = ACCOUNT_ERROR_NONE;

	CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);
	_INFO("_account_type_query_label_by_locale() end : error_code = %d", error_code);
	return error_code;
}

static int _account_insert_custom(account_s *account, int account_id)
{
	_INFO("_account_insert_custom start");

	int 			rc, count = 1;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	account_stmt 	hstmt = NULL;

	ACCOUNT_RETURN_VAL((account != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));

	if (g_slist_length( account->custom_list)==0) {
		ACCOUNT_DEBUG( "_account_insert_custom, no custom data\n");
		return ACCOUNT_ERROR_NONE;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) from %s where _id=%d", ACCOUNT_TABLE, account_id);

	rc = _account_get_record_count(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%d, %s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (rc <= 0) {
		ACCOUNT_SLOGE( "_account_insert_custom : related account item is not existed rc=%d , %s", rc, _account_db_err_msg());
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	/* insert query*/

	GSList *iter;

	for (iter = account->custom_list; iter != NULL; iter = g_slist_next(iter)) {
		int ret;
		count = 1;
		ACCOUNT_MEMSET(query, 0x00, sizeof(query));
		ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s (AccountId, AppId, Key, Value) VALUES "
				"(?, ?, ?, ?) ", ACCOUNT_CUSTOM_TABLE);

		hstmt = _account_prepare_query(query);

		if( _account_db_err_code() == SQLITE_PERM ){
			ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
			return ACCOUNT_ERROR_PERMISSION_DENIED;
		}

		ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg()));

		account_custom_s* custom_data = NULL;
		custom_data = (account_custom_s*)iter->data;

		ret = _account_query_bind_int(hstmt, count++, account_id);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Int binding fail"));
		ret = _account_query_bind_text(hstmt, count++, account->package_name);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)custom_data->key);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)custom_data->value);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));

		rc = _account_query_step(hstmt);

		if (rc != SQLITE_DONE) {
			ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
			break;
		}

		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;

	}

	_INFO("_account_insert_custom end");
	return ACCOUNT_ERROR_NONE;
}

static int _account_update_custom(account_s *account, int account_id)
{
	int 			rc, count = 1;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	account_stmt 	hstmt = NULL;

	ACCOUNT_RETURN_VAL((account != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));

	if (g_slist_length( account->custom_list)==0) {
		ACCOUNT_DEBUG( "_account_update_custom, no custom data\n");
		return ACCOUNT_ERROR_NONE;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) from %s where _id=%d", ACCOUNT_TABLE, account_id);

	rc = _account_get_record_count(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	} else if( _account_db_err_code() == SQLITE_BUSY ){
		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg());
		pthread_mutex_unlock(&account_mutex);
		return ACCOUNT_ERROR_DATABASE_BUSY;
	}

	if (rc <= 0) {
		ACCOUNT_SLOGE( "_account_update_custom : related account item is not existed rc=%d , %s", rc, _account_db_err_msg());
		return ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE AccountId=? ", ACCOUNT_CUSTOM_TABLE);
	hstmt = _account_prepare_query(query);
	count = 1;
	_account_query_bind_int(hstmt, count++, (int)account_id);
	rc = _account_query_step(hstmt);

	if (rc == SQLITE_BUSY) {
		ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
		return ACCOUNT_ERROR_DATABASE_BUSY;
	} else if (rc != SQLITE_DONE) {
		ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
		return ACCOUNT_ERROR_DB_FAILED;
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	GSList *iter;

	for (iter = account->custom_list; iter != NULL; iter = g_slist_next(iter)) {
		int ret;
		count = 1;
		ACCOUNT_MEMSET(query, 0x00, sizeof(query));
		ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s(AccountId, AppId, Key, Value) VALUES "
				"(?, ?, ?, ?) ", ACCOUNT_CUSTOM_TABLE);

		hstmt = _account_prepare_query(query);

		if( _account_db_err_code() == SQLITE_PERM ){
			ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
			return ACCOUNT_ERROR_PERMISSION_DENIED;
		}

		ACCOUNT_RETURN_VAL((hstmt != NULL), {}, ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg()));

		account_custom_s* custom_data = NULL;
		custom_data = (account_custom_s*)iter->data;

		ret = _account_query_bind_int(hstmt, count++, (int)account_id);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Int binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)account->package_name);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)custom_data->key);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)custom_data->value);
		ACCOUNT_RETURN_VAL((ret == ACCOUNT_ERROR_NONE), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));

		rc = _account_query_step(hstmt);

		if (rc != SQLITE_DONE) {
			ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg());
			break;
		}

		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;

	}

	return ACCOUNT_ERROR_NONE;
}

static int _account_query_custom_by_account_id(account_custom_cb callback, int account_id, void *user_data )
{
	int 			error_code = ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;

	ACCOUNT_RETURN_VAL((account_id > 0), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT INDEX IS LESS THAN 0"));
	ACCOUNT_RETURN_VAL((callback != NULL), {}, ACCOUNT_ERROR_INVALID_PARAMETER, ("NO CALLBACK FUNCTION"));
	ACCOUNT_RETURN_VAL((g_hAccountDB != NULL), {}, ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE AccountId = %d", ACCOUNT_CUSTOM_TABLE, account_id);
	hstmt = _account_prepare_query(query);

	if( _account_db_err_code() == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg());
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	rc = _account_query_step(hstmt);

	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	account_custom_s* custom_record = NULL;

	while (rc == SQLITE_ROW) {
		bool cb_ret = FALSE;
		custom_record = (account_custom_s*) malloc(sizeof(account_custom_s));

		if (custom_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(custom_record, 0x00, sizeof(account_custom_s));

		_account_convert_column_to_custom(hstmt, custom_record);

		cb_ret = callback(custom_record->key, custom_record->value, user_data);

		_account_custom_item_free(custom_record);
		_ACCOUNT_FREE(custom_record);

		ACCOUNT_CATCH_ERROR(cb_ret == TRUE, {}, ACCOUNT_ERROR_NONE, ("Callback func returs FALSE, its iteration is stopped!!!!\n"));

		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	error_code = ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	pthread_mutex_unlock(&account_mutex);
	return error_code;
}
