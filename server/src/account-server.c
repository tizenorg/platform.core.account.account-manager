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

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <glib.h>
#if !GLIB_CHECK_VERSION (2, 31, 0)
#include <glib/gmacros.h>
#endif
#include <cynara-client.h>
#include <cynara-session.h>
#include <cynara-creds-gdbus.h>

#include <dbg.h>
#include <account_ipc_marshal.h>
#include <account_free.h>
#include <account-mgr-stub.h>
#include <account-private.h>
#include <account-error.h>

#include "account-server-db.h"
#define _PRIVILEGE_ACCOUNT_READ "http://tizen.org/privilege/account.read"
#define _PRIVILEGE_ACCOUNT_WRITE "http://tizen.org/privilege/account.write"

#define ACCOUNT_MGR_DBUS_PATH       "/org/tizen/account/manager"
static guint owner_id = 0;
GDBusObjectManagerServer *account_mgr_server_mgr = NULL;
static AccountManager* account_mgr_server_obj = NULL;

static cynara *p_cynara;

//static gboolean has_owner = FALSE;

// pid-mode, TODO: make it sessionId-mode, were session id is mix of pid and some rand no, so that
// one client can have multiple connections having different modes
//static GHashTable* mode_table = NULL;

GDBusErrorEntry _account_svc_errors[] =
{
	{ACCOUNT_ERROR_NONE, _ACCOUNT_SVC_ERROR_PREFIX".NoError"},
	{ACCOUNT_ERROR_OUT_OF_MEMORY, _ACCOUNT_SVC_ERROR_PREFIX".OutOfMemory"},
	{ACCOUNT_ERROR_INVALID_PARAMETER, _ACCOUNT_SVC_ERROR_PREFIX".InvalidParameter"},
	{ACCOUNT_ERROR_DUPLICATED, _ACCOUNT_SVC_ERROR_PREFIX".Duplicated"},
	{ACCOUNT_ERROR_NO_DATA, _ACCOUNT_SVC_ERROR_PREFIX".NoData"},
	{ACCOUNT_ERROR_RECORD_NOT_FOUND, _ACCOUNT_SVC_ERROR_PREFIX".RecordNotFound"},
	{ACCOUNT_ERROR_DB_FAILED, _ACCOUNT_SVC_ERROR_PREFIX".DBFailed"},
	{ACCOUNT_ERROR_DB_NOT_OPENED, _ACCOUNT_SVC_ERROR_PREFIX".DBNotOpened"},
	{ACCOUNT_ERROR_QUERY_SYNTAX_ERROR, _ACCOUNT_SVC_ERROR_PREFIX".QuerySynTaxError"},
	{ACCOUNT_ERROR_ITERATOR_END, _ACCOUNT_SVC_ERROR_PREFIX".IteratorEnd"},
	{ACCOUNT_ERROR_NOTI_FAILED, _ACCOUNT_SVC_ERROR_PREFIX".NotiFalied"},
	{ACCOUNT_ERROR_PERMISSION_DENIED, _ACCOUNT_SVC_ERROR_PREFIX".PermissionDenied"},
	{ACCOUNT_ERROR_XML_PARSE_FAILED, _ACCOUNT_SVC_ERROR_PREFIX".XMLParseFailed"},
	{ACCOUNT_ERROR_XML_FILE_NOT_FOUND, _ACCOUNT_SVC_ERROR_PREFIX".FileNotFound"},
	{ACCOUNT_ERROR_EVENT_SUBSCRIPTION_FAIL, _ACCOUNT_SVC_ERROR_PREFIX".SubscriptionFailed"},
	{ACCOUNT_ERROR_NOT_REGISTERED_PROVIDER, _ACCOUNT_SVC_ERROR_PREFIX".NotRegisteredProvider"},
	{ACCOUNT_ERROR_NOT_ALLOW_MULTIPLE, _ACCOUNT_SVC_ERROR_PREFIX".NotAllowMultiple"},
	{ACCOUNT_ERROR_DATABASE_BUSY, _ACCOUNT_SVC_ERROR_PREFIX".database_busy"},
};

static guint
_get_client_pid(GDBusMethodInvocation* invoc)
{
	const char *name = NULL;
	name = g_dbus_method_invocation_get_sender(invoc);
	if (name == NULL)
	{
		_ERR("g_dbus_method_invocation_get_sender failed");
		return -1;
	}
	_INFO("sender=[%s]", name);


	guint pid = -1;
	GError *error = NULL;
	GVariant *_ret;

	_INFO("calling GetConnectionUnixProcessID");

	GDBusConnection* conn = g_dbus_method_invocation_get_connection(invoc);
	_ret = g_dbus_connection_call_sync(conn,
			"org.freedesktop.DBus",
			"/org/freedesktop/DBus",
			"org.freedesktop.DBus",
			"GetConnectionUnixProcessID",
			g_variant_new("(s)", name),
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&error);

	if (_ret != NULL)
	{
		g_variant_get(_ret, "(u)", &pid);
		g_variant_unref(_ret);
	}

	_INFO("process Id = [%u]", pid);
	return pid;
}

static GQuark
_account_error_quark (void)
{
	static volatile gsize quark_volatile = 0;

	g_dbus_error_register_error_domain (_ACCOUNT_SVC_ERROR_DOMAIN,
										&quark_volatile,
										_account_svc_errors,
										G_N_ELEMENTS (_account_svc_errors));

	return (GQuark) quark_volatile;
}

static int __check_privilege_by_cynara(const char *client, const char *session, const char *user, const char *privilege)
{
	int ret;
	char err_buf[128] = {0,};

	ret = cynara_check(p_cynara, client, session, user, privilege);
	switch (ret) {
		case CYNARA_API_ACCESS_ALLOWED:
			_DBG("cynara_check success");
			return ACCOUNT_ERROR_NONE;
		case CYNARA_API_ACCESS_DENIED:
			_ERR("cynara_check permission deined, privilege=%s, error = CYNARA_API_ACCESS_DENIED", privilege);
			return ACCOUNT_ERROR_PERMISSION_DENIED;
		default:
			cynara_strerror(ret, err_buf, sizeof(err_buf));
			_ERR("cynara_check error : %s, privilege=%s, ret = %d", err_buf, privilege, ret);
			return ACCOUNT_ERROR_PERMISSION_DENIED;
	}
}

int __get_information_for_cynara_check(GDBusMethodInvocation *invocation, char **client, char **user, char **session)
{
	GDBusConnection *gdbus_conn = NULL;
	char* sender = NULL;
	int ret = -1;

	//get GDBusConnection
	gdbus_conn = g_dbus_method_invocation_get_connection(invocation);
	if(gdbus_conn == NULL)
	{
		_ERR("g_dbus_method_invocation_get_connection failed");
		return -1;
	}

	//get sender(unique_name)
	sender = (char*) g_dbus_method_invocation_get_sender(invocation);
	if (sender == NULL)
	{
		_ERR("g_dbus_method_invocation_get_sender failed");
		return -1;
	}

	ret = cynara_creds_gdbus_get_user(gdbus_conn, sender, USER_METHOD_DEFAULT, user);
	if (ret != CYNARA_API_SUCCESS)
	{
		_ERR("cynara_creds_gdbus_get_user failed, ret = %d", ret);
		return -1;
	}

	ret = cynara_creds_gdbus_get_client(gdbus_conn, sender, CLIENT_METHOD_DEFAULT, client);
	if (ret != CYNARA_API_SUCCESS)
	{
		_ERR("cynara_creds_gdbus_get_client failed, ret = %d", ret);
		return -1;
	}

	guint pid = _get_client_pid(invocation);
	_INFO("client Id = [%u]", pid);

	*session = cynara_session_from_pid(pid);
	if (*session == NULL)
	{
		_ERR("cynara_session_from_pid failed");
		return -1;
	}
	return ACCOUNT_ERROR_NONE;
}

int _check_privilege(GDBusMethodInvocation *invocation, const char* privilege)
{
	int ret = -1;
	char *client = NULL;
	char *session = NULL;
	char *user = NULL;

	ret = __get_information_for_cynara_check(invocation, &client, &user, &session);
	if ( ret != ACCOUNT_ERROR_NONE )
	{
		_ERR("__get_information_for_cynara_check failed");
		g_free(client);
		g_free(user);
		_ACCOUNT_FREE(session);
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	ret = __check_privilege_by_cynara(client, session, user, privilege);
	if ( ret != ACCOUNT_ERROR_NONE )
	{
		_ERR("__check_privilege_by_cynara failed, ret = %d", ret);
		g_free(client);
		g_free(user);
		_ACCOUNT_FREE(session);
		return ACCOUNT_ERROR_PERMISSION_DENIED;
	}
	g_free(client);
	g_free(user);
	_ACCOUNT_FREE(session);
	return ACCOUNT_ERROR_NONE;
}

int _check_priviliege_account_read(GDBusMethodInvocation *invocation)
{
	return _check_privilege(invocation, _PRIVILEGE_ACCOUNT_READ);
}

int _check_priviliege_account_write(GDBusMethodInvocation *invocation)
{
	return _check_privilege(invocation, _PRIVILEGE_ACCOUNT_WRITE);
}

gboolean account_manager_account_add(AccountManager *obj, GDBusMethodInvocation *invocation, GVariant* account_data, gint uid, gpointer user_data)
{
	_INFO("account_manager_account_add start");
	int db_id = -1;
	account_s* account = NULL;

	guint pid = _get_client_pid(invocation);
	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _check_priviliege_account_write(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_write failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(1, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	account = umarshal_account(account_data);
	if (account == NULL)
	{
		_ERR("account unmarshalling failed");
		return_code = ACCOUNT_ERROR_DB_FAILED;

		goto RETURN;
	}

	return_code = _account_insert_to_db(account, pid, (int)uid, &db_id);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_insert_to_db() error");

		goto RETURN;
	}

RETURN:

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_add(obj, invocation, db_id);
	}
	_INFO("account_manager_account_add end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	_account_free_account_with_items(account);

	return true;
}

gboolean account_manager_account_query_all(AccountManager *obj, GDBusMethodInvocation *invocation, gint uid)
{
	_INFO("account_manager_account_query_all start");

	GVariant* account_list_variant = NULL;

	guint pid = _get_client_pid(invocation);
	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	//Mode checking not required, since default mode is read.

	GSList* account_list = NULL;
	account_list = _account_db_query_all(pid, (uid_t)uid);

	if (account_list == NULL)
	{
		return_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		_ERR("No account found.");
		goto RETURN;
	}

	_INFO("account_list length= [%d]", g_slist_length(account_list));

	return_code = 0;
	_INFO("before calling marshal_account_list");
	account_list_variant = marshal_account_list(account_list);
	_INFO("after calling marshal_account_list");

RETURN:

	if (account_list_variant == NULL)
	{
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_query_all(obj, invocation, account_list_variant);
	}
	_INFO("account_manager_account_query_all end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_account_type_query_all(AccountManager *obj, GDBusMethodInvocation *invocation, gint uid)
{
	_INFO("account_manager_account_query_all start");

	GVariant* account_type_list_variant = NULL;
	guint pid = _get_client_pid(invocation);
	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	//Mode checking not required, since default mode is read.

	GSList* account_type_list = NULL;
	account_type_list = _account_type_query_all();

	if (account_type_list == NULL)
	{
		return_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		_ERR("No account type found.");
		goto RETURN;
	}

	_INFO("account_type_list length= [%d]", g_slist_length(account_type_list));

	return_code = 0;
	_INFO("before calling marshal_account_type_list");
	account_type_list_variant = marshal_account_type_list(account_type_list);
	_INFO("after calling marshal_account_type_list");

RETURN:

	if (account_type_list_variant == NULL)
	{
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_type_query_all(obj, invocation, account_type_list_variant);
	}
	_INFO("account_manager_account_query_all end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_account_type_add(AccountManager *obj, GDBusMethodInvocation *invocation, GVariant *account_type_data, gint uid, gpointer user_data)
{
	int db_id = -1;
	account_type_s* account_type = NULL;

	_INFO("account_manager_account_type_add start");

	guint pid = _get_client_pid(invocation);
	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}
	return_code = _check_priviliege_account_write(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_write failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(1, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	account_type = umarshal_account_type(account_type_data);
	if (account_type == NULL)
	{
		_ERR("account_type unmarshalling failed");
		return_code = ACCOUNT_ERROR_DB_FAILED;
		goto RETURN;
	}

	_INFO("before _account_type_insert_to_db");
	return_code = _account_type_insert_to_db(account_type, &db_id);
	_INFO("after _account_type_insert_to_db");
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_type_insert_to_db error");
		goto RETURN;
	}

RETURN:

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_type_add(obj, invocation, db_id);
	}
	_INFO("account_manager_account_type_add end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	_account_type_free_account_type_with_items(account_type);
	return true;
}

gboolean account_manager_account_delete_from_db_by_id(AccountManager *object,
											 GDBusMethodInvocation *invocation,
											 gint account_db_id,
											 gint uid)
{
	_INFO("account_manager_account_delete_from_db_by_id start");

	guint pid = _get_client_pid(invocation);
	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}
	return_code = _check_priviliege_account_write(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_write failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(1, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	_INFO("before _account_delete");
	return_code = _account_delete(pid, uid, account_db_id);
	_INFO("after _account_delete=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_delete error");
		goto RETURN;
	}

RETURN:

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_delete_from_db_by_id(object, invocation);
	}
	_INFO("account_manager_account_delete_from_db_by_id end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_account_delete_from_db_by_user_name(AccountManager *object,
															 GDBusMethodInvocation *invocation,
															 const gchar *user_name,
															 const gchar *package_name,
															 gint uid)
{
	_INFO("account_manager_account_delete_from_db_by_user_name start");

	guint pid = _get_client_pid(invocation);
	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}
	return_code = _check_priviliege_account_write(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_write failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(1, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	_INFO("before _account_delete_from_db_by_user_name");
	return_code = _account_delete_from_db_by_user_name(pid, uid, user_name, package_name);
	_INFO("after _account_delete_from_db_by_user_name=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_delete_from_db_by_user_name error");
		goto RETURN;
	}

RETURN:

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_delete_from_db_by_id(object, invocation);
	}
	_INFO("account_manager_account_delete_from_db_by_user_name end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_account_delete_from_db_by_package_name(AccountManager *object,
															 GDBusMethodInvocation *invocation,
															 const gchar *package_name,
															 gboolean permission,
															 gint uid)
{
	_INFO("account_manager_account_delete_from_db_by_package_name start");
	int return_code = ACCOUNT_ERROR_NONE;

	guint pid = _get_client_pid(invocation);
	_INFO("client Id = [%u]", pid);

	if( permission ) {
		return_code = _check_priviliege_account_read(invocation);
		if (return_code != ACCOUNT_ERROR_NONE)
		{
			_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
			goto RETURN;
		}
		return_code = _check_priviliege_account_write(invocation);
		if (return_code != ACCOUNT_ERROR_NONE)
		{
			_ERR("_check_priviliege_account_write failed, ret = %d", return_code);
			goto RETURN;
		}
	}

	return_code = _account_db_open(1, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	_INFO("before account_delete_from_db_by_package_name");
	return_code = _account_delete_from_db_by_package_name(pid, uid, package_name, permission);
	_INFO("after account_delete_from_db_by_package_name=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_delete_from_db_by_package_name error");
		goto RETURN;
	}

RETURN:

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_delete_from_db_by_package_name(object, invocation);
	}
	_INFO("account_manager_account_delete_from_db_by_package_name end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_account_update_to_db_by_id(AccountManager *object,
															GDBusMethodInvocation *invocation,
															GVariant *account_data,
															gint account_id,
															gint uid)
{
	_INFO("account_manager_account_update_to_db_by_id start");
	account_s* account = NULL;

	guint pid = _get_client_pid(invocation);
	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}
	return_code = _check_priviliege_account_write(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_write failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(1, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	account = umarshal_account(account_data);
	if (account == NULL)
	{
		_ERR("Unmarshal failed");
		return_code = ACCOUNT_ERROR_DB_FAILED;
		goto RETURN;
	}

	_INFO("before account_update_to_db_by_id");
	return_code = _account_update_to_db_by_id(pid, uid, account, account_id);
	_INFO("after account_update_to_db_by_id=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_type_update_to_db_by_id error");
		goto RETURN;
	}

RETURN:

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_update_to_db_by_id(object, invocation);
	}
	_INFO("account_manager_account_update_to_db_by_id end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	_account_free_account_with_items(account);

	return true;
}

gboolean account_manager_handle_account_update_to_db_by_user_name(AccountManager *object,
															GDBusMethodInvocation *invocation,
															GVariant *account_data,
															const gchar *user_name,
															const gchar *package_name,
															gint uid)
{
	_INFO("account_manager_handle_account_update_to_db_by_user_name start");
	account_s* account = NULL;

	guint pid = _get_client_pid(invocation);
	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}
	return_code = _check_priviliege_account_write(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_write failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(1, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	account = umarshal_account(account_data);
	if (account == NULL)
	{
		_ERR("Unmarshal failed");
		return_code = ACCOUNT_ERROR_DB_FAILED;
		goto RETURN;
	}

	_INFO("before account_update_to_db_by_id");
	return_code = _account_update_to_db_by_user_name(pid, uid, account, user_name, package_name);
	_INFO("after account_update_to_db_by_id=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_update_to_db_by_id error");
		goto RETURN;
	}

RETURN:

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_update_to_db_by_id(object, invocation);
	}
	_INFO("account_manager_handle_account_update_to_db_by_user_name end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	_account_free_account_with_items(account);

	return true;
}

gboolean
account_manager_handle_account_type_query_label_by_locale(AccountManager *object,
															GDBusMethodInvocation *invocation,
															const gchar *app_id,
															const gchar *locale,
															gint uid)
{
	_INFO("account_manager_handle_account_type_query_label_by_locale start");
	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	_INFO("before _account_type_query_label_by_locale");
	char *label_name = NULL;
	return_code = _account_type_query_label_by_locale(app_id, locale, &label_name);
	_INFO("after _account_type_query_label_by_locale=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_type_query_label_by_locale error");
		goto RETURN;
	}

RETURN:
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_type_query_label_by_locale(object, invocation, label_name);
	}
	_INFO("account_manager_handle_account_type_query_label_by_locale end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean
account_manager_handle_account_type_query_by_provider_feature(AccountManager *obj,
															GDBusMethodInvocation *invocation,
															const gchar *key,
															gint uid)
{
	_INFO("account_manager_handle_account_type_query_by_provider_feature start");
	GVariant* account_type_list_variant = NULL;

	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	//Mode checking not required, since default mode is read.

	GSList* account_type_list = NULL;
	account_type_list = _account_type_query_by_provider_feature(key, &return_code);
	if (return_code != 0)
	{
		_ERR("_account_type_query_by_provider_feature=[%d]", return_code);
		goto RETURN;
	}

	if (account_type_list == NULL)
	{
		return_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		_ERR("No account type found.");
		goto RETURN;
	}

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_type_query_by_provider_feature error");
		goto RETURN;
	}

	_INFO("account_type_list length= [%d]", g_slist_length(account_type_list));

	_INFO("before calling marshal_account_type_list");
	account_type_list_variant = marshal_account_type_list(account_type_list);
	_INFO("after calling marshal_account_type_list");

RETURN:

	if (account_type_list_variant == NULL)
	{
		GError* error = g_error_new (_account_error_quark(), ACCOUNT_ERROR_RECORD_NOT_FOUND, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_type_query_by_provider_feature(obj, invocation, account_type_list_variant);
	}
	_INFO("account_manager_handle_account_type_query_by_provider_feature end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_account_get_total_count_from_db(AccountManager *object, GDBusMethodInvocation *invocation, gboolean include_hidden, gint uid)
{
	_INFO("account_manager_account_get_total_count_from_db start");
	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}


	_INFO("before account_get_total_count_from_db");
	int count = -1;
	return_code = _account_get_total_count_from_db(include_hidden, &count);
	_INFO("before account_get_total_count_from_db=[%d], return_code");

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_get_total_count_from_db error");
		goto RETURN;
	}

RETURN:
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_get_total_count_from_db(object, invocation, count);
	}
	_INFO("account_manager_account_get_total_count_from_db end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_handle_account_query_account_by_account_id(AccountManager *object, GDBusMethodInvocation *invocation,
		gint account_db_id, gint uid)
{
	_INFO("account_manager_handle_account_query_account_by_account_id start");
	GVariant* account_variant = NULL;
	account_s* account_data = NULL;

	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	account_data = create_empty_account_instance();
	if (account_data == NULL)
	{
		_ERR("out of memory");
		return_code = ACCOUNT_ERROR_DB_FAILED;
		goto RETURN;
	}
	_INFO("before _account_query_account_by_account_id");
	return_code = _account_query_account_by_account_id(pid, (uid_t)uid, account_db_id, account_data);
	_INFO("after _account_query_account_by_return_code=[%d]", return_code);
	_INFO("user_name = %s, user_data_txt[0] = %s, user_data_int[1] = %d", account_data->user_name, account_data->user_data_txt[0], account_data->user_data_int[1]);

	if (return_code == ACCOUNT_ERROR_NONE)
	{
		account_variant = marshal_account(account_data);
	}

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_type_query_label_by_locale error");
		goto RETURN;
	}

RETURN:
	if (account_variant == NULL || return_code != ACCOUNT_ERROR_NONE)
	{
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_query_account_by_account_id(object, invocation, account_variant);
	}
	_INFO("account_manager_handle_account_query_account_by_account_id end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	_account_free_account_with_items(account_data);

	return true;
}

gboolean
account_manager_handle_account_query_account_by_user_name(AccountManager *obj,
														  GDBusMethodInvocation *invocation,
														  const gchar *user_name,
														  gint uid)
{
	_INFO("account_manager_handle_account_query_account_by_user_name start");

	GVariant* account_list_variant = NULL;
	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	//Mode checking not required, since default mode is read.

	GList* account_list = NULL;

	account_list = _account_query_account_by_user_name(pid, (uid_t)uid, user_name, &return_code);

	if (account_list == NULL)
	{
		return_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		_ERR("No account found.");
		goto RETURN;
	}

	_INFO("account_list length= [%d]", g_list_length(account_list));

	_INFO("before calling marshal_account_list_double");
	account_list_variant = marshal_account_list_double(account_list);
	_INFO("after calling marshal_account_list_double");

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_query_account_by_user_name error");
		goto RETURN;
	}

RETURN:
	if (account_list_variant == NULL)
	{
		GError* error = g_error_new (_account_error_quark(), ACCOUNT_ERROR_RECORD_NOT_FOUND, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_query_account_by_user_name(obj, invocation, account_list_variant);
	}
	_INFO("account_manager_handle_account_query_account_by_user_name end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean
account_manager_handle_account_query_account_by_package_name(AccountManager *obj,
														  GDBusMethodInvocation *invocation,
														  const gchar *package_name,
														  gint uid)
{
	_INFO("account_manager_handle_account_query_account_by_package_name start");

	GVariant* account_list_variant = NULL;
	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	//Mode checking not required, since default mode is read.

	GList* account_list = NULL;

	account_list = _account_query_account_by_package_name(pid, (uid_t)uid, package_name, &return_code);

	if (account_list == NULL)
	{
		return_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		_ERR("No account found.");
		goto RETURN;
	}

	_INFO("account_list length= [%d]", g_list_length(account_list));

	account_list_variant = marshal_account_list_double(account_list);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_query_account_by_package_name error");
		goto RETURN;
	}

RETURN:

	if (account_list_variant == NULL)
	{
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		_INFO("sending error Domain[%d] Message[%s] Code[%d]", error->domain, error->message, error->code);
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_query_account_by_package_name(obj, invocation, account_list_variant);
	}
	_INFO("account_manager_handle_account_query_account_by_package_name start");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean
account_manager_handle_account_query_account_by_capability(AccountManager *obj,
														  GDBusMethodInvocation *invocation,
														  const gchar *capability_type,
														  gint capability_value,
														  gint uid)
{
	_INFO("account_manager_handle_account_query_account_by_capability start");

	GVariant* account_list_variant = NULL;

	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	//Mode checking not required, since default mode is read.

	GList* account_list = NULL;

	_INFO("before _account_query_account_by_capability");
	account_list = _account_query_account_by_capability(pid, (uid_t)uid, capability_type, capability_value, &return_code);
	_INFO("after _account_query_account_by_capability");

	if (account_list == NULL)
	{
		return_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		_ERR("No account found.");
		goto RETURN;
	}

	_INFO("account_list length= [%d]", g_list_length(account_list));

	account_list_variant = marshal_account_list_double(account_list);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_query_account_by_capability error");
		goto RETURN;
	}

RETURN:

	if (account_list_variant == NULL)
	{
		GError* error = g_error_new (_account_error_quark(), ACCOUNT_ERROR_RECORD_NOT_FOUND, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_query_account_by_capability(obj, invocation, account_list_variant);
	}
	_INFO("account_manager_handle_account_query_account_by_capability end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean
account_manager_handle_account_query_account_by_capability_type(AccountManager *obj,
														  GDBusMethodInvocation *invocation,
														  const gchar *capability_type,
														  gint uid)
{
	_INFO("account_manager_handle_account_query_account_by_capability_type start");

	GVariant* account_list_variant = NULL;

	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	//Mode checking not required, since default mode is read.

	GList* account_list = NULL;

	account_list = _account_query_account_by_capability_type(pid, (uid_t)uid, capability_type, &return_code);

	if (account_list == NULL)
	{
		return_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		_ERR("No account found.");
		goto RETURN;
	}

	_INFO("account_list length= [%d]", g_list_length(account_list));

	_INFO("before calling marshal_account_list_double");
	account_list_variant = marshal_account_list_double(account_list);
	_INFO("after calling marshal_account_list_double");

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_query_account_by_capability_type error");
		goto RETURN;
	}

RETURN:

	if (account_list_variant == NULL)
	{
		GError* error = g_error_new (_account_error_quark(), ACCOUNT_ERROR_RECORD_NOT_FOUND, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_query_account_by_capability(obj, invocation, account_list_variant);
	}
	_INFO("account_manager_handle_account_query_account_by_capability_type end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean
account_manager_handle_account_query_capability_by_account_id(AccountManager *obj,
														  GDBusMethodInvocation *invocation,
														  const int account_id,
														  gint uid)
{
	_INFO("account_manager_handle_account_query_capability_by_account_id start");

	GVariant* capability_list_variant = NULL;

	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	//Mode checking not required, since default mode is read.

	GSList* capability_list = NULL;

	capability_list = _account_get_capability_list_by_account_id(account_id, &return_code);

	if (capability_list == NULL)
	{
		return_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		_ERR("No capability found.");
		goto RETURN;
	}

	_INFO("capability_list length= [%d]", g_slist_length(capability_list));

	_INFO("before calling marshal_capability_list");
	capability_list_variant = marshal_capability_list(capability_list);
	_INFO("after calling marshal_capability_list");

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_get_capability_list_by_account_id error");
		goto RETURN;
	}

RETURN:

	if (capability_list_variant == NULL)
	{
		GError* error = g_error_new (_account_error_quark(), ACCOUNT_ERROR_RECORD_NOT_FOUND, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_query_capability_by_account_id(obj, invocation, capability_list_variant);
	}
	_INFO("account_manager_handle_account_query_capability_by_account_id end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_handle_account_update_sync_status_by_id(AccountManager *object,
															GDBusMethodInvocation *invocation,
															const int account_db_id,
															const int sync_status,
															gint uid)
{
	_INFO("account_manager_handle_account_update_sync_status_by_id start");
	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}
	return_code = _check_priviliege_account_write(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_write failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(1, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	_INFO("before _account_update_sync_status_by_id");
	return_code = _account_update_sync_status_by_id(uid, account_db_id, sync_status);
	_INFO("after _account_update_sync_status_by_id=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_update_sync_status_by_id error");
		goto RETURN;
	}

RETURN:

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		account_manager_complete_account_update_sync_status_by_id(object, invocation);
	}
	_INFO("account_manager_handle_account_update_sync_status_by_id end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_handle_account_type_query_provider_feature_by_app_id(AccountManager *obj,
															GDBusMethodInvocation *invocation,
															const gchar* app_id,
															gint uid)
{
	GSList* feature_record_list = NULL;
	GVariant* feature_record_list_variant = NULL;

	_INFO("account_manager_handle_account_type_query_provider_feature_by_app_id start");

	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	_INFO("before _account_type_query_provider_feature_by_app_id");
	feature_record_list = _account_type_query_provider_feature_by_app_id(app_id, &return_code);
	_INFO("after account_type_query_provider_feature_by_app_id=[%d]", return_code);

	if (feature_record_list == NULL)
	{
		_ERR("account feature_record_list is NULL");
		return_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		goto RETURN;
	}

	feature_record_list_variant = provider_feature_list_to_variant(feature_record_list);
	_INFO("%s", g_variant_print(feature_record_list_variant, true));

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_type_query_provider_feature_by_app_id error");
		goto RETURN;
	}

RETURN:
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		_INFO("Calling account_manager_complete_account_type_query_provider_feature_by_app_id");
		account_manager_complete_account_type_query_provider_feature_by_app_id(obj, invocation, feature_record_list_variant);
	}
	_INFO("account_manager_handle_account_type_query_provider_feature_by_app_id end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_handle_account_type_query_supported_feature(AccountManager *obj,
															GDBusMethodInvocation *invocation,
															const gchar* app_id,
															const gchar* capability,
															gint uid)
{
	int is_supported = 0;

	_INFO("account_manager_handle_account_type_query_supported_feature start");
	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	_INFO("before _account_type_query_supported_feature");
	is_supported = _account_type_query_supported_feature(app_id, capability, &return_code);
	_INFO("after _account_type_query_supported_feature=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_type_query_supported_feature error");
		goto RETURN;
	}

RETURN:
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		_INFO("Calling account_manager_complete_account_type_query_provider_feature_by_app_id");
		account_manager_complete_account_type_query_supported_feature(obj, invocation, is_supported);
	}
	_INFO("account_manager_handle_account_type_query_supported_feature end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_handle_account_type_update_to_db_by_app_id (AccountManager *obj,
															GDBusMethodInvocation *invocation,
															GVariant *account_type_variant,
															const gchar *app_id,
															gint uid)
{
	_INFO("account_manager_handle_account_type_update_to_db_by_app_id start");
	account_type_s* account_type = NULL;

	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}
	return_code = _check_priviliege_account_write(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_write failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(1, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	account_type = umarshal_account_type(account_type_variant);

	_INFO("before _account_type_update_to_db_by_app_id");
	return_code = _account_type_update_to_db_by_app_id(account_type, app_id);
	_INFO("after _account_type_update_to_db_by_app_id=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_type_update_to_db_by_app_id error");
		goto RETURN;
	}

RETURN:
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		_INFO("Calling account_manager_complete_account_type_update_to_db_by_app_id");
		account_manager_complete_account_type_update_to_db_by_app_id(obj, invocation);
	}
	_INFO("account_manager_handle_account_type_update_to_db_by_app_id end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	_account_type_free_account_type_with_items(account_type);

	return true;
}

gboolean account_manager_handle_account_type_delete_by_app_id (AccountManager *obj,
															GDBusMethodInvocation *invocation,
															const gchar *app_id,
															gint uid)
{
	_INFO("account_manager_handle_account_type_delete_by_app_id start");

	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}
	return_code = _check_priviliege_account_write(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_write failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(1, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	_INFO("before _account_type_delete_by_app_id");
	return_code = _account_type_delete_by_app_id (app_id);
	_INFO("after _account_type_delete_by_app_id=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_type_delete_by_app_id error");
		goto RETURN;
	}

RETURN:
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		_ERR("Calling account_manager_complete_account_type_update_to_db_by_app_id");
		account_manager_complete_account_type_delete_by_app_id (obj, invocation);
	}
	_INFO("account_manager_handle_account_type_delete_by_app_id end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_handle_account_type_query_label_by_app_id (AccountManager *obj,
															GDBusMethodInvocation *invocation,
															const gchar *app_id,
															gint uid)
{
	_INFO("account_manager_handle_account_type_query_label_by_app_id start");
	GSList* label_list = NULL;
	GVariant* label_list_variant = NULL;

	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	_INFO("before _account_type_get_label_list_by_app_id");
	label_list = _account_type_get_label_list_by_app_id (app_id, &return_code);
	_INFO("after _account_type_get_label_list_by_app_id=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_type_get_label_list_by_app_id = [%d]", return_code);
		goto RETURN;
	}

	label_list_variant = label_list_to_variant (label_list);

RETURN:
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		_ERR("Calling account_manager_complete_account_type_query_label_by_app_id");
		account_manager_complete_account_type_query_label_by_app_id (obj, invocation, label_list_variant);
	}
	_INFO("account_manager_handle_account_type_query_label_by_app_id end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_handle_account_type_query_by_app_id (AccountManager *obj,
															GDBusMethodInvocation *invocation,
															const gchar *app_id,
															gint uid)
{
	_INFO("account_manager_handle_account_type_query_by_app_id start");
	GVariant* account_type_variant = NULL;

	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	_INFO("before _account_type_query_by_app_id");
	account_type_s* account_type = NULL;
	return_code = _account_type_query_by_app_id (app_id, &account_type);
	_INFO("after _account_type_query_by_app_id=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_type_query_by_app_id = [%d]", return_code);
		goto RETURN;
	}
	if (account_type == NULL)
	{
		_ERR("account_type read is NULL");
		return_code = ACCOUNT_ERROR_RECORD_NOT_FOUND;
		goto RETURN;
	}

	account_type_variant = marshal_account_type( account_type);

RETURN:
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		_INFO("Calling account_manager_complete_account_type_query_by_app_id");
		account_manager_complete_account_type_query_by_app_id (obj, invocation, account_type_variant);
	}
	_INFO("account_manager_handle_account_type_query_by_app_id end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	_account_type_free_account_type_with_items(account_type);

	return true;
}

gboolean account_manager_handle_account_type_query_app_id_exist (AccountManager *obj,
															GDBusMethodInvocation *invocation,
															const gchar *app_id,
															gint uid)
{
	_INFO("account_manager_handle_account_type_query_app_id_exist start");
	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(0, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	_INFO("before _account_type_query_app_id_exist_from_all_db");
	return_code = _account_type_query_app_id_exist_from_all_db (app_id);
	_INFO("after _account_type_query_app_id_exist_from_all_db=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_type_query_app_id_exist_from_all_db = [%d]", return_code);
		goto RETURN;
	}

RETURN:
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		_INFO("Calling account_manager_complete_account_type_query_by_app_id_exist");
		account_manager_complete_account_type_query_app_id_exist (obj, invocation);
	}
	_INFO("account_manager_handle_account_type_query_app_id_exist end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return true;
}

gboolean account_manager_handle_account_update_to_db_by_id_ex (AccountManager *obj,
															GDBusMethodInvocation *invocation,
															GVariant *account_data,
															gint account_id,
															gint uid)
{
	_INFO("account_manager_handle_account_update_to_db_by_id_ex start");
	account_s* account = NULL;
	guint pid = _get_client_pid(invocation);

	_INFO("client Id = [%u]", pid);

	int return_code = _check_priviliege_account_read(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_read failed, ret = %d", return_code);
		goto RETURN;
	}
	return_code = _check_priviliege_account_write(invocation);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_check_priviliege_account_write failed, ret = %d", return_code);
		goto RETURN;
	}

	return_code = _account_db_open(1, pid, uid);
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	return_code = _account_global_db_open();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_global_db_open() error, ret = %d", return_code);

		goto RETURN;
	}

	account = umarshal_account(account_data);
	if (account == NULL)
	{
		_ERR("Unmarshal failed");
		return_code = ACCOUNT_ERROR_INVALID_PARAMETER;
		goto RETURN;
	}

	_INFO("before _account_update_to_db_by_id_ex");
	return_code = _account_update_to_db_by_id_ex (account, account_id);
	_INFO("after _account_update_to_db_by_id_ex()=[%d]", return_code);

	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("_account_update_to_db_by_id_ex error");
		goto RETURN;
	}

RETURN:
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		_ERR("Account SVC is returning error [%d]", return_code);
		GError* error = g_error_new (_account_error_quark(), return_code, "RecordNotFound");
		g_dbus_method_invocation_return_gerror (invocation, error);
	}
	else
	{
		_INFO("Calling account_manager_complete_account_update_to_db_by_id_ex");
		account_manager_complete_account_update_to_db_by_id_ex (obj, invocation);
	}
	_INFO("in account_manager_handle_account_update_to_db_by_id_ex_p end");

	return_code = _account_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	return_code = _account_global_db_close();
	if (return_code != ACCOUNT_ERROR_NONE)
	{
		ACCOUNT_DEBUG("_account_global_db_close() fail[%d]", return_code);
		return_code = ACCOUNT_ERROR_NONE;
	}

	_account_free_account_with_items(account);

	return true;
}

static void
on_bus_acquired (GDBusConnection *connection, const gchar *name, gpointer user_data)
{
		_INFO("on_bus_acquired [%s]", name);

		GDBusInterfaceSkeleton* interface = NULL;
		account_mgr_server_obj = account_manager_skeleton_new();
		if (account_mgr_server_obj == NULL)
		{
			_ERR("account_mgr_server_obj NULL!!");
			return;
		}

        interface = G_DBUS_INTERFACE_SKELETON(account_mgr_server_obj);
		if (!g_dbus_interface_skeleton_export(interface, connection, ACCOUNT_MGR_DBUS_PATH, NULL))
		{
			_ERR("export failed!!");
			return;
		}

		_INFO("connecting account signals start");

		g_signal_connect(account_mgr_server_obj, "handle_account_add",
						G_CALLBACK(account_manager_account_add), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_query_all",
						G_CALLBACK(account_manager_account_query_all), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_type_add",
						G_CALLBACK(account_manager_account_type_add), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_type_query_all",
						G_CALLBACK(account_manager_account_type_query_all), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_delete_from_db_by_id",
						G_CALLBACK(account_manager_account_delete_from_db_by_id), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_delete_from_db_by_user_name",
						G_CALLBACK(account_manager_account_delete_from_db_by_user_name), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_delete_from_db_by_package_name",
						G_CALLBACK(account_manager_account_delete_from_db_by_package_name), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_update_to_db_by_id",
						G_CALLBACK(account_manager_account_update_to_db_by_id), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_get_total_count_from_db",
						G_CALLBACK(account_manager_account_get_total_count_from_db), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_query_account_by_account_id",
						G_CALLBACK(account_manager_handle_account_query_account_by_account_id), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_update_to_db_by_user_name",
						G_CALLBACK(account_manager_handle_account_update_to_db_by_user_name), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_type_query_label_by_locale",
						G_CALLBACK(account_manager_handle_account_type_query_label_by_locale), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_type_query_by_provider_feature",
						G_CALLBACK(account_manager_handle_account_type_query_by_provider_feature), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_query_account_by_user_name",
						G_CALLBACK(account_manager_handle_account_query_account_by_user_name), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_query_account_by_package_name",
						G_CALLBACK(account_manager_handle_account_query_account_by_package_name), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_query_account_by_capability",
						G_CALLBACK(account_manager_handle_account_query_account_by_capability), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_query_account_by_capability_type",
						G_CALLBACK(account_manager_handle_account_query_account_by_capability_type), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_query_capability_by_account_id",
						G_CALLBACK(account_manager_handle_account_query_capability_by_account_id), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_update_sync_status_by_id",
						G_CALLBACK(account_manager_handle_account_update_sync_status_by_id), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_type_query_provider_feature_by_app_id",
						G_CALLBACK(account_manager_handle_account_type_query_provider_feature_by_app_id), NULL);


		g_signal_connect(account_mgr_server_obj, "handle_account_type_query_supported_feature",
						G_CALLBACK(account_manager_handle_account_type_query_supported_feature), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_type_update_to_db_by_app_id",
						G_CALLBACK(account_manager_handle_account_type_update_to_db_by_app_id), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_type_delete_by_app_id",
						G_CALLBACK(account_manager_handle_account_type_delete_by_app_id), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_type_query_label_by_app_id",
						G_CALLBACK(account_manager_handle_account_type_query_label_by_app_id), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_type_query_by_app_id",
						G_CALLBACK(account_manager_handle_account_type_query_by_app_id), NULL);


		g_signal_connect(account_mgr_server_obj, "handle_account_type_query_app_id_exist",
						G_CALLBACK(account_manager_handle_account_type_query_app_id_exist), NULL);

		g_signal_connect(account_mgr_server_obj, "handle_account_update_to_db_by_id_ex",
								G_CALLBACK(account_manager_handle_account_update_to_db_by_id_ex), NULL);

		_INFO("connecting account signals end");

		g_dbus_object_manager_server_set_connection(account_mgr_server_mgr, connection);
		if( connection == NULL ) {
			_INFO("g_dbus_object_manager_server_set_connection failed");
		}
		_INFO("on_bus_acquired end [%s]", name);
}

static void
on_name_acquired (GDBusConnection *connection,
						const gchar     *name,
						gpointer         user_data)
{
		_INFO("on_name_acquired");

}

static void
on_name_lost (GDBusConnection *connection,
						const gchar     *name,
						gpointer         user_data)
{
		_INFO("on_name_lost");
		exit (1);
}

static bool _initialize_dbus()
{
	_INFO("__initialize_dbus Enter");

	owner_id = g_bus_own_name (G_BUS_TYPE_SYSTEM,
                             "org.tizen.account.manager",
                             G_BUS_NAME_OWNER_FLAGS_NONE,
                             on_bus_acquired,
                             on_name_acquired,
                             on_name_lost,
                             NULL,
                             NULL);

	_INFO("owner_id=[%d]", owner_id);

    if(owner_id == 0)
    {
			_INFO("gdbus own failed!!");
			return false;
	}

	_INFO("g_bus_own_name SUCCESS");
	return true;
}

static void _initialize()
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init();
#endif
	int ret = -1;

	if (_initialize_dbus() == false)
	{	/* because dbus's initialize
					failed, we cannot continue any more. */
		_ERR("DBUS Initialization Failed");
		exit(1);
	}

	ret = cynara_initialize(&p_cynara, NULL);
	if(ret != CYNARA_API_SUCCESS) {
		_ERR("CYNARA Initialization fail");
		exit(1);
	}
}

int main()
{
	GMainLoop *mainloop = NULL;

	_INFO("Starting Accounts SVC");

	mainloop = g_main_loop_new(NULL, FALSE);

	_INFO("g_main_loop_new");

	_initialize();

	_INFO("_initialize");

	g_main_loop_run(mainloop);

	_INFO("g_main_loop_run");

	cynara_finish(p_cynara);

	_INFO("Ending Accounts SVC");
	return 0;
}
