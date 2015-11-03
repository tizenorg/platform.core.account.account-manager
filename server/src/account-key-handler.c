
/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 *
 * @file        account-key-handler.c
 * @brief       a c file for key manupulatation.
 */

#include <tizen.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <ckmc/ckmc-manager.h>
#include <ckmc/ckmc-error.h>
#include <account-private.h>
#include <dbg.h>
#include <account-error.h>
#include "account-key-handler.h"

#define ACCOUNT_MANAGER_MKEY_ALIAS "ACCOUNT_MANAGER_MKEY"
#define ACCOUNT_MANAGER_DEK_ALIAS_PFX "ACCOUNT_MANAGER_DEK_"
#define MKEY_LEN 32
#define DEK_LEN 32

#define RANDOM_FILE    "/dev/urandom"

int _get_random(int length, unsigned char** random)
{
	FILE *f;
	//read random file
	if((f = fopen(RANDOM_FILE, "r")) != NULL){
		if(fread(*random, 1, length, f) != length) {
			return CKMC_ERROR_UNKNOWN;
		}
	}
	return CKMC_ERROR_NONE;
}

int get_app_mkey(unsigned char** mkey, int* mkey_len)
{
	int ret = CKMC_ERROR_NONE;

	const char* password = "password";
	ckmc_raw_buffer_s *mkey_buffer=NULL;
	const char *alias = ACCOUNT_MANAGER_MKEY_ALIAS;

	_INFO("start get_app_mkey");

	_INFO("before ckmc_get_data");
	ret = ckmc_get_data(alias, password, &mkey_buffer);
	_INFO("after ckmc_get_data");
	if (CKMC_ERROR_NONE != ret) {
		_INFO("before mkey_buffer free");
		if (mkey_buffer)
			ckmc_buffer_free(mkey_buffer);
		_INFO("after mkey_buffer free");
		return ret;
	}

	_INFO("before mkey_buffer->size=[%d]", mkey_buffer->size);
	*mkey_len = mkey_buffer->size;
	*mkey = (unsigned char *) malloc((*mkey_len)+1);
	memset(*mkey, 0, (*mkey_len)+1);
	memcpy(*mkey, mkey_buffer->data, *mkey_len);
//	(*mkey)[*mkey_len] = '\0';
	_INFO("before mkey_buffer free");
	if(mkey_buffer)
		ckmc_buffer_free(mkey_buffer);
	_INFO("after mkey_buffer free");

	_INFO("end get_app_mkey, mkey_address=[%x]", *mkey);
	return CKMC_ERROR_NONE;
}

int create_app_mkey(unsigned char **mkey, int *mkey_len)
{
	unsigned char *random;
	int ret = CKMC_ERROR_NONE;
	const char *alias = ACCOUNT_MANAGER_MKEY_ALIAS;
	ckmc_raw_buffer_s data;
	ckmc_policy_s policy;
//	unsigned char *text = (unsigned char*)"mkey_test";

	_INFO("start create_app_mkey");

	random = (unsigned char *) malloc(MKEY_LEN);
	_INFO("before _get_random");
	ret = _get_random(MKEY_LEN, &random);
	if(CKMC_ERROR_NONE != ret) {
		return CKMC_ERROR_UNKNOWN;
	}

	policy.password = "password";
	policy.extractable = true;

	data.data = random;
	data.size = MKEY_LEN;

	_INFO("before ckmc_save_data");
	ret = ckmc_save_data(alias, data, policy);
	if(CKMC_ERROR_NONE != ret) {
		if(random)
			free(random);
		return ret;
	}

	*mkey = random;
	*mkey_len = MKEY_LEN;

	_INFO("end create_app_mkey");
	return CKMC_ERROR_NONE;
}

int get_app_dek(char *mkey, const char *pkg_id, unsigned char **dek, int *dek_len)
{
	int ret = CKMC_ERROR_NONE;
	_INFO("start get_app_dek");

	const char* password = mkey;
	ckmc_raw_buffer_s *dek_buffer=NULL;
	char alias[128] = {0,};

	//    sprintf(alias, "%s %s%s", pkg_id, APP_DEK_ALIAS_PFX, pkg_id);
	sprintf(alias, "%s%s", ACCOUNT_MANAGER_DEK_ALIAS_PFX, pkg_id);

	ret = ckmc_get_data(alias, password, &dek_buffer);
	if (CKMC_ERROR_DB_ALIAS_UNKNOWN == ret) {
		ckmc_buffer_free(dek_buffer);
		return ret;
	} else if (CKMC_ERROR_NONE != ret) {
		ckmc_buffer_free(dek_buffer);
		return ret;
	}

	*dek_len = dek_buffer->size;
	*dek = (unsigned char *) malloc((*dek_len)+1);
	_INFO("before memcpy dek_buffer");
	memcpy(*dek, dek_buffer->data, (*dek_len)+1);
	_INFO("before dek_buffer free");
	ckmc_buffer_free(dek_buffer);

	_INFO("end get_app_dek");
	return CKMC_ERROR_NONE;
}

int create_app_dek(char *mkey, const char *pkg_id, unsigned char **dek, int *dek_len)
{
	unsigned char *random;
	int ret = CKMC_ERROR_NONE;
	ckmc_raw_buffer_s data;
	ckmc_policy_s policy;
	char alias[128] = {0,};
//	unsigned char *text = (unsigned char*)"dek_test";

	_INFO("start create_app_dek");

	sprintf(alias, "%s%s", ACCOUNT_MANAGER_DEK_ALIAS_PFX, pkg_id);

	random = (unsigned char *) malloc(DEK_LEN);
	ret = _get_random(DEK_LEN, &random);
	if(CKMC_ERROR_NONE != ret) {
		return CKMC_ERROR_UNKNOWN;
	}

	policy.password = mkey;
	policy.extractable = true;

	data.data = random;
	data.size = DEK_LEN;

	_INFO("before ckmc_save_data");
	// save app_dek in key_manager
	ret = ckmc_save_data(alias, data, policy);
	if(CKMC_ERROR_NONE != ret) {
		if(random)
			free(random);
		return ret;
	}
/*
	// share app_dek for web app laucher to use app_dek
	ret = ckmc_set_permission(alias, pkg_id, CKMC_PERMISSION_READ);
	if(CKMC_ERROR_NONE != ret) {
		return ret;
	}
*/
	*dek = random;
	*dek_len = DEK_LEN;

	_INFO("end create_app_dek");

	return CKMC_ERROR_NONE;
}

int account_key_handler_get_account_dek(const char *alias, unsigned char **account_dek, int *dek_len)
{
	int ret;
	unsigned char *account_mkey = NULL;
	int mkey_len = 0;

	if (alias == NULL || account_dek == NULL || dek_len == NULL)
		return ACCOUNT_ERROR_INVALID_PARAMETER;

	_INFO("before get_app_mkey");
	ret = get_app_mkey(&account_mkey, &mkey_len);
	_INFO("after get_app_mkey ret=[%d]", ret);
	if (ret != CKMC_ERROR_NONE) {	// To Do : error value
		_INFO("before create_app_mkey");
		ret = create_app_mkey(&account_mkey, &mkey_len);
		if (ret != CKMC_ERROR_NONE) {	// To Do : error value
			_ERR("create_app_mkey failed ret=[%d]", ret);
			return ret;	// To Do : error value
		}
	}

	_INFO("before get_app_mkey");
	ret = get_app_dek((char *)account_mkey, alias, account_dek, dek_len);
	_INFO("after get_app_mkey, ret=[%d]", ret);
	if (ret != CKMC_ERROR_NONE) { // To Do : error value
		ret = create_app_dek((char *)account_mkey, alias, account_dek, dek_len);
		_ACCOUNT_FREE(account_mkey);
		if (ret != CKMC_ERROR_NONE) { // To Do : error value
			_ERR("create_app_dek failed ret=[%d]", ret);
			return ret; // To Do : error value
		}
	}

	_INFO("end account_key_hander_get_account_dek");

	return ACCOUNT_ERROR_NONE;
}


int clear_test_keys(const char* pkg_id)
{
	int ret = CKMC_ERROR_NONE;
	char alias[128] = {0,};

	ret = ckmc_remove_alias(ACCOUNT_MANAGER_MKEY_ALIAS);
	if(CKMC_ERROR_NONE != ret) {
		return ret;
	}

	sprintf(alias, "%s%s", ACCOUNT_MANAGER_DEK_ALIAS_PFX, pkg_id);
	ret = ckmc_remove_alias(alias);
	if(CKMC_ERROR_NONE != ret) {
		return ret;
	}

	return CKMC_ERROR_NONE;
}
