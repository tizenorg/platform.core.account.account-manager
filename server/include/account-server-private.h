/*
 *  account
 *
 * Copyright (c) 2012 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jiseob Jang <jiseob.jang@samsung.com>
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

#ifndef __ACCOUNT_SERVER_PRIVATE_H__
#define __ACCOUNT_SERVER_PRIVATE_H__


#ifdef __cplusplus
extern "C"
{
#endif

#include <glib.h>
#include <account-private.h>

int _account_gslist_free(GSList* list);
int _account_glist_free(GList* list);
int _account_free_capability_items(account_capability_s *data);
int _account_custom_item_free(account_custom_s *data);
int _account_custom_gslist_free(GSList* list);
int _account_free_account_items(account_s *data);
int _account_type_free_label_items(label_s *data);
int _account_type_free_feature_items(provider_feature_s *data);
int _account_type_gslist_free(GSList* list);
int _account_type_item_free(account_type_s *data);
//int _account_type_glist_free(GList* list);
int _account_type_free_account_type_items(account_type_s *data);

#ifdef __cplusplus
}
#endif

#endif /* __ACCOUNT_SERVER_PRIVATE_H__*/
