
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
 * @file        account-crypto-service.c
 * @brief       provides encryption and decription operations.
 */
#include <stdio.h>
#include <tizen.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <dbg.h>
#include <account-private.h>
#include "account-crypto-service.h"

#define AES_256_KEY_SIZE 32
#define AES_CBC_IV "01234567890123456"

//#define FALSE 0
//#define TRUE  1

#define CRYPTO_ERROR -1
#define CRYPTO_ERROR_NONE 0
#define CRYPTO_ERROR_INVALID_PARAMETER TIZEN_ERROR_INVALID_PARAMETER

static int initialized = FALSE;

void initialize()
{
    if(!initialized) {
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
		initialized = TRUE;
    }
}

int encrypt_aes_cbc(const unsigned char* key, const int key_len, const unsigned char* data, const int data_len,
                    char** encrypted_data, int* enc_data_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    unsigned char *ciphertext = NULL;
    int ciphertext_len;
    unsigned char *iv = (unsigned char *)AES_CBC_IV;
    int ret = CRYPTO_ERROR_NONE;

    initialize();

    /* check input paramter */
    if( key_len != 32 ) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    // assing a enough memory for decryption.
    ciphertext = (unsigned char*) malloc(data_len + 32);
	ACCOUNT_MEMSET(ciphertext, 0, data_len + 32);

	_INFO("before EVP_CIPHER_CTX_new");
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ret = CRYPTO_ERROR;
        goto error;
    }
	_INFO("after EVP_CIPHER_CTX_new success");

	_INFO("before EVP_EncryptInit_ex");
    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ret = CRYPTO_ERROR;
        goto error;
    }
	_INFO("after EVP_EncryptInit_ex success");

	_INFO("before EVP_EncryptUpdate, data = %s, data_len=[%d]", data, data_len);
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, data, data_len)) {
        ret = CRYPTO_ERROR;
        goto error;
    }
    ciphertext_len = len;
	_INFO("after EVP_EncryptUpdate, data = %s, data_len=[%d]", data, data_len);

	_INFO("before EVP_EncryptFinal_ex, ciphertext_len=[%d]", ciphertext_len);
    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ret = CRYPTO_ERROR;
        goto error;
    }
    ciphertext_len += len;
	_INFO("after EVP_EncryptFinal_ex, ciphertext_len=[%d]", ciphertext_len);

    *encrypted_data = (char *)ciphertext;
    *enc_data_len = ciphertext_len;

    ret = CRYPTO_ERROR_NONE;
error:
    if(ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    if(ret != CRYPTO_ERROR_NONE && ciphertext != NULL)
        free(ciphertext);
    return ret;
}

int decrypt_aes_cbc(const unsigned char* key, const int key_len, const unsigned char* data, const int data_len,
                    char** decrypted_data, int* dec_data_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    unsigned char* plaintext = NULL;
    int plaintext_len;
    unsigned char *iv = (unsigned char *)AES_CBC_IV;
    int ret = CRYPTO_ERROR_NONE;

    initialize();

    /* check input paramter */
    if( key_len != 32 ) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    // assing a enough memory for decryption.
    plaintext = (unsigned char*) malloc(data_len);
	ACCOUNT_MEMSET(plaintext, 0, data_len);

	_INFO("before EVP_CIPHER_CTX_new");
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ret = CRYPTO_ERROR;
        goto error;
    }
	_INFO("after EVP_CIPHER_CTX_new");

	_INFO("before EVP_DecryptInit_ex");
    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ret = CRYPTO_ERROR;
        goto error;
    }
	_INFO("after EVP_DecryptInit_ex");

	_INFO("before EVP_DecryptUpdate, data_len=[%d]", data_len);
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, data, data_len)) {
        ret = CRYPTO_ERROR;
        goto error;
    }
    plaintext_len = len;
	_INFO("after EVP_DecryptUpdate, data_len=[%d], plaintext_len=[%d]", data_len, plaintext_len);

	_INFO("before EVP_EncryptFinal_ex");
    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ret = CRYPTO_ERROR;
        goto error;
    }
    plaintext_len += len;
	_INFO("after EVP_EncryptFinal_ex, plaintext_len=[%d]",plaintext_len);

    *decrypted_data = (char *)plaintext;
	(*decrypted_data)[plaintext_len] = '\0';
    *dec_data_len = plaintext_len;
	_INFO("after decrypted_data = (char *)plaintext;, *decrypted_data = %s", *decrypted_data);

    ret = CRYPTO_ERROR_NONE;
error:
    if(ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    if(ret != CRYPTO_ERROR_NONE && plaintext != NULL)
        free(plaintext);
    return ret;
}
