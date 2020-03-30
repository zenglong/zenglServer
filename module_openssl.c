/*
 * module_openssl.c
 *
 *  Created on: Mar 30, 2020
 *      Author: zengl
 */

#include "main.h"
#include "module_openssl.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>

static void module_openssl_free_rsa_resource_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	RSA * rsa = (RSA *)ptr;
	RSA_free(rsa);
}

ZL_EXP_VOID module_openssl_read_key(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: opensslReadKey(key, is_public[, password]): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [key] of opensslReadKey must be string");
	}
	char * key = arg.val.str;
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	int is_public = 0;
	if(arg.type == ZL_EXP_FAT_INT) {
		is_public = (int)arg.val.integer;
	}
	else {
		zenglApi_Exit(VM_ARG,"the second argument [is_public] of opensslReadKey must be integer");
	}
	char * password = NULL;
	if(argcount > 2) {
		zenglApi_GetFunArg(VM_ARG,3,&arg);
		password = arg.val.str;
	}
	BIO * keybio = BIO_new_mem_buf(key, -1);
	if(keybio == NULL) {
		zenglApi_Exit(VM_ARG,"failed to create key BIO in opensslReadKey");
	}
	RSA * rsa = NULL;
	if(password != NULL) {
		OpenSSL_add_all_algorithms(); //密钥有经过口令加密需要这个函数
	}
	if(is_public) {
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, password);
	}
	else {
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, password);
	}
	BIO_free_all(keybio);
	if(rsa == NULL) {
		char * err = malloc(130);
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		zenglApi_SetErrThenStop(VM_ARG, "opensslReadKey ERROR: %s",err);
		free(err);
		return ;
	}
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int ret_code = resource_list_set_member(&(my_data->resource_list), rsa, module_openssl_free_rsa_resource_callback);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "opensslReadKey add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)rsa, 0);
}

ZL_EXP_VOID module_openssl_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslReadKey",module_openssl_read_key);
}
