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
#include <string.h>

#define MOD_OPENSSL_PADDING_NUM 4

static void module_openssl_free_rsa_resource_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	RSA * rsa = (RSA *)ptr;
	RSA_free(rsa);
}

static ZL_EXP_BOOL is_valid_rsa_key(RESOURCE_LIST * resource_list, void * key)
{
	int ret = resource_list_get_ptr_idx(resource_list, key, module_openssl_free_rsa_resource_callback);
	if(ret >= 0)
		return ZL_EXP_TRUE;
	else
		return ZL_EXP_FALSE;
}

/**
 * 检测模块函数argnum位置所对应的参数，是否是引用类型
 */
static void detect_arg_is_address_type(ZL_EXP_VOID * VM_ARG, int argnum, ZENGL_EXPORT_MOD_FUN_ARG * arg,
		const char * arg_pos, const char * arg_name, const char * func_name)
{
	zenglApi_GetFunArgInfo(VM_ARG,argnum,arg);
	switch(arg->type){
	case ZL_EXP_FAT_ADDR:
	case ZL_EXP_FAT_ADDR_LOC:
	case ZL_EXP_FAT_ADDR_MEMBLK:
		break;
	default:
		zenglApi_Exit(VM_ARG,"the %s argument [&%s] of %s must be address type", arg_pos, arg_name, func_name);
		break;
	}
}

/**
 * 将模块函数argnum位置对应的参数设置为指定的值
 */
static void set_arg_value(ZL_EXP_VOID * VM_ARG, int argnum, ZENGL_EXPORT_MOD_FUN_ARG_TYPE arg_type,
		ZL_EXP_CHAR * arg_str_val, ZL_EXP_LONG arg_int_val)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	arg.type = arg_type;
	if(arg_type == ZL_EXP_FAT_STR) {
		arg.val.str = arg_str_val;
	}
	else if(arg_type == ZL_EXP_FAT_INT) {
		arg.val.integer = arg_int_val;
	}
	zenglApi_SetFunArg(VM_ARG,argnum,&arg);
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

static void common_encrypt_decrypt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount, const char * func_name,
		ZL_EXP_BOOL is_public, ZL_EXP_BOOL is_encrypt)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 4)
		zenglApi_Exit(VM_ARG,"usage: %s(data, data_len, key, &result[, padding = 0]): integer", func_name);
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR && arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [data] of %s must be string or integer", func_name);
	}
	unsigned char * data = NULL;
	ZL_EXP_BOOL is_data_str = ZL_EXP_FALSE;
	if(arg.type == ZL_EXP_FAT_STR) {
		data = (unsigned char *)arg.val.str;
		is_data_str = ZL_EXP_TRUE;
	}
	else {
		data = (unsigned char *)arg.val.integer;
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the second argument [data_len] of %s must be integer", func_name);
	}
	int data_len = (int)arg.val.integer;
	if(data_len < 0 && is_data_str) {
		data_len = (int)strlen((char *)data);
	}
	zenglApi_GetFunArg(VM_ARG,3,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the third argument [key] of %s must be integer", func_name);
	}
	RSA * rsa = (RSA *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_rsa_key(&(my_data->resource_list), rsa)) {
		zenglApi_Exit(VM_ARG,"%s runtime error: invalid key", func_name);
	}
	int paddings[MOD_OPENSSL_PADDING_NUM] = {
		RSA_PKCS1_PADDING,       // 索引: 0
		RSA_PKCS1_OAEP_PADDING,  // 索引: 1
		RSA_SSLV23_PADDING,      // 索引: 2
		RSA_NO_PADDING           // 索引: 3
	};
	int padding = paddings[0];
	if(argcount > 4) {
		zenglApi_GetFunArg(VM_ARG,5,&arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the fifth argument [padding] of %s must be integer", func_name);
		}
		int padding_idx = (int)arg.val.integer;
		if(padding_idx < 0 || padding_idx >= MOD_OPENSSL_PADDING_NUM) {
			zenglApi_Exit(VM_ARG,"the fifth argument [padding] of %s is invalid, must be in [0, %d)", func_name, MOD_OPENSSL_PADDING_NUM);
		}
		padding = paddings[padding_idx];
	}
	detect_arg_is_address_type(VM_ARG, 4, &arg, "fourth", "result", func_name);
	int rsa_len = RSA_size(rsa);
	unsigned char * result = (unsigned char *)zenglApi_AllocMem(VM_ARG, rsa_len);
	memset(result, 0, rsa_len);
	int retval = 0;
	if(is_public) {
		if(is_encrypt) {
			retval = RSA_public_encrypt(data_len,data,result,rsa,padding);
		}
		else {
			retval = RSA_public_decrypt(data_len,data,result,rsa,padding);
		}
	}
	else {
		if(is_encrypt) {
			retval = RSA_private_encrypt(data_len,data,result,rsa,padding);
		}
		else {
			retval = RSA_private_decrypt(data_len,data,result,rsa,padding);
		}
	}
	if(retval == -1) {
		char * err = malloc(130);
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		zenglApi_SetErrThenStop(VM_ARG, "%s ERROR: %s", func_name, err);
		free(err);
		return ;
	}
	if(is_encrypt) {
		set_arg_value(VM_ARG, 4, ZL_EXP_FAT_INT, NULL, (ZL_EXP_LONG)result);
	}
	else {
		set_arg_value(VM_ARG, 4, ZL_EXP_FAT_STR, (ZL_EXP_CHAR *)result, 0);
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)retval, 0);
}

ZL_EXP_VOID module_openssl_public_encrypt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	common_encrypt_decrypt(VM_ARG, argcount, "opensslPublicEncrypt", ZL_EXP_TRUE, ZL_EXP_TRUE);
}

ZL_EXP_VOID module_openssl_private_decrypt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	common_encrypt_decrypt(VM_ARG, argcount, "opensslPrivateDecrypt", ZL_EXP_FALSE, ZL_EXP_FALSE);
}

ZL_EXP_VOID module_openssl_private_encrypt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	common_encrypt_decrypt(VM_ARG, argcount, "opensslPrivateEncrypt", ZL_EXP_FALSE, ZL_EXP_TRUE);
}

ZL_EXP_VOID module_openssl_public_decrypt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	common_encrypt_decrypt(VM_ARG, argcount, "opensslPublicDecrypt", ZL_EXP_TRUE, ZL_EXP_FALSE);
}

ZL_EXP_VOID module_openssl_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslReadKey",module_openssl_read_key);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslPublicEncrypt",module_openssl_public_encrypt);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslPrivateDecrypt",module_openssl_private_decrypt);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslPrivateEncrypt",module_openssl_private_encrypt);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslPublicDecrypt",module_openssl_public_decrypt);
}
