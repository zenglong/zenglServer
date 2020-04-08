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

#define MODULE_OPENSSL_PADDING_NUM 4

typedef struct _MODULE_OPENSSL_RSA_KEY {
	RSA * rsa;
	ZL_EXP_BOOL is_public_key;
} MODULE_OPENSSL_RSA_KEY;

static void module_openssl_free_rsa_resource_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	MODULE_OPENSSL_RSA_KEY * mod_openssl_rsa = (MODULE_OPENSSL_RSA_KEY *)ptr;
	RSA_free(mod_openssl_rsa->rsa);
	zenglApi_FreeMem(VM_ARG, mod_openssl_rsa);
}

static void module_openssl_free_ptr_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	zenglApi_FreeMem(VM_ARG, ptr);
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

ZL_EXP_VOID module_openssl_get_error(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	char * err = malloc(130);
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, err, 0, 0);
	free(err);
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
		if(arg.type != ZL_EXP_FAT_STR) {
			zenglApi_Exit(VM_ARG,"the third argument [password] of opensslReadKey must be string");
		}
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
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		return;
	}
	MODULE_OPENSSL_RSA_KEY * mod_openssl_rsa = zenglApi_AllocMem(VM_ARG, sizeof(MODULE_OPENSSL_RSA_KEY));
	mod_openssl_rsa->is_public_key = (is_public ? ZL_EXP_TRUE : ZL_EXP_FALSE);
	mod_openssl_rsa->rsa = rsa;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int ret_code = resource_list_set_member(&(my_data->resource_list), mod_openssl_rsa, module_openssl_free_rsa_resource_callback);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "opensslReadKey add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)mod_openssl_rsa, 0);
}

static void common_encrypt_decrypt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount, const char * func_name,
		ZL_EXP_BOOL is_public, ZL_EXP_BOOL is_encrypt)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 4)
		zenglApi_Exit(VM_ARG,"usage: %s(data, data_len, key, &result[, padding = 0[, decrypt_to_str = 1]]): integer", func_name);
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR && arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [data] of %s must be string or integer", func_name);
	}
	unsigned char * data = NULL;
	ZL_EXP_BOOL is_data_str = ZL_EXP_FALSE;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int data_ptr_size = 0;
	if(arg.type == ZL_EXP_FAT_STR) {
		data = (unsigned char *)arg.val.str;
		is_data_str = ZL_EXP_TRUE;
	}
	else {
		data = (unsigned char *)arg.val.integer;
		int ptr_idx = pointer_list_get_ptr_idx(&(my_data->pointer_list), data);
		if(ptr_idx < 0) {
			zenglApi_Exit(VM_ARG,"runtime error: the first argument [data] of %s is invalid pointer", func_name);
		}
		data_ptr_size = my_data->pointer_list.list[ptr_idx].ptr_size;
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the second argument [data_len] of %s must be integer", func_name);
	}
	int data_len = (int)arg.val.integer;
	if(data_len < 0 && is_data_str) {
		data_len = (int)strlen((char *)data);
	}
	if(data_ptr_size > 0 && data_len > data_ptr_size) {
		data_len = data_ptr_size;
	}
	zenglApi_GetFunArg(VM_ARG,3,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the third argument [key] of %s must be integer", func_name);
	}
	MODULE_OPENSSL_RSA_KEY * mod_openssl_rsa = (MODULE_OPENSSL_RSA_KEY *)arg.val.integer;
	if(!is_valid_rsa_key(&(my_data->resource_list), mod_openssl_rsa)) {
		zenglApi_Exit(VM_ARG,"%s runtime error: invalid key", func_name);
	}
	if(is_public) {
		if(!mod_openssl_rsa->is_public_key) {
			zenglApi_Exit(VM_ARG,"%s runtime error: the key is not a public key", func_name);
		}
	}
	else {
		if(mod_openssl_rsa->is_public_key) {
			zenglApi_Exit(VM_ARG,"%s runtime error: the key is not a private key", func_name);
		}
	}
	RSA * rsa = mod_openssl_rsa->rsa;
	int paddings[MODULE_OPENSSL_PADDING_NUM] = {
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
		if(padding_idx < 0 || padding_idx >= MODULE_OPENSSL_PADDING_NUM) {
			zenglApi_Exit(VM_ARG,"the fifth argument [padding] of %s is invalid, must be in [0, %d)", func_name, MODULE_OPENSSL_PADDING_NUM);
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
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)retval, 0);
		return ;
	}
	ZL_EXP_BOOL is_result_ptr = ZL_EXP_FALSE;
	if(is_encrypt) {
		set_arg_value(VM_ARG, 4, ZL_EXP_FAT_INT, NULL, (ZL_EXP_LONG)result);
		is_result_ptr = ZL_EXP_TRUE;
	}
	else {
		int decrypt_to_str = ZL_EXP_TRUE;
		if(argcount > 5) {
			zenglApi_GetFunArg(VM_ARG,6,&arg);
			if(arg.type != ZL_EXP_FAT_INT) {
				zenglApi_Exit(VM_ARG,"the sixth argument [decrypt_to_str] of %s must be integer", func_name);
			}
			decrypt_to_str = (int)arg.val.integer;
		}
		if(decrypt_to_str) {
			set_arg_value(VM_ARG, 4, ZL_EXP_FAT_STR, (ZL_EXP_CHAR *)result, 0);
			zenglApi_FreeMem(VM_ARG, result);
		}
		else {
			set_arg_value(VM_ARG, 4, ZL_EXP_FAT_INT, NULL, (ZL_EXP_LONG)result);
			is_result_ptr = ZL_EXP_TRUE;
		}
	}
	if(is_result_ptr) {
		int ret_set_ptr = pointer_list_set_member(&(my_data->pointer_list), result, retval, module_openssl_free_ptr_callback);
		if(ret_set_ptr != 0) {
			zenglApi_Exit(VM_ARG, "%s add pointer to pointer_list failed, pointer_list_set_member error code:%d", func_name, ret_set_ptr);
		}
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
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslGetError",module_openssl_get_error);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslReadKey",module_openssl_read_key);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslPublicEncrypt",module_openssl_public_encrypt);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslPrivateDecrypt",module_openssl_private_decrypt);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslPrivateEncrypt",module_openssl_private_encrypt);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslPublicDecrypt",module_openssl_public_decrypt);
}
