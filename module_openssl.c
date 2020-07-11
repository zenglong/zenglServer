/*
 * module_openssl.c
 *
 *  Created on: Mar 30, 2020
 *      Author: zengl
 */

#include "main.h"
#include "module_openssl.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <string.h>

// rsa加密解密函数需要使用一个padding参数，目前模块函数暂时只支持4个padding值
#define MODULE_OPENSSL_PADDING_NUM 4
// 在执行rsa签名时需要使用一个type签名类型，目前模块函数暂时只支持9个签名类型
#define MODULE_OPENSSL_SIGN_TYPE 9

// 如果定义了NID_sha，就将NID_sha的值定义给MOD_OPENSSL_NID_sha，否则就将MOD_OPENSSL_NID_sha设置为-1，表示底层openssl库不支持该签名类型
#ifdef NID_sha
	#define MOD_OPENSSL_NID_sha NID_sha
#else
	#define MOD_OPENSSL_NID_sha -1
#endif

// 如果定义了NID_sha1，就将NID_sha1的值定义给MOD_OPENSSL_NID_sha1，否则就将MOD_OPENSSL_NID_sha1设置为-1，表示底层openssl库不支持该签名类型
#ifdef NID_sha1
	#define MOD_OPENSSL_NID_sha1 NID_sha1
#else
	#define MOD_OPENSSL_NID_sha1 -1
#endif

// 如果定义了NID_ripemd160，就将NID_ripemd160的值定义给MOD_OPENSSL_NID_ripemd160，否则就将MOD_OPENSSL_NID_ripemd160设置为-1，表示底层openssl库不支持该签名类型
#ifdef NID_ripemd160
	#define MOD_OPENSSL_NID_ripemd160 NID_ripemd160
#else
	#define MOD_OPENSSL_NID_ripemd160 -1
#endif

// 如果定义了NID_md5，就将NID_md5的值定义给MOD_OPENSSL_NID_md5，否则就将MOD_OPENSSL_NID_md5设置为-1，表示底层openssl库不支持该签名类型
#ifdef NID_md5
	#define MOD_OPENSSL_NID_md5 NID_md5
#else
	#define MOD_OPENSSL_NID_md5 -1
#endif

// 如果定义了NID_md5_sha1，就将NID_md5_sha1的值定义给MOD_OPENSSL_NID_md5_sha1，否则就将MOD_OPENSSL_NID_md5_sha1设置为-1，表示底层openssl库不支持该签名类型
#ifdef NID_md5_sha1
	#define MOD_OPENSSL_NID_md5_sha1 NID_md5_sha1
#else
	#define MOD_OPENSSL_NID_md5_sha1 -1
#endif

// 如果定义了NID_sha256，就将NID_sha256的值定义给MOD_OPENSSL_NID_sha256，否则就将MOD_OPENSSL_NID_sha256设置为-1，表示底层openssl库不支持该签名类型
#ifdef NID_sha256
	#define MOD_OPENSSL_NID_sha256 NID_sha256
#else
	#define MOD_OPENSSL_NID_sha256 -1
#endif

// 如果定义了NID_sha256WithRSAEncryption，就将NID_sha256WithRSAEncryption的值定义给MOD_OPENSSL_NID_sha256WithRSAEncryption，
// 否则就将MOD_OPENSSL_NID_sha256WithRSAEncryption设置为-1，表示底层openssl库不支持该签名类型
#ifdef NID_sha256WithRSAEncryption
	#define MOD_OPENSSL_NID_sha256WithRSAEncryption NID_sha256WithRSAEncryption
#else
	#define MOD_OPENSSL_NID_sha256WithRSAEncryption -1
#endif

// 如果定义了NID_sha512，就将NID_sha512的值定义给MOD_OPENSSL_NID_sha512，否则就将MOD_OPENSSL_NID_sha512设置为-1，表示底层openssl库不支持该签名类型
#ifdef NID_sha512
	#define MOD_OPENSSL_NID_sha512 NID_sha512
#else
	#define MOD_OPENSSL_NID_sha512 -1
#endif

// 如果定义了NID_sha512WithRSAEncryption，就将NID_sha512WithRSAEncryption的值定义给MOD_OPENSSL_NID_sha512WithRSAEncryption，
// 否则就将MOD_OPENSSL_NID_sha512WithRSAEncryption设置为-1，表示底层openssl库不支持该签名类型
#ifdef NID_sha512WithRSAEncryption
	#define MOD_OPENSSL_NID_sha512WithRSAEncryption NID_sha512WithRSAEncryption
#else
	#define MOD_OPENSSL_NID_sha512WithRSAEncryption -1
#endif

// 对RSA指针进行模块封装
typedef struct _MODULE_OPENSSL_RSA_KEY {
	RSA * rsa; // openssl底层库函数在进行加密解密，签名操作时所需要的RSA指针，通过读取RSA密钥key生成的指针
	ZL_EXP_BOOL is_public_key; // 判断是公钥key生成的RSA指针，还是私钥key生成的
	EVP_PKEY * evp_key;
} MODULE_OPENSSL_RSA_KEY;

/**
 * 在zengl脚本退出时，会自动调用下面这个回调函数，将分配过的rsa key资源给释放掉
 */
static void module_openssl_free_rsa_resource_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	MODULE_OPENSSL_RSA_KEY * mod_openssl_rsa = (MODULE_OPENSSL_RSA_KEY *)ptr;
	// RSA_free(mod_openssl_rsa->rsa);
	EVP_PKEY_free(mod_openssl_rsa->evp_key);
	zenglApi_FreeMem(VM_ARG, mod_openssl_rsa);
}

/**
 * 在zengl脚本退出时，会自动调用下面这个回调函数，将openssl模块函数分配过的指针给释放掉，使用bltFree释放指针时，也会调用这个函数来执行具体的释放操作
 */
static void module_openssl_free_ptr_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	zenglApi_FreeMem(VM_ARG, ptr);
}

/**
 * openssl模块函数内部会通过此函数来判断，脚本提供的key参数是否是有效的rsa key
 */
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

/**
 * 以下代码参考自php的openssl扩展：https://github.com/php/php-src/blob/master/ext/openssl/openssl.c
 */
static EVP_MD * st_get_evp_md_from_algo(int algo)
{
	EVP_MD *mdtype;

	switch (algo) {
	case MOD_OPENSSL_NID_sha1:
		mdtype = (EVP_MD *) EVP_sha1();
		break;
	case MOD_OPENSSL_NID_ripemd160:
		mdtype = (EVP_MD *) EVP_ripemd160();
		break;
	case MOD_OPENSSL_NID_md5:
		mdtype = (EVP_MD *) EVP_md5();
		break;
	case MOD_OPENSSL_NID_sha256:
		mdtype = (EVP_MD *) EVP_sha256();
		break;
	case MOD_OPENSSL_NID_sha512:
		mdtype = (EVP_MD *) EVP_sha512();
		break;
	default:
		return NULL;
		break;
	}

	return mdtype;
}

/**
 * opensslGetError模块函数，用于获取openssl操作失败时的出错信息
 *
 * 例如：
	use builtin,openssl;
	def NULL 0;

	.............................. // 省略中间代码

	key = opensslReadKey(key_content, is_public, password);
	if(key == NULL)
		exit('read key "'+ file +'" failed: ' + opensslGetError());
	endif

	上面代码片段中，如果opensslReadKey读取密钥key失败，则会通过opensslGetError来获取具体的错误信息，从而可以知道大概的出错原因

	模块函数版本历史：
	 - v0.20.0版本新增此模块函数
 */
ZL_EXP_VOID module_openssl_get_error(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	char * err = malloc(130);
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, err, 0, 0);
	free(err);
}

/**
 * opensslReadKey模块函数，读取密钥key，并返回和key相关的指针
 * 第一个参数key必须是字符串类型，表示密钥的具体内容，如果密钥存在于文件中，则需要先将文件里的密钥内容读取出来，然后再传给此函数
 * 第二个参数is_public必须是整数类型，当值为不为0的整数时表示公钥，为0时表示私钥
 * 第三个参数password是可选参数(如果提供了的话，必须是字符串类型)，表示密钥相关的密码，密钥可以经过加密处理，如果密钥被加密过，就需要提供相关的密码
 *
 * 例如：
	use builtin,openssl;
	def RSA_PUBLIC 1;
	def RSA_PRIVATE 0;
	def NULL 0;

	fun exit(msg)
		print msg;
		bltExit();
	endfun

	fun read_rsa_key(file, is_public, password = '')
		ret = bltReadFile(file, &key_content, &file_size);
		if(ret == 0)
			print file + ' file size: ' + file_size;
			if(password)
				key = opensslReadKey(key_content, is_public, password);
			else
				key = opensslReadKey(key_content, is_public);
			endif
			if(key == NULL)
				exit('read key "'+ file +'" failed: ' + opensslGetError());
			endif
			print 'key:' + key;
			return key;
		else
			exit('read '+file+' failed, maybe the file does not exists, or open failed.');
		endif
	endfun

	key = read_rsa_key('rsa_public.key', RSA_PUBLIC);
	p_key = read_rsa_key('rsa_private.key', RSA_PRIVATE);
	p_aes_key = read_rsa_key('rsa_aes_private.key', RSA_PRIVATE, '111111');

	上面代码片段中，由于密钥存储于文件中，因此，会先通过bltReadFile模块函数根据文件名读取出密钥的具体内容，
	接着将密钥内容传递给opensslReadKey模块函数，并通过第二个is_public参数来指定该密钥是公钥还是私钥，
	如果密钥经过了加密处理，就再通过第三个password参数设置相关的密码，opensslReadKey在成功读取了密钥后，
	会返回一个和密钥相关的key指针，通过该指针就可以进行RSA加密解密，签名之类的操作了

	模块函数版本历史：
	 - v0.20.0版本新增此模块函数
 */
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
	mod_openssl_rsa->evp_key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(mod_openssl_rsa->evp_key, rsa);
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int ret_code = resource_list_set_member(&(my_data->resource_list), mod_openssl_rsa, module_openssl_free_rsa_resource_callback);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "opensslReadKey add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)mod_openssl_rsa, 0);
}

/**
 * 下面的C函数是 opensslPublicEncrypt，opensslPrivateEncrypt，opensslPrivateDecrypt，opensslPublicDecrypt 这四个RSA加密解密模块函数的通用C代码
 * 第一个参数data表示需要加密或解密的原数据，可以是字符串类型，也可以是整数形式的指针类型
 * 第二个参数data_len表示需要加密或解密的原数据的字节大小，必须是整数类型
 * 第三个参数key表示密钥相关的key指针，也就是opensslReadKey模块函数返回的指针
 * 第四个参数&result必须是引用类型，用于存储加密或解密后的结果
 * 第五个参数padding是可选参数(如果提供了的话，必须是整数类型)，表示加密或解密操作时的padding类型，目前暂时支持4个padding值(默认值是0)：
 *  - 当padding值为0时表示 RSA_PKCS1_PADDING，
 *  - 当padding值为1时表示 RSA_PKCS1_OAEP_PADDING，
 *  - 当padding值为2时表示 RSA_SSLV23_PADDING，
 *  - 当padding值为3时表示 RSA_NO_PADDING
 *  上面的某些padding在有的操作中无法使用，例如：
 *  在1.0.2k-fips版本的openssl底层库中，私钥加密opensslPrivateEncrypt相关的底层库函数 RSA_private_encrypt 不支持 RSA_PKCS1_OAEP_PADDING 和 RSA_SSLV23_PADDING，
 *  详情可以通过man RSA_private_encrypt命令查看到，当提供了不支持的padding时，底层库函数也会反馈相应的错误信息
 *
 * 第六个参数decrypt_to_str是可选参数(如果提供了的话，也必须是整数类型)，表示在进行RSA解密操作时，是否需要将result结果转为字符串类型，
 *  - decrypt_to_str参数的默认值是1表示需要将结果转为字符串类型，如果提供0值则表示不需要转为字符串类型，则结果会以整数类型的指针形式存储到result参数中
 *
 * 第七个参数use_block也是可选参数(如果提供了的话，也必须是整数类型)，表示加密和解密操作时，是否需要根据key的尺寸进行分块的加密和解密操作，因为密钥key对
 * 加密或解密的数据是有尺寸要求的，超出尺寸时，会提示数据太长，因此将太长的数据进行分块，每块数据都使用相同的密钥，进行加密和解密，就可以解决这个问题。
 *  - 当use_block的值为1时表示需要进行分块处理，当为0时表示不需要进行分块处理，默认值为0表示不需要进行分块
 *
 * 例如：
	use builtin,openssl;
	use builtin,openssl;
	def RSA_PUBLIC 1;
	def RSA_PRIVATE 0;
	def RSA_PKCS1_PADDING 0;
	def TRUE 1;
	def FALSE 0;
	def NULL 0;
	def DUMP_HEX 2;

	fun exit(msg)
		print msg;
		bltExit();
	endfun

	fun read_rsa_key(file, is_public, password = '')
		.........................  // 省略中间代码，读取密钥key的代码可以参考opensslReadKey模块函数的示例代码
	endfun

	fun print_header()
		print '\n=======================================\n';
	endfun

	fun encrypt_and_decrypt(pub_pri, str, key, p_key, decrypt_to_str = TRUE, use_block = FALSE)
		print_header();

		if(pub_pri == 'public')
			if(use_block)
				enc_len = opensslPublicEncrypt(str, -1, key, &enc, RSA_PKCS1_PADDING, FALSE, use_block);
			else
				enc_len = opensslPublicEncrypt(str, -1, key, &enc);
			endif
		else
			enc_len = opensslPrivateEncrypt(str, -1, p_key, &enc, RSA_PKCS1_PADDING, FALSE, use_block);
		endif
		if(enc_len == -1)
			exit(pub_pri + ' encrypt failed: ' + opensslGetError());
		endif

		file_name = pub_pri + '_enc.data';
		bltWriteFile(file_name, enc, enc_len);
		bltReadFile(file_name, &file_data, &file_size, &file_data_ptr);
		print file_name + ' - size:' + file_size;
		print file_name + ' - data:' + bltDumpPtrData(file_data_ptr, file_size, DUMP_HEX);

		if(pub_pri == 'public')
			dec_len = opensslPrivateDecrypt(file_data_ptr, file_size, p_key, &dec, RSA_PKCS1_PADDING, decrypt_to_str, use_block);
		else
			dec_len = opensslPublicDecrypt(file_data_ptr, file_size, key, &dec, RSA_PKCS1_PADDING, decrypt_to_str, use_block);
		endif

		if(dec_len == -1)
			exit(pub_pri + ' decrypt failed: ' + opensslGetError());
		endif
		print 'decrypt_to_str: ' + decrypt_to_str;
		print 'dec_len:' + dec_len;
		if(decrypt_to_str)
			print 'dec:' + dec;
		else
			print 'dec ptr:' + dec;
			print 'dec ptr data:' + bltDumpPtrData(dec, dec_len, DUMP_CHAR);
			bltFree(dec);
		endif

		bltFree(enc);
	endfun

	key = read_rsa_key('rsa_public.key', RSA_PUBLIC);
	p_key = read_rsa_key('rsa_private.key', RSA_PRIVATE);
	p_aes_key = read_rsa_key('rsa_aes_private.key', RSA_PRIVATE, '111111');

	encrypt_and_decrypt('public', 'hello world!', key, p_key);

	encrypt_and_decrypt('private', '!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!', key, p_aes_key, TRUE, TRUE);

	encrypt_and_decrypt('public', 'hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!', key, p_key, TRUE, TRUE);

	encrypt_and_decrypt('private', '!!! hello world! other test!!!', key, p_aes_key);
	encrypt_and_decrypt('private2', '!!! hello world! hahaha ~~~', key, p_aes_key, FALSE);

	上面代码片段中的encrypt_and_decrypt是测试加密和解密操作的脚本函数，
	当该函数的第一个参数是public时，会先通过opensslPublicEncrypt进行公钥加密，再通过opensslPrivateDecrypt进行私钥解密，
	当该函数的第一个参数不是public时，，则会先通过opensslPrivateEncrypt进行私钥加密，再通过opensslPublicDecrypt进行公钥解密
	该脚本函数在进行加密和解密后，会将加密和解密的结果打印出来，当结果是整数类型的指针时，会通过bltDumpPtrData模块函数，将指针所指向的二进制数据以十六进制的格式显示出来。

	以上代码片段的执行结果类似如下所示：

	rsa_public.key file size: 451
	key:20127712
	rsa_private.key file size: 1679
	key:20129488
	rsa_aes_private.key file size: 1766
	key:20023904

	=======================================

	public_enc.data - size:256
	public_enc.data - data:05 D8 17 45 03 70 68 93 F5 98 AF E7 E2 64 04 53 AF D5 DF B4 44 36 30 06 82 78 71 B3 1C ......................
	decrypt_to_str: 1
	dec_len:12
	dec:hello world!

	=======================================

	private_enc.data - size:1024
	private_enc.data - data:C4 CC 02 82 F3 2D 83 F6 B7 40 4F EC 38 03 82 54 65 63 AD FE 0C 8D AF 82 98 A7 7C 79 EE ......................
	decrypt_to_str: 1
	dec_len:750
	dec:!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!!!! hello world! other test!!!

	=======================================

	public_enc.data - size:512
	public_enc.data - data:A6 0E 35 49 2D 0A 9D FC 4F D4 70 28 8E 78 79 3A 00 CD 19 B1 71 B5 35 AA D2 B1 A7 09 05 ......................
	decrypt_to_str: 1
	dec_len:372
	dec:hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!

	=======================================

	private_enc.data - size:256
	private_enc.data - data:29 C3 F5 11 92 AD C9 8E 07 2F 3E F6 8C FE 93 F9 3E D2 86 13 F4 51 78 24 CD D2 01 74 53 ......................
	decrypt_to_str: 1
	dec_len:30
	dec:!!! hello world! other test!!!

	=======================================

	private2_enc.data - size:256
	private2_enc.data - data:1C 7A FB 80 2D AE 74 5E DC 6E 6E C4 1C 9D 7F EB 14 42 82 63 2D AF CC E7 BF BC 33 7D C6 ......................
	decrypt_to_str: 0
	dec_len:27
	dec ptr:20125216
	dec ptr data:! ! !   h e l l o   w o r l d !   h a h a h a   ~ ~ ~
 */
static void common_encrypt_decrypt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount, const char * func_name,
		ZL_EXP_BOOL is_public, ZL_EXP_BOOL is_encrypt)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 4)
		zenglApi_Exit(VM_ARG,"usage: %s(data, data_len, key, &result[, padding = 0[, decrypt_to_str = 1[, use_block = 0]]]): integer", func_name);
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
	int rsa_size = RSA_size(rsa);
	int data_blocks = 1;
	int data_block_size = data_len;
	int result_block_size = rsa_size;
	ZL_EXP_BOOL use_block = ZL_EXP_FALSE;
	if(argcount > 6) {
		zenglApi_GetFunArg(VM_ARG,7,&arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the seventh argument [use_block] of %s must be integer", func_name);
		}
		if(arg.val.integer != 0)
			use_block = ZL_EXP_TRUE;
		else
			use_block = ZL_EXP_FALSE;
	}
	if(data_len > 0 && use_block) {
		if(is_public && is_encrypt) {
			switch(padding) {
			case RSA_SSLV23_PADDING:
			case RSA_PKCS1_PADDING:
				data_block_size = rsa_size - 12;
				break;
			case RSA_PKCS1_OAEP_PADDING:
				data_block_size = rsa_size - 42;
				break;
			case RSA_NO_PADDING:
				data_block_size = rsa_size - 1;
				break;
			}
			result_block_size = rsa_size;
		}
		else if(!is_public && !is_encrypt) {
			data_block_size = rsa_size;
			result_block_size = rsa_size - 1;
		}
		else if(!is_public && is_encrypt) {
			data_block_size = rsa_size - 12;
			result_block_size = rsa_size;
		}
		else {
			data_block_size = rsa_size;
			result_block_size = rsa_size - 12;
		}
		data_blocks = data_len / data_block_size;
		if(data_blocks > 0) {
			if(data_len % data_block_size > 0) {
				data_blocks += 1;
			}
		}
		else {
			data_blocks = 1;
		}
	}
	int result_size = data_blocks * result_block_size;
	unsigned char * result = (unsigned char *)zenglApi_AllocMem(VM_ARG, result_size);
	memset(result, 0, result_size);
	int retval = 0;
	int i;
	for(i = 0 ; i < data_blocks ; i++) {
		int data_block_len = data_block_size;
		if(data_len > 0) {
			if(i == (data_blocks - 1)) {
				data_block_len = data_len - (i * data_block_size);
			}
		}
		else
			data_block_len = 0;
		int inner_retval = 0;
		int data_step = i * data_block_size;
		if(is_public) {
			if(is_encrypt) {
				inner_retval = RSA_public_encrypt(data_block_len,data + data_step,result + retval,rsa,padding);
			}
			else {
				inner_retval = RSA_public_decrypt(data_block_len,data + data_step,result + retval,rsa,padding);
			}
		}
		else {
			if(is_encrypt) {
				inner_retval = RSA_private_encrypt(data_block_len,data + data_step,result + retval,rsa,padding);
			}
			else {
				inner_retval = RSA_private_decrypt(data_block_len,data + data_step,result + retval,rsa,padding);
			}
		}
		if(inner_retval == -1) {
			zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)inner_retval, 0);
			return ;
		}
		retval += inner_retval;
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
			result[retval] = '\0';
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

/**
 * 下面C函数是 opensslSign 和 opensslVerify 模块函数的通用C代码
 * 第一个参数data表示RSA签名或验签的原数据，必须是字符串类型，或者是整数类型的指针
 * 第二个参数data_len表示签名或验签的原数据的字节大小，必须是整数类型
 * 第三个参数private_key|public_key表示签名需要的私钥key，或者验签需要的公钥key，通过opensslReadKey模块函数返回，必须是整数类型
 * 第四个参数当执行签名操作时，必须是引用类型，用于存储RSA签名的结果，如果是验签操作，则必须是整数类型的指针，用于指向验签用的签名数据
 * 第五个参数当执行签名操作时，必须是引用类型，用于存储RSA签名结果的字节大小，如果是验签操作，则必须是整数类型，表示用于验签的签名数据的字节大小
 * 第六个参数type必须是整数，表示签名数据类型，目前暂时只支持9种类型：
 *  - type 为0时表示 NID_sha 签名类型
 *  - type 为1时表示 NID_sha1 签名类型
 *  - type 为2时表示 NID_ripemd160 签名类型
 *  - type 为3时表示 NID_md5 签名类型
 *  - type 为4时表示 NID_md5_sha1 签名类型
 *  - type 为5时表示 NID_sha256 签名类型
 *  - type 为6时表示 NID_sha256WithRSAEncryption 签名类型
 *  - type 为7时表示 NID_sha512 签名类型
 *  - type 为8时表示 NID_sha512WithRSAEncryption 签名类型
 *  这些签名类型和底层openssl库的具体版本相关，如果底层库因为历史版本原因不支持某个签名类型时，有可能会报不支持该类型的错误
 *  无论底层库是否支持这些签名类型，也无论底层库中这些签名类型实际的宏值是多少，type值与签名类型的对应关系都不会变，也就是说
 *  当type为1时，它始终表示 NID_sha1 的签名类型，如果底层库不支持该类型的话，模块函数也会反馈相应的错误提示
 *  type是可选参数，默认值是0，也就是 NID_sha 签名类型
 * 第七个参数use_evp也是可选参是，当提供了此参数时，必须是整数类型，表示在进行签名和验签时是否使用EVP_为前缀的底层库函数进行签名操作
 *  use_evp的默认值是0，表示使用默认的 RSA_sign 和 RSA_verify 的底层库函数来完成签名和验签操作
 *  当use_evp的值不为0时，则表示使用 EVP_SignFinal 和 EVP_VerifyFinal 的底层库函数来完成签名和验签操作
 *  当需要进行支付宝签名和验签时，需要使用EVP_为前缀的底层库函数来执行相关的底层操作，php语言的签名和验签的底层库函数也是用的EVP_为前缀的库函数
 *
 * 例如：
	use builtin,openssl;
	def RSA_PUBLIC 1;
	def RSA_PRIVATE 0;
	def RSA_SIGN_SHA1 1;
	def TRUE 1;
	def FALSE 0;
	def NULL 0;
	def DUMP_HEX 2;

	fun exit(msg)
		print msg;
		bltExit();
	endfun

	fun read_rsa_key(file, is_public, password = '')
		.........................  // 省略中间代码，读取密钥key的代码可以参考opensslReadKey模块函数的示例代码
	endfun

	fun print_header()
		print '\n=======================================\n';
	endfun

	fun sign_verify(str, p_key, verify_str, key, print_sign = TRUE, sign_type = RSA_SIGN_SHA1)
		if(print_sign)
			print_header();
		endif

		ret = opensslSign(str, -1, p_key, &sign, &sign_len, sign_type);
		if(!ret)
			exit('sign failed: ' + opensslGetError());
		endif

		if(print_sign)
			print 'sign len: ' + sign_len;
			print 'sign data: ' + bltDumpPtrData(sign, sign_len, DUMP_HEX);
		endif

		ret = opensslVerify(verify_str, -1, key, sign, sign_len, sign_type);
		print verify_str + ' - verify :' + (ret ? 'True' : 'False');

		bltFree(sign);
	endfun

	key = read_rsa_key('rsa_public.key', RSA_PUBLIC);
	p_key = read_rsa_key('rsa_private.key', RSA_PRIVATE);
	p_aes_key = read_rsa_key('rsa_aes_private.key', RSA_PRIVATE, '111111');

	sign_str = "hello world test sign!";
	sign_verify(sign_str, p_key, "hello world test sign!", key);
	sign_verify(sign_str, p_key, "hello world!", key, FALSE);

	上面的代码片段中的sign_verify脚本函数，是用于测试RSA签名和验证签名数据的函数，在该脚本函数里，会先通过opensslSign模块函数生成签名数据，
	再通过opensslVerify模块函数来验证签名数据

	该测试代码的执行结果类似如下所示：

	rsa_public.key file size: 451
	key:20127712
	rsa_private.key file size: 1679
	key:20129488
	rsa_aes_private.key file size: 1766
	key:20023904

	=======================================

	sign len: 256
	sign data: 90 6C CA F0 94 EA D9 FA 84 13 64 89 C1 EA A6 03 3C 27 DB 39 0D 6A A6 92 C6 DC 9E 74 77 .................................
	hello world test sign! - verify :True
	hello world! - verify :False

	从执行结果中可以看到，hello world test sign!通过了签名验证，而hello world!则没有通过签名验证
 */
static void common_sign_verify(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount, const char * func_name,
		ZL_EXP_BOOL is_sign)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 5) {
		if(is_sign)
			zenglApi_Exit(VM_ARG,"usage: %s(data, data_len, private_key, &sigret, &siglen[, type = 0[, use_evp = 0]]): integer", func_name);
		else
			zenglApi_Exit(VM_ARG,"usage: %s(data, data_len, public_key, sigbuf, siglen[, type = 0[, use_evp = 0]]): integer", func_name);
	}
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
	if(is_sign) {
		if(mod_openssl_rsa->is_public_key) {
			zenglApi_Exit(VM_ARG,"%s runtime error: the key is not a private key", func_name);
		}
	}
	else {
		if(!mod_openssl_rsa->is_public_key) {
			zenglApi_Exit(VM_ARG,"%s runtime error: the key is not a public key", func_name);
		}
	}
	RSA * rsa = mod_openssl_rsa->rsa;
	EVP_PKEY * evp_key = mod_openssl_rsa->evp_key;
	if(is_sign) {
		detect_arg_is_address_type(VM_ARG, 4, &arg, "fourth", "sigret", func_name);
		detect_arg_is_address_type(VM_ARG, 5, &arg, "fifth", "siglen", func_name);
	}
	int sign_types[MODULE_OPENSSL_SIGN_TYPE] = {
		MOD_OPENSSL_NID_sha,                       // 索引: 0
		MOD_OPENSSL_NID_sha1,                      // 索引: 1
		MOD_OPENSSL_NID_ripemd160,                 // 索引: 2
		MOD_OPENSSL_NID_md5,                       // 索引: 3
		MOD_OPENSSL_NID_md5_sha1,                  // 索引: 4
		MOD_OPENSSL_NID_sha256,                    // 索引: 5
		MOD_OPENSSL_NID_sha256WithRSAEncryption,   // 索引: 6
		MOD_OPENSSL_NID_sha512,                    // 索引: 7
		MOD_OPENSSL_NID_sha512WithRSAEncryption    // 索引: 8
	};
	int sign_type_idx = 0;
	int sign_type = sign_types[sign_type_idx];
	ZL_EXP_BOOL use_evp = ZL_EXP_FALSE;
	EVP_MD * mdtype = NULL;
	if(argcount > 5) {
		zenglApi_GetFunArg(VM_ARG,6,&arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the sixth argument [type] of %s must be integer", func_name);
		}
		sign_type_idx = (int)arg.val.integer;
		if(sign_type_idx < 0 || sign_type_idx >= MODULE_OPENSSL_SIGN_TYPE) {
			zenglApi_Exit(VM_ARG,"the sixth argument [type] of %s is invalid, must be in [0, %d)", func_name, MODULE_OPENSSL_SIGN_TYPE);
		}
		sign_type = sign_types[sign_type_idx];
		if(argcount > 6) {
			zenglApi_GetFunArg(VM_ARG,7,&arg);
			if(arg.type != ZL_EXP_FAT_INT) {
				zenglApi_Exit(VM_ARG,"the seventh argument [use_evp] of %s must be integer", func_name);
			}
			int arg_use_evp = (int)arg.val.integer;
			use_evp = (arg_use_evp == 0) ? ZL_EXP_FALSE : ZL_EXP_TRUE;
		}
		if(use_evp) {
			mdtype = st_get_evp_md_from_algo(sign_type);
			if(mdtype == NULL) {
				zenglApi_Exit(VM_ARG,"the sixth argument [type] of %s is not supported when use evp", func_name, MODULE_OPENSSL_SIGN_TYPE);
			}
		}
	}
	if(sign_type == -1) {
		zenglApi_Exit(VM_ARG,"the sixth argument [type:%d] of %s is not supported", sign_type_idx, func_name);
	}
	if(is_sign) {
		int rsa_len = 0;
		if(use_evp)
			rsa_len = EVP_PKEY_size(evp_key);
		else
			rsa_len = RSA_size(rsa);
		unsigned char * sigret = (unsigned char *)zenglApi_AllocMem(VM_ARG, rsa_len);
		memset(sigret, 0, rsa_len);
		unsigned int siglen = 0;
		EVP_MD_CTX * md_ctx = NULL;
		int retval = 0;
		if(use_evp) {
			md_ctx = EVP_MD_CTX_create();
			if (md_ctx != NULL &&
						EVP_SignInit(md_ctx, mdtype) &&
						EVP_SignUpdate(md_ctx, data, data_len) &&
						EVP_SignFinal(md_ctx, sigret, &siglen, evp_key)) {
				retval = 1;
			}
			if(md_ctx != NULL) {
				EVP_MD_CTX_destroy(md_ctx);
			}
		} else {
			retval = RSA_sign(sign_type, data, data_len, sigret, &siglen, rsa);
		}
		if(!retval) {
			zenglApi_FreeMem(VM_ARG, sigret);
			set_arg_value(VM_ARG, 4, ZL_EXP_FAT_INT, NULL, 0);
			set_arg_value(VM_ARG, 5, ZL_EXP_FAT_INT, NULL, 0);
			zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		}
		else {
			set_arg_value(VM_ARG, 4, ZL_EXP_FAT_INT, NULL, (ZL_EXP_LONG)sigret);
			set_arg_value(VM_ARG, 5, ZL_EXP_FAT_INT, NULL, (ZL_EXP_LONG)siglen);
			int ret_set_ptr = pointer_list_set_member(&(my_data->pointer_list), sigret, siglen, module_openssl_free_ptr_callback);
			if(ret_set_ptr != 0) {
				zenglApi_Exit(VM_ARG, "%s add pointer to pointer_list failed, pointer_list_set_member error code:%d", func_name, ret_set_ptr);
			}
			zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 1, 0);
		}
	}
	else {
		zenglApi_GetFunArg(VM_ARG,4,&arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the fourth argument [sigbuf] of %s must be integer", func_name);
		}
		unsigned char * sigbuf = (unsigned char *)arg.val.integer;
		int sigbuf_ptr_idx = pointer_list_get_ptr_idx(&(my_data->pointer_list), sigbuf);
		if(sigbuf_ptr_idx < 0) {
			zenglApi_Exit(VM_ARG,"runtime error: the fourth argument [sigbuf] of %s is invalid pointer", func_name);
		}
		int sigbuf_ptr_size = my_data->pointer_list.list[sigbuf_ptr_idx].ptr_size;
		zenglApi_GetFunArg(VM_ARG,5,&arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the fifth argument [siglen] of %s must be integer", func_name);
		}
		unsigned int siglen = (unsigned int)arg.val.integer;
		if(sigbuf_ptr_size > 0 && siglen > sigbuf_ptr_size) {
			siglen = sigbuf_ptr_size;
		}
		if(use_evp) {
			EVP_MD_CTX * md_ctx = NULL;
			int err = -1;
			md_ctx = EVP_MD_CTX_create();
			if (md_ctx != NULL &&
					EVP_VerifyInit (md_ctx, mdtype) &&
					EVP_VerifyUpdate (md_ctx, data, data_len)) {
				err = EVP_VerifyFinal(md_ctx, sigbuf, siglen, evp_key);
			}
			if(md_ctx != NULL) {
				EVP_MD_CTX_destroy(md_ctx);
			}
			zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, err, 0);
		} else {
			int retval = RSA_verify(sign_type, data, data_len, sigbuf, siglen, rsa);
			if(!retval) {
				zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
			}
			else {
				zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 1, 0);
			}
		}
	}
}

/**
 * opensslSign模块函数，用于生成RSA签名数据，和此模块函数相关的详细说明请参考 common_sign_verify 函数的注释
 *
 * 模块函数版本历史：
 *  - v0.20.0版本新增此模块函数
 *  - v0.22.0版本增加了use_evp的可选参数
 */
ZL_EXP_VOID module_openssl_sign(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	common_sign_verify(VM_ARG, argcount, "opensslSign", ZL_EXP_TRUE);
}

/**
 * opensslVerify模块函数，用于验证RSA签名数据，和此模块函数相关的详细说明请参考 common_sign_verify 函数的注释
 *
 * 模块函数版本历史：
 *  - v0.20.0版本新增此模块函数
 *  - v0.22.0版本增加了use_evp的可选参数
 */
ZL_EXP_VOID module_openssl_verify(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	common_sign_verify(VM_ARG, argcount, "opensslVerify", ZL_EXP_FALSE);
}

/**
 * opensslPublicEncrypt模块函数，用于执行公钥加密操作，和此模块函数相关的详细说明请参考 common_encrypt_decrypt 函数的注释
 *
 * 模块函数版本历史：
 *  - v0.20.0版本新增此模块函数
 */
ZL_EXP_VOID module_openssl_public_encrypt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	common_encrypt_decrypt(VM_ARG, argcount, "opensslPublicEncrypt", ZL_EXP_TRUE, ZL_EXP_TRUE);
}

/**
 * opensslPrivateDecrypt模块函数，用于执行私钥解密操作，和此模块函数相关的详细说明请参考 common_encrypt_decrypt 函数的注释
 *
 * 模块函数版本历史：
 *  - v0.20.0版本新增此模块函数
 */
ZL_EXP_VOID module_openssl_private_decrypt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	common_encrypt_decrypt(VM_ARG, argcount, "opensslPrivateDecrypt", ZL_EXP_FALSE, ZL_EXP_FALSE);
}

/**
 * opensslPrivateEncrypt模块函数，用于执行私钥加密操作，和此模块函数相关的详细说明请参考 common_encrypt_decrypt 函数的注释
 *
 * 模块函数版本历史：
 *  - v0.20.0版本新增此模块函数
 */
ZL_EXP_VOID module_openssl_private_encrypt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	common_encrypt_decrypt(VM_ARG, argcount, "opensslPrivateEncrypt", ZL_EXP_FALSE, ZL_EXP_TRUE);
}

/**
 * opensslPublicDecrypt模块函数，用于执行公钥解密操作，和此模块函数相关的详细说明请参考 common_encrypt_decrypt 函数的注释
 *
 * 模块函数版本历史：
 *  - v0.20.0版本新增此模块函数
 */
ZL_EXP_VOID module_openssl_public_decrypt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	common_encrypt_decrypt(VM_ARG, argcount, "opensslPublicDecrypt", ZL_EXP_TRUE, ZL_EXP_FALSE);
}

/**
 * opensslFreeKey模块函数，用于释放opensslReadKey返回的密钥key
 * 该模块函数的参数是可变参数，用法：opensslFreeKey(key1, key2, key3......)
 * 每个参数都必须是有效的密钥key
 *
 * 例如：
	use builtin,openssl;
	def RSA_PUBLIC 1;
	def RSA_PRIVATE 0;

	.................................. // 省略中间代码

	key = read_rsa_key('rsa_public.key', RSA_PUBLIC);
	p_key = read_rsa_key('rsa_private.key', RSA_PRIVATE);
	p_aes_key = read_rsa_key('rsa_aes_private.key', RSA_PRIVATE, '111111');

	.................................. // 省略中间代码

	opensslFreeKey(key, p_key, p_aes_key);

	上面在用完key，p_key等密钥key后，就通过opensslFreeKey将这些密钥key给释放掉了，释放掉的密钥不能再用于加密解密，签名验签等操作，
	如果释放后，还继续使用这些key的话，加密解密等模块函数会反馈相应的错误

	模块函数版本历史：
	- v0.20.0版本新增此模块函数
 */
ZL_EXP_VOID module_openssl_free_key(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	const char * func_name = "opensslFreeKey";
	if(argcount < 1) {
		zenglApi_Exit(VM_ARG,"usage: %s(key...): integer", func_name);
	}
	int i;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	for(i = 1; i <= argcount; i++) {
		zenglApi_GetFunArg(VM_ARG,i,&arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the %d argument of %s must be integer", i, func_name);
		}
		MODULE_OPENSSL_RSA_KEY * mod_openssl_rsa = (MODULE_OPENSSL_RSA_KEY *)arg.val.integer;
		if(!is_valid_rsa_key(&(my_data->resource_list), mod_openssl_rsa)) {
			zenglApi_Exit(VM_ARG,"runtime error: the %d argument of %s is invalid key", i, func_name);
		}
		module_openssl_free_rsa_resource_callback(VM_ARG, mod_openssl_rsa);
		int ret_code = resource_list_remove_member(&(my_data->resource_list), mod_openssl_rsa); // 将释放掉的实例指针从资源列表中移除
		if(ret_code != 0) {
			zenglApi_Exit(VM_ARG, "%s remove resource from resource_list failed [the %d argument], resource_list_remove_member error code:%d",
					func_name, i, ret_code);
		}
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, i, 0);
}

/**
 * openssl模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄(对应的C函数)
 */
ZL_EXP_VOID module_openssl_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslGetError",module_openssl_get_error);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslReadKey",module_openssl_read_key);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslPublicEncrypt",module_openssl_public_encrypt);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslPrivateDecrypt",module_openssl_private_decrypt);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslPrivateEncrypt",module_openssl_private_encrypt);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslPublicDecrypt",module_openssl_public_decrypt);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslSign",module_openssl_sign);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslVerify",module_openssl_verify);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"opensslFreeKey",module_openssl_free_key);
}
