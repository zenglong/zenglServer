/*
 * module_mysql.c
 *
 *  Created on: 2017-9-26
 *      Author: zengl
 */

#include "main.h"
#include "module_mysql.h"
#include <mysql.h>
#include <stdlib.h>
#include <string.h>

#define MODULE_MYSQL_RES_SIGNER 0x54555352 // RSUT签名，从低字节到高字节，ASCII码

/**
 * 自定义的结构体，除了官方的MYSQL_RES指针外，
 * 还将结果中包含的字段数存储在num_fields中，这样就不用在每次提取一行数据时，都重复执行一次查询字段数的操作，
 * signer成员用于存储有效的签名，在对mysql_res进行相关操作之前，会先校验signer是否是有效的签名
 */
typedef struct _MODULE_MYSQL_RES {
	MYSQL_RES * mysql_res;
	int num_fields;
	unsigned int signer;
} MODULE_MYSQL_RES;

/**
 * 在zengl脚本退出之前，会自动通过下面的回调函数，
 * 将所有未关闭的数据库连接都关闭掉
 */
static void module_mysql_free_connection_resource_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	MYSQL *con = (MYSQL *)ptr;
	mysql_close(con);
}

/**
 * 在zengl脚本退出之前，会自动通过下面的回调函数，
 * 将所有未释放掉的和结果集相关的数据库资源都释放掉
 */
static void module_mysql_free_result_resource_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	MODULE_MYSQL_RES * result = (MODULE_MYSQL_RES *)ptr;
	mysql_free_result(result->mysql_res);
	zenglApi_FreeMem(VM_ARG, result);
}

/**
 * 判断指针con对应的连接，是否是有效的mysql连接
 */
static ZL_EXP_BOOL is_valid_mysql_connection(RESOURCE_LIST * resource_list, void * con)
{
	int ret = resource_list_get_ptr_idx(resource_list, con, module_mysql_free_connection_resource_callback);
	if(ret >= 0)
		return ZL_EXP_TRUE;
	else
		return ZL_EXP_FALSE;
}

/**
 * 判断指针res对应的结果集，是否是有效的mysql结果集
 */
static ZL_EXP_BOOL is_valid_mysql_result(RESOURCE_LIST * resource_list, void * res)
{
	int ret = resource_list_get_ptr_idx(resource_list, res, module_mysql_free_result_resource_callback);
	if(ret >= 0)
		return ZL_EXP_TRUE;
	else
		return ZL_EXP_FALSE;
}

/**
 * mysqlGetClientInfo模块函数对应的C函数
 * 通过mysql_get_client_info的官方库函数，来返回mysql客户端库的版本信息
 */
ZL_EXP_VOID module_mysql_get_client_info(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, (char *)mysql_get_client_info(), 0, 0);
}

/**
 * mysqlGetServerVersion模块函数对应的C函数
 * 通过mysql_get_server_version官方库函数，获取服务端的版本号信息，
 * 主版本，子版本，修正版本号会依次存储在返回数组的前三个成员中
 */
ZL_EXP_VOID module_mysql_get_server_version(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 1)
		zenglApi_Exit(VM_ARG,"usage: mysqlGetServerVersion(connection)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [connection] of mysqlGetServerVersion must be integer");
	}
	MYSQL *con = (MYSQL *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_mysql_connection(&(my_data->resource_list), con)) {
		zenglApi_Exit(VM_ARG,"mysqlGetServerVersion runtime error: invalid connection");
	}
	unsigned long server_version = mysql_get_server_version(con);
	long major_version = (long)(server_version / 10000);
	long minor_version = (long)((server_version % 10000) / 100);
	long patch_version = (long)(server_version % 100);
	ZENGL_EXPORT_MEMBLOCK memblock = {0};
	if(zenglApi_CreateMemBlock(VM_ARG,&memblock,0) == -1) {
		zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
	}
	arg.type = ZL_EXP_FAT_INT;
	arg.val.integer = major_version;
	zenglApi_SetMemBlock(VM_ARG,&memblock,1,&arg);
	arg.val.integer = minor_version;
	zenglApi_SetMemBlock(VM_ARG,&memblock,2,&arg);
	arg.val.integer = patch_version;
	zenglApi_SetMemBlock(VM_ARG,&memblock,3,&arg);
	zenglApi_SetRetValAsMemBlock(VM_ARG,&memblock);
}

/**
 * mysqlInit模块函数对应的C函数
 * 通过mysql_init的官方库函数，初始化一个MYSQL结构体的connection连接指针，后续的各种数据库操作，包括连接数据库，查询数据库等操作都需要传递该指针，
 * 并通过resource_list_set_member函数将指针存储到资源列表中，如果该指针在脚本中没有被手动关闭的话，
 * 最后，会通过module_mysql_free_connection_resource_callback回调函数将指针自动关闭掉
 */
ZL_EXP_VOID module_mysql_Init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	MYSQL * con = mysql_init(NULL);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)con, 0);
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int ret_code = resource_list_set_member(&(my_data->resource_list), con, module_mysql_free_connection_resource_callback);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "mysqlInit add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
	}
}

/**
 * mysqlRealConnect模块函数对应的C函数
 * 通过mysql_real_connect官方库函数，连接mysql数据库，
 * 需要将mysqlInit初始化的连接指针，以及主机名(或IP地址)，用户名，密码，数据库名，端口号作为参数传递给它，最后两个参数是可选的
 */
ZL_EXP_VOID module_mysql_real_connect(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 4)
		zenglApi_Exit(VM_ARG,"usage: mysqlRealConnect(connection, host, username, password[, select_db][, port])");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [connection] of mysqlRealConnect must be integer");
	}
	MYSQL *con = (MYSQL *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_mysql_connection(&(my_data->resource_list), con)) {
		zenglApi_Exit(VM_ARG,"mysqlRealConnect runtime error: invalid connection");
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [host] of mysqlRealConnect must be string");
	}
	char * host = arg.val.str;
	zenglApi_GetFunArg(VM_ARG,3,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the third argument [username] of mysqlRealConnect must be string");
	}
	char * username = arg.val.str;
	zenglApi_GetFunArg(VM_ARG,4,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the fourth argument [password] of mysqlRealConnect must be string");
	}
	char * password = arg.val.str;
	char * select_db = NULL;
	if(argcount >= 5) {
		zenglApi_GetFunArg(VM_ARG,5,&arg);
		if(arg.type == ZL_EXP_FAT_INT) {
			select_db = (char *)arg.val.integer;
		}
		else if(arg.type == ZL_EXP_FAT_STR) {
			select_db = arg.val.str;
		}
	}
	unsigned int port = 0;
	if(argcount >= 6) {
		zenglApi_GetFunArg(VM_ARG,6,&arg);
		if(arg.type == ZL_EXP_FAT_INT) {
			port = (unsigned int)arg.val.integer;
		}
	}
	MYSQL * retval = mysql_real_connect(con, host, username, password, select_db, port, NULL, 0);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)retval, 0);
}

/**
 * mysqlSetCharacterSet模块函数对应的C函数
 * 通过mysql_set_character_set官方库函数，设置当前连接默认的字符集
 */
ZL_EXP_VOID module_mysql_set_character_set(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 2)
		zenglApi_Exit(VM_ARG,"usage: mysqlSetCharacterSet(connection, charset_name)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [connection] of mysqlSetCharacterSet must be integer");
	}
	MYSQL *con = (MYSQL *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_mysql_connection(&(my_data->resource_list), con)) {
		zenglApi_Exit(VM_ARG,"mysqlSetCharacterSet runtime error: invalid connection");
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [charset_name] of mysqlSetCharacterSet must be string");
	}
	char * charset_name = arg.val.str;
	int retval = mysql_set_character_set(con, (const char *)charset_name);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)retval, 0);
}

/**
 * mysqlCharacterSetName模块函数对应的C函数
 * 通过mysql_character_set_name官方库函数，返回当前连接的默认字符集名称
 */
ZL_EXP_VOID module_mysql_character_set_name(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 1)
		zenglApi_Exit(VM_ARG,"usage: mysqlCharacterSetName(connection)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [connection] of mysqlCharacterSetName must be integer");
	}
	MYSQL *con = (MYSQL *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_mysql_connection(&(my_data->resource_list), con)) {
		zenglApi_Exit(VM_ARG,"mysqlCharacterSetName runtime error: invalid connection");
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, (char *)mysql_character_set_name(con), 0, 0);
}

/**
 * mysqlRealEscapeString模块函数对应的C函数
 * 通过mysql_real_escape_string官方库函数，将字符串进行安全转义，使其能够用于sql语句中
 */
ZL_EXP_VOID module_mysql_real_escape_string(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 2)
		zenglApi_Exit(VM_ARG,"usage: mysqlRealEscapeString(connection, source_string)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [connection] of mysqlRealEscapeString must be integer");
	}
	MYSQL *con = (MYSQL *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_mysql_connection(&(my_data->resource_list), con)) {
		zenglApi_Exit(VM_ARG,"mysqlRealEscapeString runtime error: invalid connection");
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [source_string] of mysqlRealEscapeString must be string");
	}
	char * source_string = arg.val.str;
	int source_length = strlen(source_string);
	int to_length = source_length * 2 + 1;
	char * to_string = (char *)zenglApi_AllocMem(VM_ARG, to_length);
	unsigned long retval = mysql_real_escape_string(con, to_string, (const char *)source_string, (unsigned long)source_length);
	if(retval == ((unsigned long) - 1)) {
		zenglApi_Exit(VM_ARG, "mysqlRealEscapeString failed: %s", (char *)mysql_error(con));
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, to_string, 0, 0);
	zenglApi_FreeMem(VM_ARG, to_string);
}

/**
 * mysqlError模块函数对应的C函数
 * 通过mysql_error官方库函数，将最近一次调用mysql api接口时发生的错误信息返回
 */
ZL_EXP_VOID module_mysql_error(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 1)
		zenglApi_Exit(VM_ARG,"usage: mysqlError(connection)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [connection] of mysqlError must be integer");
	}
	MYSQL *con = (MYSQL *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_mysql_connection(&(my_data->resource_list), con)) {
		zenglApi_Exit(VM_ARG,"mysqlError runtime error: invalid connection");
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, (char *)mysql_error(con), 0, 0);
}

/**
 * mysqlQuery模块函数对应的C函数
 * 通过mysql_query官方库函数，执行具体的sql语句
 */
ZL_EXP_VOID module_mysql_query(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 2)
		zenglApi_Exit(VM_ARG,"usage: mysqlQuery(connection, statement)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [connection] of mysqlQuery must be integer");
	}
	MYSQL *con = (MYSQL *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_mysql_connection(&(my_data->resource_list), con)) {
		zenglApi_Exit(VM_ARG,"mysqlQuery runtime error: invalid connection");
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [statement] of mysqlQuery must be string");
	}
	char * statement = arg.val.str;
	int retval = mysql_query(con, (const char *)statement);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, retval, 0);
}

/**
 * mysqlClose模块函数对应的C函数
 * 通过mysql_close的官方库函数，关闭数据库连接
 * 并通过resource_list_remove_member函数将连接指针从资源列表中移除，以防止脚本结束时，自动对该连接指针再次执行关闭操作
 */
ZL_EXP_VOID module_mysql_close(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 1)
		zenglApi_Exit(VM_ARG,"usage: mysqlClose(connection)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [connection] of mysqlClose must be integer");
	}
	MYSQL *con = (MYSQL *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_mysql_connection(&(my_data->resource_list), con)) {
		zenglApi_Exit(VM_ARG,"mysqlClose runtime error: invalid connection");
	}
	mysql_close(con);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
	int ret_code = resource_list_remove_member(&(my_data->resource_list), con);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "mysqlClose remove resource from resource_list failed, resource_list_remove_member error code:%d", ret_code);
	}
}

/**
 * mysqlStoreResult模块函数对应的C函数
 * 通过mysql_store_result官方库函数，存储查询结果，同时通过mysql_num_fields库函数，保存结果集中的字段数
 * 并通过resource_list_set_member函数，将结果指针存储到资源列表中，如果该结果指针没有在zengl脚本中被手动释放掉的话，
 * 在脚本结束时，会自动通过module_mysql_free_result_resource_callback回调函数将结果指针给释放掉
 */
ZL_EXP_VOID module_mysql_store_result(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 1)
		zenglApi_Exit(VM_ARG,"usage: mysqlStoreResult(connection)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [connection] of mysqlStoreResult must be integer");
	}
	MYSQL *con = (MYSQL *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_mysql_connection(&(my_data->resource_list), con)) {
		zenglApi_Exit(VM_ARG,"mysqlStoreResult runtime error: invalid connection");
	}
	MYSQL_RES * res = mysql_store_result(con);
	MODULE_MYSQL_RES * result = zenglApi_AllocMem(VM_ARG, sizeof(MODULE_MYSQL_RES));
	result->mysql_res = res;
	result->num_fields = (int)mysql_num_fields(res);
	result->signer = MODULE_MYSQL_RES_SIGNER;
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)result, 0);
	int ret_code = resource_list_set_member(&(my_data->resource_list), result, module_mysql_free_result_resource_callback);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "mysqlStoreResult add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
	}
}

/**
 * mysqlFreeResult模块函数对应的C函数
 * 通过mysql_free_result官方库函数，将结果指针中的mysql_res给释放掉，再通过zenglApi_FreeMem接口将结果指针释放掉
 * 最后通过resource_list_remove_member函数，将结果指针从资源列表中移除
 */
ZL_EXP_VOID module_mysql_free_result(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 1)
		zenglApi_Exit(VM_ARG,"usage: mysqlFreeResult(result)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [result] of mysqlFreeResult must be integer");
	}
	MODULE_MYSQL_RES * result = (MODULE_MYSQL_RES *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_mysql_result(&(my_data->resource_list), result)) {
		zenglApi_Exit(VM_ARG,"mysqlFreeResult runtime error: invalid result");
	}
	if(result->signer != MODULE_MYSQL_RES_SIGNER) {
		zenglApi_Exit(VM_ARG,"the first argument [result] of mysqlFreeResult is invalid");
	}
	mysql_free_result(result->mysql_res);
	zenglApi_FreeMem(VM_ARG, result);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
	int ret_code = resource_list_remove_member(&(my_data->resource_list), result);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "mysqlFreeResult remove resource from resource_list failed, resource_list_remove_member error code:%d", ret_code);
	}
}

/**
 * mysqlFetchResultRow模块函数对应的C函数
 * 通过mysql_fetch_row官方库函数，将结果集中当前行游标对应的一行数据读取出来，
 * 同时通过mysql_fetch_field库函数，将每个字段的信息读取出来，
 * 从而根据字段名和行数据，构成一个名值对组成的哈希数组，并将该数组作为结果返回
 * 在读取行数据时，会根据每个字段的类型，对数据进行类型转换，例如，某个字段是整数类型，那么该字段对应的数据就会被转为整数类型，再存储到哈希数组中
 */
ZL_EXP_VOID module_mysql_fetch_result_row(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 2)
		zenglApi_Exit(VM_ARG,"usage: mysqlFetchResultRow(result, &result_array)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [result] of mysqlFetchResultRow must be integer");
	}
	MODULE_MYSQL_RES * result = (MODULE_MYSQL_RES *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_mysql_result(&(my_data->resource_list), result)) {
		zenglApi_Exit(VM_ARG,"mysqlFetchResultRow runtime error: invalid result");
	}
	if(result->signer != MODULE_MYSQL_RES_SIGNER) {
		zenglApi_Exit(VM_ARG,"the first argument [result] of mysqlFetchResultRow is invalid");
	}
	MYSQL_ROW row;
	MYSQL_FIELD * field;
	MYSQL_RES * mysql_res = result->mysql_res;
	if ((row = mysql_fetch_row(mysql_res)))
	{
		int num_fields = result->num_fields;
		if(num_fields > 0) {
			mysql_field_seek(mysql_res,0);
		}
		ZENGL_EXPORT_MEMBLOCK memblock = {0};
		if(zenglApi_CreateMemBlock(VM_ARG,&memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
		for(int i = 0; i < num_fields; i++)
		{
			field = mysql_fetch_field(mysql_res);
			if(row[i])
			{
				switch(field->type)
				{
				case MYSQL_TYPE_TINY:
				case MYSQL_TYPE_SHORT:
				case MYSQL_TYPE_INT24:
				case MYSQL_TYPE_LONG:
				case MYSQL_TYPE_YEAR:
					arg.type = ZL_EXP_FAT_INT;
					arg.val.integer = atol(row[i]);
					zenglApi_SetMemBlockByHashKey(VM_ARG, &memblock, field->name, &arg);
					break;
				case MYSQL_TYPE_FLOAT:
				case MYSQL_TYPE_DOUBLE:
				case MYSQL_TYPE_DECIMAL:
					arg.type = ZL_EXP_FAT_FLOAT;
					arg.val.floatnum = atof(row[i]);
					zenglApi_SetMemBlockByHashKey(VM_ARG, &memblock, field->name, &arg);
					break;
				default:
					arg.type = ZL_EXP_FAT_STR;
					arg.val.str = row[i];
					zenglApi_SetMemBlockByHashKey(VM_ARG, &memblock, field->name, &arg);
					break;
				}
			}
			else
			{
				arg.type = ZL_EXP_FAT_NONE;
				zenglApi_SetMemBlockByHashKey(VM_ARG, &memblock, field->name, &arg);
			}
		}
		zenglApi_GetFunArgInfo(VM_ARG,2,&arg);
		switch(arg.type){
		case ZL_EXP_FAT_ADDR:
		case ZL_EXP_FAT_ADDR_LOC:
		case ZL_EXP_FAT_ADDR_MEMBLK:
			break;
		default:
			zenglApi_Exit(VM_ARG,"the second argument [&result_array] of mysqlFetchResultRow must be address type");
			break;
		}
		arg.type = ZL_EXP_FAT_MEMBLOCK;
		arg.val.memblock = memblock;
		zenglApi_SetFunArg(VM_ARG,2,&arg);
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 1, 0);
	}
	else
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
}

/**
 * mysql模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄(对应的C函数)
 */
ZL_EXP_VOID module_mysql_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlGetClientInfo",module_mysql_get_client_info);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlGetServerVersion",module_mysql_get_server_version);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlInit",module_mysql_Init);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlRealConnect",module_mysql_real_connect);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlError",module_mysql_error);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlQuery",module_mysql_query);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlClose",module_mysql_close);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlSetCharacterSet",module_mysql_set_character_set);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlCharacterSetName",module_mysql_character_set_name);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlRealEscapeString",module_mysql_real_escape_string);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlStoreResult",module_mysql_store_result);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlFreeResult",module_mysql_free_result);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"mysqlFetchResultRow",module_mysql_fetch_result_row);
}
