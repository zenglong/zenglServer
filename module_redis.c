/*
 * module_redis.c
 *
 *  Created on: Feb 22, 2020
 *      Author: zengl
 */

#include "main.h"
#include "module_redis.h"
#include <hiredis.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

/**
 * 在zengl脚本退出之前，会自动通过下面的回调函数，
 * 将所有未释放的redis连接资源都释放掉
 */
static void module_redis_free_context_resource_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	redisContext * context = (redisContext *)ptr;
	redisFree(context);
}

/**
 * 判断context对应的连接，是否是有效的redis连接
 */
static ZL_EXP_BOOL is_valid_redis_context(RESOURCE_LIST * resource_list, void * context)
{
	int ret = resource_list_get_ptr_idx(resource_list, context, module_redis_free_context_resource_callback);
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
 * 将zengl数组转换为C语言字符串数组argv，然后就可以调用redisCommandArgv库函数来发送redis命令了，
 * 例如：bltArray('hset', 'hash2', 'testname', 'say "hello world!"')
 * 转为argv字符串数组后，再调用redisCommandArgv，就可以发送 hset hash2 testname "say \"hello world!\"" 命令给redis
 */
static redisReply * st_redis_set_command_by_array(ZL_EXP_VOID * VM_ARG, redisContext * context,
		ZENGL_EXPORT_MEMBLOCK memblock, ZL_EXP_INT * memblock_count)
{
	ZL_EXP_INT size,count,process_count,i,j;
	ZENGL_EXPORT_MOD_FUN_ARG mblk_val = {ZL_EXP_FAT_NONE,{0}};
	zenglApi_GetMemBlockInfo(VM_ARG,&memblock,&size,ZL_EXP_NULL);
	count = zenglApi_GetMemBlockNNCount(VM_ARG, &memblock);
	(*memblock_count) = count;
	if(count <= 0) {
		return NULL;
	}
	char ** argv = (char **)zenglApi_AllocMem(VM_ARG, sizeof(char *) * count);
	for(i = 0; i < count; i++) {
		argv[i] = NULL;
	}
	for(i=1,process_count=0; i<=size && process_count < count; i++) {
		char tmp[150] = {0};
		mblk_val = zenglApi_GetMemBlock(VM_ARG,&memblock,i);
		switch(mblk_val.type)
		{
		case ZL_EXP_FAT_INT:
		case ZL_EXP_FAT_FLOAT:
		case ZL_EXP_FAT_STR:
			process_count++;
			break;
		}
		switch(mblk_val.type)
		{
		case ZL_EXP_FAT_INT:
			snprintf(tmp, 150, "%ld", mblk_val.val.integer);
			argv[process_count - 1] = zenglApi_AllocMemForString(VM_ARG, tmp);
			break;
		case ZL_EXP_FAT_FLOAT:
			snprintf(tmp, 150, "%.16g", mblk_val.val.floatnum);
			argv[process_count - 1] = zenglApi_AllocMemForString(VM_ARG, tmp);
			break;
		case ZL_EXP_FAT_STR:
			argv[process_count - 1] = zenglApi_AllocMemForString(VM_ARG, mblk_val.val.str);
			break;
		}
	}
	(*memblock_count) = process_count;
	if(process_count > 0) {
		redisReply * retval = redisCommandArgv(context, process_count, (const char **)argv, NULL);
		for(i = 0; i < count; i++) {
			if(argv[i] != NULL) {
				zenglApi_FreeMem(VM_ARG, argv[i]);
			}
		}
		zenglApi_FreeMem(VM_ARG, argv);
		return retval;
	}
	else {
		zenglApi_FreeMem(VM_ARG, argv);
		return NULL;
	}
}

/**
 * redisConnect模块函数，根据指定的ip地址，端口号等参数连接对应的redis服务器
 * 第一个参数ip表示需要连接的redis服务器所在的ip地址或者主机名
 * 第二个参数port表示需要连接的redis服务器的端口号
 * 第三个参数context必须是引用类型，用于存储redis连接相关的上下文指针，通过该指针可以向redis服务器发送命令等
 * 第四个参数error是可选参数，也必须是引用类型，当连接发生错误时，会将错误信息存储到该参数中
 * 第五个参数timeout也是可选参数，表示连接超时时间，以秒为单位
 * 如果该模块函数连接成功，会返回1，连接失败则返回0，并将连接失败的原因存储到第四个error参数中
 *
 * 例如：
 * use builtin, redis;
 *
 * fun exit(error)
		print error;
		bltExit();
   endfun

   if(!redisConnect("127.0.0.1", 6379, &con, &error, 30))
		exit(error);
   endif

   上面这段代码会尝试连接ip地址为127.0.0.1，端口为6379的redis服务器，并设置了30秒的连接超时时间
   如果连接成功，则会将连接相关的上下文指针存储到con变量，如果连接失败，则会将错误信息存储到error变量
 */
ZL_EXP_VOID module_redis_connect(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 3)
		zenglApi_Exit(VM_ARG,"usage: redisConnect(ip, port, &context[, &error[, timeout]])");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [ip] of redisConnect must be string");
	}
	char * ip = arg.val.str;
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	int port = 0;
	if(arg.type == ZL_EXP_FAT_INT) {
		port = (unsigned int)arg.val.integer;
	}
	else {
		zenglApi_Exit(VM_ARG,"the second argument [port] of redisConnect must be integer");
	}
	time_t timeout = 0;
	detect_arg_is_address_type(VM_ARG, 3, &arg, "third", "context", "redisConnect");
	if(argcount > 3) {
		detect_arg_is_address_type(VM_ARG, 4, &arg, "fourth", "error", "redisConnect");
		if(argcount > 4) {
			zenglApi_GetFunArg(VM_ARG,5,&arg);
			if(arg.type != ZL_EXP_FAT_INT) {
				zenglApi_Exit(VM_ARG,"the fifth argument [timeout] of redisConnect must be integer");
			}
			timeout = (time_t)arg.val.integer;
		}
	}
	redisContext * context = NULL;
	if(!timeout) {
		context = redisConnect((const char *)ip, port);
	}
	else {
		struct timeval tv = {0};
		tv.tv_sec = timeout;
		context = redisConnectWithTimeout((const char *)ip, port, tv);
	}
	ZL_EXP_LONG retval = ZL_EXP_TRUE;
	if(context == NULL || context->err) {
		if(argcount > 3) {
			DYNAMIC_STRING errstr = {0};
			if(context) {
				const char * err_const = "redisConnect error: ";
				dynamic_string_append(&errstr, (char *)err_const, strlen(err_const), 100);
				dynamic_string_append(&errstr, (char *)context->errstr, strlen(context->errstr), 100);
			}
			else {
				const char * err_const = "redisConnect can't allocate redis context";
				dynamic_string_append(&errstr, (char *)err_const, strlen(err_const), 100);
			}
			set_arg_value(VM_ARG, 4, ZL_EXP_FAT_STR, errstr.str, 0);
			dynamic_string_free(&errstr);
		}
		retval = ZL_EXP_FALSE;
		redisFree(context);
		context = NULL;
	}
	else {
		MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
		int ret_code = resource_list_set_member(&(my_data->resource_list), context, module_redis_free_context_resource_callback);
		if(ret_code != 0) {
			zenglApi_Exit(VM_ARG, "redisConnect add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
		}
	}
	set_arg_value(VM_ARG, 3, ZL_EXP_FAT_INT, NULL, (ZL_EXP_LONG)context);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, retval, 0);
}

/**
 * redisCommand模块函数，向redis服务器发送命令，并获取redis命令的执行结果
 * 第一个参数context，是通过redisConnect模块函数获取到的和redis连接相关的上下文指针
 * 第二个参数command，表示需要发送的redis命令，可以是字符串的形式，也可以是数组的形式
 * 第三个参数result必须是引用类型，用于存储redis命令的执行结果
 * 第四个参数is_null是可选参数，也必须是引用类型，用于表示执行结果是否为空
 * 第五个参数error也是可选参数，也必须是引用类型，当命令执行出错时，会将出错信息存储到该参数中
 * 第六个参数array_assoc也是可选参数，用于表示如果结果是数组类型的话，是否将其转换为哈希数组(使用字符串作为数组成员的key)
 * 如果redis命令执行成功，该模块函数会返回1，执行失败则返回0
 *
 * 例如：
	use builtin, redis;
	def TRUE 1;
	def FALSE 0;

	fun exit(error)
		print error;
		bltExit();
	endfun

	// 连接redis服务器
	if(!redisConnect("127.0.0.1", 6379, &con, &error, 30))
		exit(error);
	endif

	// 向redis服务器发送 get name 命令
	if(!redisCommand(con, "get name", &result, &is_null, &error))
		exit(error);
	endif

	// 判断命令的执行结果是否为空，不为空则将结果打印出来
	if(is_null)
		print '*** null ***';
	else
		print result;
	endif

	// 以数组的形式发送命令：hset hash2 testname "say \"hello world!\""
	if(!redisCommand(con, bltArray('hset', 'hash2', 'testname', 'say "hello world!"'), &result, &is_null, &error))
		exit(error);
	else
		print result;
	endif

	// 执行命令 hgetall hash2 ，并将结果转为哈希数组
	if(!redisCommand(con, "hgetall hash2", &result, &is_null, &error, TRUE))
		exit(error);
	endif

	if(is_null)
		print '*** null ***';
	else
		print result;
		// 循环将哈希数组中每个成员的键名和值打印出来
		for(i=0;bltIterArray(result,&i,&k,&v);)
			print k + ':' + v;
		endfor
	endif
 */
ZL_EXP_VOID module_redis_command(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 3)
		zenglApi_Exit(VM_ARG,"usage: redisCommand(context, command, &result[, &is_null[, &error[, array_assoc]]])");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [context] of redisCommand must be integer");
	}
	redisContext * context = (redisContext *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_redis_context(&(my_data->resource_list), context)) {
		zenglApi_Exit(VM_ARG,"redisCommand runtime error: invalid context");
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	char * command = NULL;
	ZENGL_EXPORT_MEMBLOCK command_memblock = {0};
	if(arg.type == ZL_EXP_FAT_STR) {
		command = arg.val.str;
	}
	else if(arg.type == ZL_EXP_FAT_MEMBLOCK) {
		command_memblock = arg.val.memblock;
	}
	else {
		zenglApi_Exit(VM_ARG,"the second argument [command] of redisCommand must be string or array");
	}
	ZL_EXP_LONG array_assoc = ZL_EXP_FALSE;
	detect_arg_is_address_type(VM_ARG, 3, &arg, "third", "result", "redisCommand");
	if(argcount > 3) {
		detect_arg_is_address_type(VM_ARG, 4, &arg, "fourth", "is_null", "redisCommand");
		if(argcount > 4) {
			detect_arg_is_address_type(VM_ARG, 5, &arg, "fifth", "error", "redisCommand");
			if(argcount > 5) {
				zenglApi_GetFunArg(VM_ARG,6,&arg);
				if(arg.type != ZL_EXP_FAT_INT) {
					zenglApi_Exit(VM_ARG,"the sixth argument [array_assoc] of redisCommand must be integer");
				}
				array_assoc = arg.val.integer;
			}
		}
	}
	redisReply * reply = NULL;
	ZL_EXP_INT memblock_valid_count = 0;
	if(command != NULL) {
		reply = redisCommand(context, command);
	}
	else {
		reply = st_redis_set_command_by_array(VM_ARG, context, command_memblock, &memblock_valid_count);
	}
	ZL_EXP_LONG retval = ZL_EXP_TRUE;
	ZL_EXP_LONG is_null = ZL_EXP_FALSE;
	if(reply == NULL) {
		char error_str[300] = {0};
		if(argcount > 4) {
			if(memblock_valid_count <= 0) {
				snprintf(error_str, 300, "redisCommand error: command array invalid count: %d", memblock_valid_count);
				set_arg_value(VM_ARG, 5, ZL_EXP_FAT_STR, (char *)error_str, 0);
			}
			else {
				snprintf(error_str, 300, "redisCommand error: reply is null");
				set_arg_value(VM_ARG, 5, ZL_EXP_FAT_STR, (char *)error_str, 0);
			}
		}
		set_arg_value(VM_ARG, 3, ZL_EXP_FAT_INT, NULL, 0);
		retval = ZL_EXP_FALSE;
	}
	else if(reply->type == REDIS_REPLY_ERROR) {
		if(argcount > 4) {
			DYNAMIC_STRING errstr = {0};
			const char * err_const = "redisCommand error: ";
			dynamic_string_append(&errstr, (char *)err_const, strlen(err_const), 100);
			dynamic_string_append(&errstr, reply->str, strlen(reply->str), 100);
			set_arg_value(VM_ARG, 5, ZL_EXP_FAT_STR, errstr.str, 0);
			dynamic_string_free(&errstr);
		}
		set_arg_value(VM_ARG, 3, ZL_EXP_FAT_INT, NULL, 0);
		retval = ZL_EXP_FALSE;
	}
	else if(reply->type == REDIS_REPLY_STRING || reply->type == REDIS_REPLY_STATUS) {
		set_arg_value(VM_ARG, 3, ZL_EXP_FAT_STR, reply->str, 0);
	}
	else if(reply->type == REDIS_REPLY_INTEGER) {
		set_arg_value(VM_ARG, 3, ZL_EXP_FAT_INT, NULL, (ZL_EXP_LONG)reply->integer);
	}
	else if(reply->type == REDIS_REPLY_NIL) {
		set_arg_value(VM_ARG, 3, ZL_EXP_FAT_INT, NULL, 0);
		is_null = ZL_EXP_TRUE;
	}
	else if(reply->type == REDIS_REPLY_ARRAY) {
		ZENGL_EXPORT_MEMBLOCK memblock = {0};
		ZENGL_EXPORT_MOD_FUN_ARG memblock_arg = {ZL_EXP_FAT_NONE,{0}};
		if(zenglApi_CreateMemBlock(VM_ARG,&memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
		int step = 1;
		if(array_assoc)
			step = 2;
		for(int i = 0; i < reply->elements; i += step) {
			int n = i;
			if(array_assoc)
				n = i + 1;
			switch(reply->element[n]->type) {
			case REDIS_REPLY_STRING:
			case REDIS_REPLY_STATUS:
				memblock_arg.type = ZL_EXP_FAT_STR;
				memblock_arg.val.str = reply->element[n]->str;
				break;
			case REDIS_REPLY_INTEGER:
				memblock_arg.type = ZL_EXP_FAT_INT;
				memblock_arg.val.integer = (ZL_EXP_LONG)reply->element[n]->integer;
				break;
			default:
				memblock_arg.type = ZL_EXP_FAT_INT;
				memblock_arg.val.integer = 0;
				break;
			}
			if(array_assoc && reply->element[i]->type == REDIS_REPLY_STRING) {
				zenglApi_SetMemBlockByHashKey(VM_ARG, &memblock, reply->element[i]->str, &memblock_arg);
			}
			else {
				zenglApi_SetMemBlock(VM_ARG, &memblock, (i+1), &memblock_arg);
			}
		}
		arg.type = ZL_EXP_FAT_MEMBLOCK;
		arg.val.memblock = memblock;
		zenglApi_SetFunArg(VM_ARG,3,&arg);
	}
	else {
		if(argcount > 4) {
			char error_str[300] = {0};
			snprintf(error_str, 300, "redisCommand error: invalid reply type: %d", reply->type);
			set_arg_value(VM_ARG, 5, ZL_EXP_FAT_STR, (char *)error_str, 0);
		}
		set_arg_value(VM_ARG, 3, ZL_EXP_FAT_INT, NULL, 0);
		retval = ZL_EXP_FALSE;
	}
	if(argcount > 3) {
		set_arg_value(VM_ARG, 4, ZL_EXP_FAT_INT, NULL, is_null);
	}
	freeReplyObject(reply);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, retval, 0);
}

/**
 * redisFree模块函数，将redis连接相关的上下文指针，对应的资源给释放掉
 * 第一个参数context表示需要释放的redis连接相关的上下文指针
 */
ZL_EXP_VOID module_redis_free(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: redisFree(context)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [context] of redisFree must be integer");
	}
	redisContext * context = (redisContext *)arg.val.integer;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!is_valid_redis_context(&(my_data->resource_list), context)) {
		zenglApi_Exit(VM_ARG,"redisFree runtime error: invalid context");
	}
	redisFree(context);
	int ret_code = resource_list_remove_member(&(my_data->resource_list), context);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "redisFree remove resource from resource_list failed, resource_list_remove_member error code:%d", ret_code);
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
}

/**
 * redis模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄(对应的C函数)
 */
ZL_EXP_VOID module_redis_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"redisConnect",module_redis_connect);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"redisCommand",module_redis_command);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"redisFree",module_redis_free);
}
