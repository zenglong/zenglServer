/*
 * module_redis.c
 *
 *  Created on: Feb 22, 2020
 *      Author: zengl
 */

#include "main.h"
#include "module_redis.h"
#include <hiredis.h>

static void module_redis_free_context_resource_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	redisContext * context = (redisContext *)ptr;
	redisFree(context);
}

static ZL_EXP_BOOL is_valid_redis_context(RESOURCE_LIST * resource_list, void * context)
{
	int ret = resource_list_get_ptr_idx(resource_list, context, module_redis_free_context_resource_callback);
	if(ret >= 0)
		return ZL_EXP_TRUE;
	else
		return ZL_EXP_FALSE;
}

ZL_EXP_VOID module_redis_connect(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 2)
		zenglApi_Exit(VM_ARG,"usage: redisConnect(ip, port)");
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
	redisContext * retval = redisConnect((const char *)ip, port);
	if(retval == NULL || retval->err) {
		if(retval) {
			zenglApi_Exit(VM_ARG,"redisConnect error: %s", retval->errstr);
		}
		else {
			zenglApi_Exit(VM_ARG,"redisConnect can't allocate redis context");
		}
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)retval, 0);
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int ret_code = resource_list_set_member(&(my_data->resource_list), retval, module_redis_free_context_resource_callback);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "redisConnect add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
	}
}

ZL_EXP_VOID module_redis_command(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 2)
		zenglApi_Exit(VM_ARG,"usage: redisCommand(context, command)");
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
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [command] of redisCommand must be string");
	}
	char * command = arg.val.str;
	redisReply * reply = redisCommand(context, command);
	if(reply->type == REDIS_REPLY_ERROR) {
		zenglApi_SetErrThenStop(VM_ARG,"redisCommand error: %s", reply->str);
		freeReplyObject(reply);
		return ;
	}
	if(reply->type == REDIS_REPLY_STRING || reply->type == REDIS_REPLY_STATUS) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, reply->str, 0, 0);
	}
	else if(reply->type == REDIS_REPLY_INTEGER) {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)reply->integer, 0);
	}
	else {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
	}
	freeReplyObject(reply);
}

ZL_EXP_VOID module_redis_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"redisConnect",module_redis_connect);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"redisCommand",module_redis_command);
}
