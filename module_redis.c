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

ZL_EXP_VOID module_redis_connect(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 3)
		zenglApi_Exit(VM_ARG,"usage: redisConnect(ip, port, &context[, &error])");
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
	detect_arg_is_address_type(VM_ARG, 3, &arg, "third", "context", "redisConnect");
	if(argcount > 3) {
		detect_arg_is_address_type(VM_ARG, 4, &arg, "fourth", "error", "redisConnect");
	}
	redisContext * context = redisConnect((const char *)ip, port);
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
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [command] of redisCommand must be string");
	}
	char * command = arg.val.str;
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
	redisReply * reply = redisCommand(context, command);
	ZL_EXP_LONG retval = ZL_EXP_TRUE;
	ZL_EXP_LONG is_null = ZL_EXP_FALSE;
	if(reply->type == REDIS_REPLY_ERROR) {
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

ZL_EXP_VOID module_redis_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"redisConnect",module_redis_connect);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"redisCommand",module_redis_command);
}
