/*
 * module_curl.c
 *
 *  Created on: Nov 20, 2018
 *      Author: zengl
 */

#include "main.h"
#include "module_curl.h"
#include <curl/curl.h>
#include <string.h>

typedef struct _my_curl_memory_struct {
	char * memory;
	size_t size;
	ZL_EXP_VOID * VM_ARG;
} my_curl_memory_struct;

static __thread ZL_EXP_BOOL st_is_curl_global_init = ZL_EXP_FALSE;

static ZL_EXP_BOOL st_curl_global_init()
{
	if(st_is_curl_global_init == ZL_EXP_FALSE) {
		curl_global_init(CURL_GLOBAL_ALL);
		st_is_curl_global_init = ZL_EXP_TRUE;
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] curl_global_init \n"); // debug
		return ZL_EXP_TRUE;
	}
	else
		return ZL_EXP_FALSE;
}

static void st_curl_easy_cleanup_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	if(ptr != NULL) {
		CURL * curl_handle = (CURL *)ptr;
		curl_easy_cleanup(curl_handle);
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] curl_easy_cleanup: %x\n", curl_handle); // debug
	}
}

static ZL_EXP_BOOL st_is_valid_curl_handle(RESOURCE_LIST * resource_list, void * curl_handle)
{
	int ret = resource_list_get_ptr_idx(resource_list, curl_handle, st_curl_easy_cleanup_callback);
	if(ret >= 0)
		return ZL_EXP_TRUE;
	else
		return ZL_EXP_FALSE;
}

static MAIN_DATA * st_assert_curl_handle(ZL_EXP_VOID * VM_ARG, void * curl_handle, const char * module_fun_name)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!st_is_valid_curl_handle(&(my_data->resource_list), curl_handle)) {
		zenglApi_Exit(VM_ARG,"%s runtime error: invalid curl_handle: %x", module_fun_name, curl_handle);
	}
	return my_data;
}

static size_t st_write_memory_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	my_curl_memory_struct * chunk = (my_curl_memory_struct *)userp;
	chunk->memory = (char *)zenglApi_ReAllocMem(chunk->VM_ARG, chunk->memory, chunk->size + realsize + 1);
	if(chunk->memory == NULL) {
		zenglApi_Exit(chunk->VM_ARG, "not enough memory in st_write_memory_callback");
	}
	memcpy(&(chunk->memory[chunk->size]), contents, realsize);
	chunk->size += realsize;
	chunk->memory[chunk->size] = '\0';
	return realsize;
}

void export_curl_global_cleanup()
{
	if(st_is_curl_global_init == ZL_EXP_TRUE) {
		curl_global_cleanup();
		st_is_curl_global_init = ZL_EXP_FALSE;
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] curl_global_cleanup \n"); // debug
	}
}

ZL_EXP_VOID module_curl_easy_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	st_curl_global_init();
	CURL * curl_handle = curl_easy_init();
	write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] curl_easy_init: %x\n", curl_handle); // debug
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)curl_handle, 0);
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int ret_code = resource_list_set_member(&(my_data->resource_list), curl_handle, st_curl_easy_cleanup_callback);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "curlEasyInit add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
	}
}

ZL_EXP_VOID module_curl_easy_cleanup(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: curlEasyCleanup(curl_handle): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [curl_handle] of curlEasyCleanup must be integer");
	}
	CURL * curl_handle = (CURL *)arg.val.integer;
	MAIN_DATA * my_data = st_assert_curl_handle(VM_ARG, curl_handle, "curlEasyCleanup");
	curl_easy_cleanup(curl_handle);
	write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] curl_easy_cleanup: %x\n", curl_handle); // debug
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
	int ret_code = resource_list_remove_member(&(my_data->resource_list), curl_handle); // 将清理掉的实例指针从资源列表中移除
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "curlEasyCleanup remove resource from resource_list failed, resource_list_remove_member error code:%d", ret_code);
	}
}

ZL_EXP_VOID module_curl_easy_setopt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 3)
		zenglApi_Exit(VM_ARG,"usage: curlEasySetopt(curl_handle, option_name, option_value): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [curl_handle] of curlEasySetopt must be integer");
	}
	CURL * curl_handle = (CURL *)arg.val.integer;
	st_assert_curl_handle(VM_ARG, curl_handle, "curlEasySetopt");
	char * options_str[] = {
			"URL", "USERAGENT", "FOLLOWLOCATION"
	};
	int options_str_len = sizeof(options_str)/sizeof(options_str[0]);
	CURLoption options_enum[] = {
			CURLOPT_URL, CURLOPT_USERAGENT, CURLOPT_FOLLOWLOCATION
	};
	CURLoption option = 0;
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	int opt_idx = 0;
	if(arg.type == ZL_EXP_FAT_STR) {
		for(; opt_idx < options_str_len; opt_idx++) {
			if(options_str[opt_idx][0] == arg.val.str[0] &&
				strlen(options_str[opt_idx]) == strlen(arg.val.str) &&
				strcmp(options_str[opt_idx], arg.val.str) == 0) {
				option = (CURLoption)options_enum[opt_idx];
				break;
			}
		}
	}
	else {
		zenglApi_Exit(VM_ARG,"the second argument [option_name] of curlEasySetopt must be string");
	}
	zenglApi_GetFunArg(VM_ARG,3,&arg);
	CURLcode retval;
	switch(option) {
	case CURLOPT_URL:
	case CURLOPT_USERAGENT:
		if(arg.type == ZL_EXP_FAT_STR) {
			char * option_value = arg.val.str;
			retval = curl_easy_setopt(curl_handle, option, option_value);
		}
		else {
			zenglApi_Exit(VM_ARG,"the third argument [option_value] of curlEasySetopt must be string when [option_name] is %s", options_str[opt_idx]);
		}
		break;
	case CURLOPT_FOLLOWLOCATION:
		if(arg.type == ZL_EXP_FAT_INT) {
			long option_value = arg.val.integer;
			retval = curl_easy_setopt(curl_handle, option, option_value);
		}
		else {
			zenglApi_Exit(VM_ARG,"the third argument [option_value] of curlEasySetopt must be integer when [option_name] is %s", options_str[opt_idx]);
		}
		break;
	default:
		zenglApi_Exit(VM_ARG, "the second argument [option_name] of curlEasySetopt is invalid: %s", options_str[opt_idx]);
		break;
	}
	if(retval == CURLE_OK)
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
	else if(retval > 0)
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)retval, 0);
	else
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, -1, 0);
}

ZL_EXP_VOID module_curl_easy_perform(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: curlEasyPerform(curl_handle, &content[, &size]): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [curl_handle] of curlEasyPerform must be integer");
	}
	CURL * curl_handle = (CURL *)arg.val.integer;
	st_assert_curl_handle(VM_ARG, curl_handle, "curlEasyPerform");
	zenglApi_GetFunArgInfo(VM_ARG, 2, &arg);
	switch(arg.type){
	case ZL_EXP_FAT_ADDR:
	case ZL_EXP_FAT_ADDR_LOC:
	case ZL_EXP_FAT_ADDR_MEMBLK:
		break;
	default:
		zenglApi_Exit(VM_ARG,"the second argument [&content] of curlEasyPerform must be address type");
		break;
	}
	if(argcount > 2) {
		zenglApi_GetFunArgInfo(VM_ARG, 3, &arg);
		switch(arg.type){
		case ZL_EXP_FAT_ADDR:
		case ZL_EXP_FAT_ADDR_LOC:
		case ZL_EXP_FAT_ADDR_MEMBLK:
			break;
		default:
			zenglApi_Exit(VM_ARG,"the third argument [&size] of curlEasyPerform must be address type");
			break;
		}
	}
	my_curl_memory_struct chunk = {0};
	chunk.memory = (char *)zenglApi_AllocMem(VM_ARG, 1);
	chunk.size = 0;
	chunk.memory[chunk.size] = '\0';
	chunk.VM_ARG = VM_ARG;
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, st_write_memory_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
	CURLcode retval = curl_easy_perform(curl_handle);
	if(retval == CURLE_OK) {
		arg.type = ZL_EXP_FAT_STR;
		arg.val.str = chunk.memory;
		zenglApi_SetFunArg(VM_ARG,2,&arg);
		if(argcount > 2) {
			arg.type = ZL_EXP_FAT_INT;
			arg.val.integer = (ZL_EXP_INT)chunk.size;
			zenglApi_SetFunArg(VM_ARG,3,&arg);
		}
		zenglApi_FreeMem(VM_ARG, chunk.memory);
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
	}
	else {
		zenglApi_FreeMem(VM_ARG, chunk.memory);
		if(retval > 0) {
			zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)retval, 0);
		}
		else
			zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, -1, 0);
	}
}

ZL_EXP_VOID module_curl_easy_strerror(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: curlEasyStrError(errornum): string");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [errornum] of curlEasyStrError must be integer");
	}
	if(arg.val.integer < 0) {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, "unknown error code", 0, 0);
		return;
	}
	CURLcode errornum = (CURLcode)arg.val.integer;
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, (char *)curl_easy_strerror(errornum), 0, 0);
}

ZL_EXP_VOID module_curl_version(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, (char *)curl_version(), 0, 0);
}

ZL_EXP_VOID module_curl_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlEasyInit",module_curl_easy_init);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlEasyCleanup",module_curl_easy_cleanup);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlEasySetopt",module_curl_easy_setopt);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlEasyPerform",module_curl_easy_perform);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlEasyStrError",module_curl_easy_strerror);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlVersion",module_curl_version);
}
