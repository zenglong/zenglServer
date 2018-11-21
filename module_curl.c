/*
 * module_curl.c
 *
 *  Created on: Nov 20, 2018
 *      Author: zengl
 */

#include "main.h"
#include "module_curl.h"
#include <curl/curl.h>

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
		zenglApi_Exit(VM_ARG,"%s runtime error: invalid curl_handle", module_fun_name);
	}
	return my_data;
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
	write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] curlEasyCleanup: %x\n", curl_handle); // debug
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
	int ret_code = resource_list_remove_member(&(my_data->resource_list), curl_handle); // 将清理掉的实例指针从资源列表中移除
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "curlEasyCleanup remove resource from resource_list failed, resource_list_remove_member error code:%d", ret_code);
	}
}

ZL_EXP_VOID module_curl_version(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, (char *)curl_version(), 0, 0);
}

ZL_EXP_VOID module_curl_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlEasyInit",module_curl_easy_init);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlEasyCleanup",module_curl_easy_cleanup);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlVersion",module_curl_version);
}
