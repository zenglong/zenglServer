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

/**
 * 和curl抓取操作相关的结构体，
 * 当curl库在执行抓取数据的操作时，会通过回调函数，将抓取到的数据存储到下面结构体中的memory字段，
 * 并将抓取到的数据的字节大小写入到下面结构体中的size字段，
 * 结构体中的VM_ARG字段用于存储zengl脚本的虚拟机指针，以对memory字段分配内存和根据抓取的数据动态调整内存大小。
 */
typedef struct _my_curl_memory_struct {
	char * memory;
	size_t size;
	ZL_EXP_VOID * VM_ARG;
} my_curl_memory_struct;

/**
 * curlEasyInit模块函数会返回以下类型的指针，
 * 其他的curl模块函数，例如：curlEasySetopt，curlEasyPerform等，都需要接收该类型的指针来进行curl相关的操作，
 * 该结构体中，又封装了一个CURL类型的指针，该指针是用于执行实际的curl操作的，
 * 结构体中的url字段，用于存储需要抓取的目标url地址，
 * 结构体中的useragent字段，用于存储设置的用户代理信息，
 * 在curlEasySetopt模块函数设置URL和USERAGENT时，会将下面结构体中的url和useragent字段对应的指针传给底层的库函数，
 * 在旧的curl库版本中(例如：7.15版本)，url和useragent等，需要自己提供和维护独立的内存空间，新的curl版本中会在内部执行拷贝操作，不需要外部调用者提供和维护独立的内存空间，
 * 为了兼容旧的curl库版本，就有了下面这个结构体，该结构体为curl需要的url和useragent等提供了独立的url，useragent等字段来指向相应的数据。
 * 结构体中的url和useragent字段，会被zengl虚拟机分配独立的互不干扰的内存空间，以确保旧版本的curl库函数能正常工作。
 */
typedef struct _my_curl_handle_struct {
	char * url;
	char * useragent;
	CURL * curl_handle;
} my_curl_handle_struct;

/**
 * 该变量用于判断，脚本中是否使用了curl_global_init库函数执行过curl的初始化。
 */
static __thread ZL_EXP_BOOL st_is_curl_global_init = ZL_EXP_FALSE;

/**
 * 通过底层的curl_global_init库函数来执行curl的初始化操作，
 * 在使用curl_easy_init，curl_easy_setopt库函数执行具体的curl操作之前，需要先通过curl_global_init库函数来初始化curl相关的环境，
 * curlEasyInit模块函数会在内部自动调用下面这个函数去执行初始化，如果已经执行过初始化了(通过st_is_curl_global_init的静态变量来判断)，
 * 则会跳过去，不会在同一个脚本中重复执行初始化操作。
 */
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

/**
 * 下面这个函数，用于清理curlEasyInit模块函数返回的my_curl_handle_struct类型的指针，
 * 它还会将my_curl_handle_struct类型的结构体中的url和useragent字段对应的内存也释放掉。
 */
static void st_curl_free_my_handle(ZL_EXP_VOID * VM_ARG, my_curl_handle_struct * my_curl_handle)
{
	if(my_curl_handle != NULL) {
		if(my_curl_handle->url != NULL) {
			zenglApi_FreeMem(VM_ARG, my_curl_handle->url);
		}
		if(my_curl_handle->useragent != NULL) {
			zenglApi_FreeMem(VM_ARG, my_curl_handle->useragent);
		}
		zenglApi_FreeMem(VM_ARG, my_curl_handle);
	}
}

/**
 * 根据src源字符串为dest分配内存，并将src字符串拷贝到dest指向的内存中，
 * 在设置my_curl_handle_struct类型的url，useragent等字段时，就会通过下面这个函数来为这些字段分配内存，和设置实际的字符串信息
 */
static char * st_curl_alloc_str(ZL_EXP_VOID * VM_ARG, char * dest, char * src)
{
	int src_len = strlen(src);
	ZL_EXP_BOOL need_cpy = ZL_EXP_TRUE;
	if(dest == NULL) {
		dest = (char *)zenglApi_AllocMem(VM_ARG, (src_len + 1));
	}
	else {
		int dest_len = strlen(dest);
		if(dest_len != src_len)
			dest = (char *)zenglApi_ReAllocMem(VM_ARG, dest, (src_len + 1));
		else if(strcmp(dest, src) == 0)
			need_cpy = ZL_EXP_FALSE;
	}
	if(need_cpy == ZL_EXP_TRUE) {
		memcpy(dest, src, src_len);
		dest[src_len] = '\0';
	}
	return dest;
}

/**
 * 为my_curl_handle_struct结构体中的url和useragent等字段分配内存，并设置相应的字符串信息
 */
static char * st_curl_process_str(ZL_EXP_VOID * VM_ARG, CURLoption option, my_curl_handle_struct * my_curl_handle, char * src)
{
	char * retval = NULL;
	switch(option) {
	case CURLOPT_URL:
		my_curl_handle->url = st_curl_alloc_str(VM_ARG, my_curl_handle->url, src);
		retval = my_curl_handle->url;
		break;
	case CURLOPT_USERAGENT:
		my_curl_handle->useragent = st_curl_alloc_str(VM_ARG, my_curl_handle->useragent, src);
		retval = my_curl_handle->useragent;
		break;
	}
	return retval;
}

/**
 * my_curl_handle_struct类型的指针的资源清理回调函数，
 * 如果没有在zengl脚本中手动通过curlEasyCleanup模块函数执行过清理操作的话，
 * 在脚本结束后，zenglServer会自动通过下面这个回调函数将未清理的指针给清理掉
 */
static void st_curl_easy_cleanup_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	if(ptr != NULL) {
		my_curl_handle_struct * my_curl_handle = (my_curl_handle_struct *)ptr;
		CURL * curl_handle = my_curl_handle->curl_handle;
		curl_easy_cleanup(curl_handle);
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] curl_easy_cleanup: %x\n", curl_handle); // debug
		st_curl_free_my_handle(VM_ARG, my_curl_handle);
	}
}

/**
 * 通过资源列表，判断是否是有效的my_curl_handle_struct类型的指针
 */
static ZL_EXP_BOOL st_is_valid_curl_handle(RESOURCE_LIST * resource_list, void * curl_handle)
{
	int ret = resource_list_get_ptr_idx(resource_list, curl_handle, st_curl_easy_cleanup_callback);
	if(ret >= 0)
		return ZL_EXP_TRUE;
	else
		return ZL_EXP_FALSE;
}

/**
 * 在curlEasySetopt，curlEasyPerform等模块函数中，
 * 会先通过下面这个函数来判断脚本提供的第一个参数是否是有效的指针，
 * 如果不是有效的指针，则会抛出错误
 */
static MAIN_DATA * st_assert_curl_handle(ZL_EXP_VOID * VM_ARG, void * curl_handle, const char * module_fun_name)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!st_is_valid_curl_handle(&(my_data->resource_list), curl_handle)) {
		zenglApi_Exit(VM_ARG,"%s runtime error: invalid curl_handle: %x", module_fun_name, curl_handle);
	}
	return my_data;
}

/**
 * 执行curl抓取数据操作时的回调函数，
 * 在该回调函数中会将抓取到的数据写入到my_curl_memory_struct结构体变量的memory字段中，
 * 并将抓取到的数据的字节大小写入到my_curl_memory_struct结构体变量的size字段中，
 * 如果抓取的数据比较大，则该回调函数可能会被执行多次
 */
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

/**
 * 如果使用了curl_global_init库函数进行过curl的初始化操作，
 * 则在结束时，需要使用curl_global_cleanup库函数来清理掉初始化操作所分配的资源，
 * zenglServer会在脚本执行结束时，自动调用下面这个函数来完成清理操作
 */
void export_curl_global_cleanup()
{
	if(st_is_curl_global_init == ZL_EXP_TRUE) {
		curl_global_cleanup();
		st_is_curl_global_init = ZL_EXP_FALSE;
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] curl_global_cleanup \n"); // debug
	}
}

/**
 * curlEasyInit模块函数，执行curl初始化，并返回一个用于执行curl操作的指针，
 * 返回的指针是my_curl_handle_struct类型的，该类型对应的结构体中又封装了一个CURL类型的指针(用于执行实际的底层的curl操作的)，
 * 该模块函数在创建了my_curl_handle_struct类型的指针后，还会将其存储到资源列表中，
 * 这样其他的curl模块函数在接收到该类型的指针后，就可以根据资源列表来判断是否是有效的指针了，
 * 同时，如果在脚本中忘了手动清理该指针的话，在脚本结束时，也会自动根据资源列表来清理掉指针。
 * 该模块函数相关的示例代码，请参考curlEasyPerform模块函数的注释部分
 *
 * 此模块函数在底层，会先通过curl_global_init库函数来进行curl的初始化操作，如果在同一脚本中已经初始化过了，则会跳过去，不会重复进行初始化，
 * 接着会通过curl_easy_init的库函数来创建一个CURL类型的指针，并将该指针封装到自定义的my_curl_handle_struct类型的结构中，
 * 最后将my_curl_handle_struct类型的指针返回，之所以做一个封装，是为了兼容旧的curl库版本而做的兼容处理。
 * curl_global_init库函数的官方地址为：https://curl.haxx.se/libcurl/c/curl_global_init.html
 * curl_easy_init库函数的官方地址为：https://curl.haxx.se/libcurl/c/curl_easy_init.html
 */
ZL_EXP_VOID module_curl_easy_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	st_curl_global_init();
	CURL * curl_handle = curl_easy_init();
	write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] curl_easy_init: %x\n", curl_handle); // debug
	my_curl_handle_struct * my_curl_handle = zenglApi_AllocMem(VM_ARG, sizeof(my_curl_handle_struct));
	memset(my_curl_handle, 0, sizeof(my_curl_handle_struct));
	my_curl_handle->curl_handle = curl_handle;
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)my_curl_handle, 0);
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int ret_code = resource_list_set_member(&(my_data->resource_list), my_curl_handle, st_curl_easy_cleanup_callback);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "curlEasyInit add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
	}
}

/**
 * curlEasyCleanup模块函数，清理和my_curl_handle_struct指针相关的资源
 * 该模块函数的第一个参数必须是有效的my_curl_handle_struct指针，该指针由curlEasyInit模块函数返回，
 * 当不需要执行curl相关的抓取操作时，可以手动通过该模块函数将指针相关的资源给清理掉，
 * 如果没有手动清理的话，在脚本退出时也会自动进行指针的清理操作。
 * 该模块函数的示例代码，请参考curlEasyPerform模块函数的注释部分
 *
 * my_curl_handle_struct指针指向的结构中，又封装了一个CURL类型的指针，该指针是用于执行实际的curl操作的，
 * 该模块函数在底层，会通过curl_easy_cleanup库函数将CURL类型指针相关的资源给清理掉，
 * 和curl_easy_cleanup库函数相关的官方地址为：https://curl.haxx.se/libcurl/c/curl_easy_cleanup.html
 */
ZL_EXP_VOID module_curl_easy_cleanup(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: curlEasyCleanup(curl_handle): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [curl_handle] of curlEasyCleanup must be integer");
	}
	my_curl_handle_struct * my_curl_handle = (my_curl_handle_struct *)arg.val.integer;
	MAIN_DATA * my_data = st_assert_curl_handle(VM_ARG, my_curl_handle, "curlEasyCleanup");
	CURL * curl_handle = my_curl_handle->curl_handle;
	curl_easy_cleanup(curl_handle);
	write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] curl_easy_cleanup: %x\n", curl_handle); // debug
	st_curl_free_my_handle(VM_ARG, my_curl_handle);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
	int ret_code = resource_list_remove_member(&(my_data->resource_list), my_curl_handle); // 将清理掉的实例指针从资源列表中移除
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "curlEasyCleanup remove resource from resource_list failed, resource_list_remove_member error code:%d", ret_code);
	}
}

/**
 * curlEasySetopt模块函数，设置curl抓取相关的选项，例如：抓取的目标地址，需要使用的用户代理等
 * 该模块函数的第一个参数必须是有效的my_curl_handle_struct指针，该指针由curlEasyInit模块函数返回，
 * 第二个参数是字符串类型的选项名称，暂时只支持三个选项：
 * 'URL'：表示需要抓取的目标地址
 * 'USERAGENT'：需要设置的用户代理
 * 'FOLLOWLOCATION'：当抓取到重定向页面时，是否进行重定向操作
 * 第三个参数是需要设置的具体的选项值，当第二个参数是'URL'，'USERAGENT'时，选项值必须是字符串类型，表示需要设置的url地址，用户代理等，
 * 当第二个参数是'FOLLOWLOCATION'时，选项值必须是整数类型，表示是否进行重定向操作，默认是0，即不进行重定向，需要进行重定向的，可以将选项值设置为1
 * 具体的例子，请参考curlEasyPerform模块函数的注释部分
 *
 * 该模块函数最终会通过curl_easy_setopt库函数去执行具体的操作，
 * 该库函数的官方地址为：https://curl.haxx.se/libcurl/c/curl_easy_setopt.html
 */
ZL_EXP_VOID module_curl_easy_setopt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 3)
		zenglApi_Exit(VM_ARG,"usage: curlEasySetopt(curl_handle, option_name, option_value): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [curl_handle] of curlEasySetopt must be integer");
	}
	my_curl_handle_struct * my_curl_handle = (my_curl_handle_struct *)arg.val.integer;
	st_assert_curl_handle(VM_ARG, my_curl_handle, "curlEasySetopt");
	CURL * curl_handle = my_curl_handle->curl_handle;
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
			char * option_value = st_curl_process_str(VM_ARG, option, my_curl_handle, arg.val.str);
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

/**
 * curlEasyPerform模块函数，它会使用curl库执行具体的抓取操作
 * 该模块函数的第一个参数必须是有效的my_curl_handle_struct指针，该指针由curlEasyInit模块函数返回，
 * 第二个参数content必须是引用类型，用于存储抓取到的具体数据，
 * 第三个参数size也必须是引用类型，用于存储抓取到的数据的字节大小，该参数是可选的，
 * 该模块函数如果执行成功，会返回0，如果执行失败，则返回相应的错误码，可以使用curlEasyStrError模块函数，来获取错误码对应的字符串类型的错误描述，
 * 例如：
	use builtin, curl, request;
	def TRUE 1;

	rqtSetResponseHeader("Content-Type: text/html; charset=utf-8");
	curl_handle = curlEasyInit();
	curlEasySetopt(curl_handle, 'URL', 'https://www.example.com/');
	curlEasySetopt(curl_handle, 'USERAGENT', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0');
	curlEasySetopt(curl_handle, 'FOLLOWLOCATION', TRUE);
	ret = curlEasyPerform(curl_handle, &content, &size);
	if(ret == 0)
		print 'size: ' + size;
		print 'content: ' + content;
	else
		print 'error: ' + curlEasyStrError(ret);
	endif
	curlEasyCleanup(curl_handle);

	上面脚本中会先通过curlEasyInit模块函数获取my_curl_handle_struct类型的指针，
	接着，通过curlEasySetopt模块函数来设置需要抓取的目标地址，以及设置useragent用户代理等，
	在设置好后，最后通过curlEasyPerform模块函数去执行抓取操作，如果返回的ret为0，则content变量将包含抓取的数据，size变量则会包含抓取数据的字节大小，
	如果返回的ret不为0，则会将返回值传递给curlEasyStrError模块函数，以获取具体的错误描述信息。

	该模块函数在底层最终会通过curl_easy_perform库函数去执行具体的抓取操作，
	该库函数的官方地址为：https://curl.haxx.se/libcurl/c/curl_easy_perform.html
 */
ZL_EXP_VOID module_curl_easy_perform(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: curlEasyPerform(curl_handle, &content[, &size]): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [curl_handle] of curlEasyPerform must be integer");
	}
	my_curl_handle_struct * my_curl_handle = (my_curl_handle_struct *)arg.val.integer;
	st_assert_curl_handle(VM_ARG, my_curl_handle, "curlEasyPerform");
	CURL * curl_handle = my_curl_handle->curl_handle;
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

/**
 * curlEasyStrError模块函数，根据其他模块函数返回的整数类型的错误码，返回相应的错误描述
 * 该模块函数的第一个参数是整数类型的错误码，返回的结果是字符串类型的错误信息
 * 该模块函数底层会通过curl_easy_strerror库函数来获取具体的错误信息
 * curl_easy_strerror库函数的官方地址：https://curl.haxx.se/libcurl/c/curl_easy_strerror.html
 */
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

/**
 * curlVersion模块函数，用于获取当前所使用的curl库的版本信息
 * 该模块函数除了会返回curl库的版本信息，还会将与其相关的组件的版本信息也显示出来(例如：OpenSSL等)
 * 该模块函数返回的结果，类似如下：
 * libcurl/7.29.0 NSS/3.34 zlib/1.2.11 libidn/1.28 libssh2/1.4.3
 * 该模块函数底层会通过curl_version的库函数去执行具体的操作
 * curl_version库函数的官方地址：https://curl.haxx.se/libcurl/c/curl_version.html
 */
ZL_EXP_VOID module_curl_version(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, (char *)curl_version(), 0, 0);
}

/**
 * curl模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄(对应的C函数)
 */
ZL_EXP_VOID module_curl_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlEasyInit",module_curl_easy_init);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlEasyCleanup",module_curl_easy_cleanup);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlEasySetopt",module_curl_easy_setopt);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlEasyPerform",module_curl_easy_perform);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlEasyStrError",module_curl_easy_strerror);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlVersion",module_curl_version);
}
