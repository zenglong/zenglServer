/*
 * module_curl.c
 *
 *  Created on: Nov 20, 2018
 *      Author: zengl
 */

#include "main.h"
#include "module_builtin.h"
#include "module_curl.h"
#include <curl/curl.h>
#include <string.h>

/**
 * 根据当前执行脚本的目录路径，加上filename文件名，来生成可以被fopen等C库函数使用的路径，定义在module_builtin.c文件中
 */
void builtin_make_fullpath(char * full_path, char * filename, MAIN_DATA * my_data);

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
 * 在curlEasySetopt模块函数设置URL和USERAGENT时，会将下面结构体中的url和useragent字段对应的指针传给底层的库函数，
 * 在旧的curl库版本中(例如：7.15版本)，url和useragent等，需要自己提供和维护独立的内存空间，新的curl版本中会在内部执行拷贝操作，不需要外部调用者提供和维护独立的内存空间，
 * 为了兼容旧的curl库版本，就有了下面这个结构体，该结构体为curl需要的url和useragent等提供了独立的url，useragent等字段来指向相应的数据。
 * 结构体中的url和useragent字段，会被zengl虚拟机分配独立的互不干扰的内存空间，以确保旧版本的curl库函数能正常工作。
 */
typedef struct _my_curl_handle_struct {
	char * url;           // 需要抓取的目标url地址
	char * useragent;     // 需要设置的用户代理信息
	char * cookiefile;    // 需要读cookie的文件名，当需要发送cookie信息时，curl会读取该文件，并将其中的cookie作为请求发送出去
	char * cookiejar;     // 需要写入cookie的文件名，当curl获取到的响应头中包含了设置cookie的信息时，会将这些cookie写入到指定的文件
	char * cookie;        // 存储自定义的cookie
	char * proxy;         // 用于设置http，socks5之类的代理
	char * postfields;    // 用于设置application/x-www-form-urlencoded类型的POST请求
	FILE * stderr_stream; // 当使用VERBOSE输出调试信息时，会将调试信息写入到stderr_stream文件指针所对应的文件中
	CURL * curl_handle;   // 用于执行实际的底层的curl操作
	struct curl_httppost * post; // 用于设置multipart/form-data类型的POST请求
	struct curl_slist * chunk;   // 用于设置自定义的HTTP请求头
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
 * 它还会将my_curl_handle_struct类型的结构体中的url和useragent等字段对应的内存也释放掉。
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
		if(my_curl_handle->cookiefile != NULL) {
			zenglApi_FreeMem(VM_ARG, my_curl_handle->cookiefile);
		}
		if(my_curl_handle->cookiejar != NULL) {
			zenglApi_FreeMem(VM_ARG, my_curl_handle->cookiejar);
		}
		if(my_curl_handle->cookie != NULL) {
			zenglApi_FreeMem(VM_ARG, my_curl_handle->cookie);
		}
		if(my_curl_handle->proxy != NULL) {
			zenglApi_FreeMem(VM_ARG, my_curl_handle->proxy);
		}
		if(my_curl_handle->postfields != NULL) {
			zenglApi_FreeMem(VM_ARG, my_curl_handle->postfields);
		}
		if(my_curl_handle->stderr_stream != NULL) {
			fclose(my_curl_handle->stderr_stream);
		}
		if(my_curl_handle->post != NULL) {
			curl_formfree(my_curl_handle->post);
			my_curl_handle->post = NULL;
		}
		if(my_curl_handle->chunk != NULL) {
			curl_slist_free_all(my_curl_handle->chunk);
			my_curl_handle->chunk = NULL;
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
static char * st_curl_process_str(ZL_EXP_VOID * VM_ARG, MAIN_DATA * my_data,
		CURLoption option, my_curl_handle_struct * my_curl_handle, char * src)
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
	case CURLOPT_COOKIEFILE:
	case CURLOPT_COOKIEJAR:
		{
			char full_path[FULL_PATH_SIZE];
			builtin_make_fullpath(full_path, src, my_data);
			if(option == CURLOPT_COOKIEFILE) {
				my_curl_handle->cookiefile = st_curl_alloc_str(VM_ARG, my_curl_handle->cookiefile, full_path);
				retval = my_curl_handle->cookiefile;
			}
			else {
				my_curl_handle->cookiejar = st_curl_alloc_str(VM_ARG, my_curl_handle->cookiejar, full_path);
				retval = my_curl_handle->cookiejar;
			}
		}
		break;
	case CURLOPT_COOKIE:
		my_curl_handle->cookie = st_curl_alloc_str(VM_ARG, my_curl_handle->cookie, src);
		retval = my_curl_handle->cookie;
		break;
	case CURLOPT_PROXY:
		my_curl_handle->proxy = st_curl_alloc_str(VM_ARG, my_curl_handle->proxy, src);
		retval = my_curl_handle->proxy;
		break;
	case CURLOPT_POSTFIELDS:
		my_curl_handle->postfields = st_curl_alloc_str(VM_ARG, my_curl_handle->postfields, src);
		retval = my_curl_handle->postfields;
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

static void st_curl_free_ptr_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	if(ptr != NULL) {
		zenglApi_FreeMem(VM_ARG, ptr);
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
 * 第二个参数是字符串类型的选项名称，暂时只支持以下几个选项：
 * 'URL'：表示需要抓取的目标地址
 * 'USERAGENT'：需要设置的用户代理
 * 'FOLLOWLOCATION'：当抓取到重定向页面时，是否进行重定向操作
 * 'SSL_VERIFYPEER'：是否校验SSL证书
 * 'TIMEOUT': 设置超时时间
 * 'COOKIEFILE': 设置需要读cookie的文件名，当需要发送cookie信息时，curl会读取该文件，并将其中的cookie作为请求发送出去
 * 'COOKIEJAR': 设置需要写入cookie的文件名，当curl获取到的响应头中包含了设置cookie的信息时，会将这些cookie写入到指定的文件
 * 'COOKIE': 设置自定义的cookie
 * 'PROXY': 设置http，socks5之类的代理，socks协议的代理需要7.21.7及以上的版本才支持，低版本的curl库只支持http协议的代理
 * 'POSTFIELDS': 设置application/x-www-form-urlencoded类型的POST请求
 * 'VERBOSE': 设置是否输出详细的连接信息，包含了请求头和响应头在内，方便调试，这些连接信息会输出到 STDERR 所指定的文件中
 * 'STDERR': 当开启了VERBOSE时，详细的连接信息会保存到STDERR所指定的文件中
 *
 * 第三个参数是需要设置的具体的选项值，
 *
 * 当第二个参数是'URL'，'USERAGENT'，'COOKIE'，'PROXY'，'POSTFIELDS'时，
 * 选项值必须是字符串类型，表示需要设置的url地址，用户代理等，
 * 当第二个参数是'COOKIEFILE'，'COOKIEJAR'时，选项值也是字符串，表示需要读取和写入cookie的文件的路径（该路径是相对于当前主执行脚本的）
 *
 * 当第二个参数是'STDERR'时，可以有两个选项值：
 * 	第一个选项值option_value表示相对于当前主执行脚本的文件路径，即需要输出VERBOSE信息到哪个文件，
 * 	第二个选项值option_value2是可选的，表示需要以什么模式来打开该文件，默认是wb表示以写入模式打开文件，该模式会清空文件中原有的内容，
 * 		如果option_value2设置为ab，则表示以追加的方式打开文件，VERBOSE信息会追加到文件的末尾。
 *
 * 当第二个参数是'VERBOSE'时，选项值必须是整数类型，表示是否输出详细的连接信息，默认是0，即不输出连接信息，如果要输出连接信息，可以将选项值设置为1
 * 当第二个参数是'FOLLOWLOCATION'时，选项值必须是整数类型，表示是否进行重定向操作，默认是0，即不进行重定向，需要进行重定向的，可以将选项值设置为1
 * 当第二个参数是'SSL_VERIFYPEER'时，选项值必须是整数类型，表示是否校验SSL证书，默认是1，即需要进行校验，如果不需要校验，可以将选项值设置为0
 * 当第二个参数是'TIMEOUT'时，选项值必须是整数类型，表示需要设置的超时时间
 *
 * 和'URL'，'USERAGENT'，'FOLLOWLOCATION'，'SSL_VERIFYPEER'，'TIMEOUT'选项相关的例子，请参考curlEasyPerform模块函数的注释部分
 * 和'COOKIEFILE'选项相关的例子可以参考 my_webroot/v0_16_0/test_cookiefile.zl 脚本对应的代码
 * 和'COOKIEJAR'选项相关的例子可以参考 my_webroot/v0_16_0/test_cookiejar.zl 脚本对应的代码
 * 和'COOKIE'选项相关的例子可以参考 my_webroot/v0_16_0/test_cookie.zl 脚本对应的代码
 * 和'PROXY'选项相关的例子可以参考 my_webroot/v0_16_0/test_proxy.zl 脚本对应的代码
 * 和'POSTFIELDS'选项相关的例子可以参考 my_webroot/v0_16_0/test_postfields.zl 脚本对应的代码
 * 和'VERBOSE'，'STDERR'选项相关的例子可以参考 my_webroot/v0_16_0/test_verbose.zl 脚本对应的代码
 *
 * 该模块函数最终会通过curl_easy_setopt库函数去执行具体的操作，
 * 该库函数的官方地址为：https://curl.haxx.se/libcurl/c/curl_easy_setopt.html
 */
ZL_EXP_VOID module_curl_easy_setopt(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 3)
		zenglApi_Exit(VM_ARG,"usage: curlEasySetopt(curl_handle, option_name, option_value[, option_value2]): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [curl_handle] of curlEasySetopt must be integer");
	}
	my_curl_handle_struct * my_curl_handle = (my_curl_handle_struct *)arg.val.integer;
	MAIN_DATA * my_data = st_assert_curl_handle(VM_ARG, my_curl_handle, "curlEasySetopt");
	CURL * curl_handle = my_curl_handle->curl_handle;
	char * options_str[] = {
			"URL", "USERAGENT", "FOLLOWLOCATION", "SSL_VERIFYPEER", "SSL_VERIFYHOST", "TIMEOUT",
			"COOKIEFILE", "COOKIEJAR", "COOKIE", "PROXY", "POSTFIELDS",
			"VERBOSE", "STDERR"
	};
	int options_str_len = sizeof(options_str)/sizeof(options_str[0]);
	CURLoption options_enum[] = {
			CURLOPT_URL, CURLOPT_USERAGENT, CURLOPT_FOLLOWLOCATION, CURLOPT_SSL_VERIFYPEER, CURLOPT_SSL_VERIFYHOST, CURLOPT_TIMEOUT,
			CURLOPT_COOKIEFILE, CURLOPT_COOKIEJAR, CURLOPT_COOKIE, CURLOPT_PROXY, CURLOPT_POSTFIELDS,
			CURLOPT_VERBOSE, CURLOPT_STDERR
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
	case CURLOPT_COOKIEFILE:
	case CURLOPT_COOKIEJAR:
	case CURLOPT_COOKIE:
	case CURLOPT_PROXY:
	case CURLOPT_POSTFIELDS:
		if(arg.type == ZL_EXP_FAT_STR) {
			char * option_value = st_curl_process_str(VM_ARG, my_data, option, my_curl_handle, arg.val.str);
			retval = curl_easy_setopt(curl_handle, option, option_value);
		}
		else {
			zenglApi_Exit(VM_ARG,"the third argument [option_value] of curlEasySetopt must be string when [option_name] is %s", options_str[opt_idx]);
		}
		break;
	case CURLOPT_STDERR:
		if(arg.type == ZL_EXP_FAT_STR) {
			if(my_curl_handle->stderr_stream != NULL) {
				fclose(my_curl_handle->stderr_stream);
			}
			char * filename = arg.val.str;
			char full_path[FULL_PATH_SIZE];
			builtin_make_fullpath(full_path, filename, my_data);
			char * mode = "wb";
			if(argcount > 3) {
				zenglApi_GetFunArg(VM_ARG,4,&arg);
				if(arg.type != ZL_EXP_FAT_STR) {
					zenglApi_Exit(VM_ARG,"the fourth argument [option_value2] of curlEasySetopt must be string when [option_name] is %s",
							options_str[opt_idx]);
				}
				mode = arg.val.str;
			}
			my_curl_handle->stderr_stream = fopen(full_path, mode);
			retval = curl_easy_setopt(curl_handle, option, my_curl_handle->stderr_stream);
		}
		else {
			zenglApi_Exit(VM_ARG,"the third argument [option_value] of curlEasySetopt must be string when [option_name] is %s", options_str[opt_idx]);
		}
		break;
	case CURLOPT_FOLLOWLOCATION:
	case CURLOPT_SSL_VERIFYPEER:
	case CURLOPT_SSL_VERIFYHOST:
	case CURLOPT_TIMEOUT:
	case CURLOPT_VERBOSE:
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
 * 该模块函数的第一个参数必须是有效的my_curl_handle_struct类型的指针，该指针由curlEasyInit模块函数返回，
 * 第二个参数content必须是引用类型，用于存储抓取到的具体数据（只能存储字符串数据，如果是图像等二进制数据会存储不完整），
 * 第三个参数size也必须是引用类型（该参数是可选的），用于存储抓取到的数据的字节大小，
 * 第四个参数ptr也必须是引用类型（该参数也是可选的），用于存储指针，该指针指向的内存中存储了抓取到的数据，当抓取到的数据是图像等二进制数据时，
 * 就可以使用该指针来访问这些二进制数据，例如，可以利用指针和数据的字节大小，将二进制数据写入文件等，ptr指针在不需要用了时，需要使用
 * bltFree模块函数将该指针对应的内存空间释放掉(zengl虚拟机内部并没有执行实际的释放，只是做了标记，下次需要分配内存时，就会直接重利用这段内存)，
 * 如果没有手动释放，则只有等到脚本结束后，由zengl虚拟机来自动释放该指针对应的内存，
 * 建议还是手动释放，因为如果脚本中有循环下载操作的话，就会导致内存越来越大，只有等脚本执行结束才能自动释放。
 *
 * 该模块函数如果执行成功，会返回0，如果执行失败，则返回相应的错误码，可以使用curlEasyStrError模块函数，来获取错误码对应的字符串类型的错误描述，
 * 例如：
	use builtin, curl, request;
	def TRUE 1;
	def FALSE 0;

	rqtSetResponseHeader("Content-Type: text/html; charset=utf-8");
	curl_handle = curlEasyInit();
	curlEasySetopt(curl_handle, 'URL', 'https://www.example.com/');
	curlEasySetopt(curl_handle, 'USERAGENT', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0');
	curlEasySetopt(curl_handle, 'FOLLOWLOCATION', TRUE);
	curlEasySetopt(curl_handle, 'SSL_VERIFYPEER', FALSE);
	curlEasySetopt(curl_handle, 'TIMEOUT', 30);
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

	如果要下载图像等二进制数据，则可以使用第四个ptr参数，例如：

	use builtin, curl, request;
	def TRUE 1;
	def FALSE 0;

	rqtSetResponseHeader("Content-Type: text/html; charset=utf-8");

	print 'curl version: ' + curlVersion();

	curl_handle = curlEasyInit();
	curlEasySetopt(curl_handle, 'URL', 'https://raw.githubusercontent.com/zenglong/zenglOX/master/screenshot/v302_1.jpg');
	curlEasySetopt(curl_handle, 'USERAGENT', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0');
	curlEasySetopt(curl_handle, 'FOLLOWLOCATION', TRUE);
	curlEasySetopt(curl_handle, 'SSL_VERIFYPEER', FALSE);
	curlEasySetopt(curl_handle, 'TIMEOUT', 30);
	ret = curlEasyPerform(curl_handle, &content, &size, &ptr);
	if(ret == 0)
		print 'size: ' + size;
		bltWriteFile('download.jpg', ptr, size);
		print 'write to <a href="download.jpg" target="_blank">download.jpg</a>';
	else
		print 'error: ' + curlEasyStrError(ret);
	endif
	curlEasyCleanup(curl_handle);
	bltFree(ptr);

	上面脚本中，在curlEasyPerform模块函数中使用了&ptr，将获取的图像数据的指针存储到ptr变量，接着就可以使用bltWriteFile模块函数，
	根据ptr指针和size图像的字节大小，将curl抓取到的图像的二进制数据写入到download.jpg文件中了。

	该模块函数在底层最终会通过curl_easy_perform库函数去执行具体的抓取操作，
	该库函数的官方地址为：https://curl.haxx.se/libcurl/c/curl_easy_perform.html
 */
ZL_EXP_VOID module_curl_easy_perform(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: curlEasyPerform(curl_handle, &content[, &size[, &ptr]]): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [curl_handle] of curlEasyPerform must be integer");
	}
	my_curl_handle_struct * my_curl_handle = (my_curl_handle_struct *)arg.val.integer;
	st_assert_curl_handle(VM_ARG, my_curl_handle, "curlEasyPerform");
	CURL * curl_handle = my_curl_handle->curl_handle;
	for(int i = 2; i <= argcount && i < 5; i++) {
		const char * arg_desces[] = {"second argument [&content]",
				"third argument [&size]",
				"fourth argument [&ptr]"};
		st_detect_arg_is_address_type(VM_ARG, i, &arg, arg_desces[i - 2], "curlEasyPerform");
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
		ZL_EXP_BOOL need_free = ZL_EXP_TRUE;
		arg.type = ZL_EXP_FAT_STR;
		arg.val.str = chunk.memory;
		zenglApi_SetFunArg(VM_ARG,2,&arg);
		if(argcount > 2) {
			arg.type = ZL_EXP_FAT_INT;
			arg.val.integer = (ZL_EXP_INT)chunk.size;
			zenglApi_SetFunArg(VM_ARG,3,&arg);
			if(argcount > 3) {
				arg.type = ZL_EXP_FAT_INT;
				arg.val.integer = (ZL_EXP_LONG)chunk.memory;
				zenglApi_SetFunArg(VM_ARG,4,&arg);
				need_free = ZL_EXP_FALSE;
				MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
				int ret_set_ptr = pointer_list_set_member(&(my_data->pointer_list), chunk.memory, (int)chunk.size, st_curl_free_ptr_callback);
				if(ret_set_ptr != 0) {
					zenglApi_Exit(VM_ARG, "curlEasyPerform add pointer to pointer_list failed, pointer_list_set_member error code:%d", ret_set_ptr);
				}
			}
		}
		if(need_free)
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
 * curlSetPostByHashArray模块函数，通过哈希数组来设置multipart/form-data类型的POST请求，
 * 该模块函数的第一个参数必须是有效的my_curl_handle_struct类型的指针，该指针由curlEasyInit模块函数返回，
 * 第二个参数hash_array是用于设置POST请求的哈希数组，数组中的每个带有字符串key的成员都对应一个POST请求的名值对信息，
 * 数组成员的字符串key将作为POST请求的name，数组成员的值将作为POST请求的值，
 * 当需要在POST请求中发送文件时，可以使用@file_path的格式来设置需要发送的文件的路径（该路径是相对于当前主执行脚本的路径），
 * 例如：@upload/upload_image.jpg 表示将 upload/upload_image.jpg 对应的文件内容通过POST请求发送出去，
 * 还可以设置发送文件的Content-Type类型，只需在路径后面跟随Content-Type类型名即可，
 * 文件路径和Content-Type类型名之间通过英文半角逗号隔开，
 * 例如：@upload/kernel_shell.png,image/png 表示需要发送的文件路径为upload/kernel_shell.png，Content-Type类型为image/png，
 *
 * 示例代码如下：

	use builtin, curl, request;
	def TRUE 1;
	def FALSE 0;

	rqtSetResponseHeader("Content-Type: text/html; charset=utf-8");

	print 'curl version: ' + curlVersion() + '<br/>';

	curl_handle = curlEasyInit();
	curlEasySetopt(curl_handle, 'URL', 'http://127.0.0.1:8084/v0_2_0/post.zl');
	curlEasySetopt(curl_handle, 'USERAGENT', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0');
	curlEasySetopt(curl_handle, 'FOLLOWLOCATION', TRUE);
	curlEasySetopt(curl_handle, 'SSL_VERIFYPEER', FALSE);
	curlEasySetopt(curl_handle, 'TIMEOUT', 30);
	data['name'] = 'zenglong';
	data['job'] = 'programmer';
	data['age'] = 30;
	data['money'] = 550.35;
	data['myjpg'] = '@upload/upload_image.jpg';
	data['mypng'] = '@upload/kernel_shell.png,image/png';
	curlSetPostByHashArray(curl_handle, data);
	ret = curlEasyPerform(curl_handle, &content);
	if(ret == 0)
		print content;
	else
		print 'error: ' + curlEasyStrError(ret);
	endif
	curlEasyCleanup(curl_handle);

	上面脚本中，先通过data数组设置需要发送的POST请求所对应的名值对信息，
	例如上面的 data['job'] = 'programmer'; 表示将要设置一个名为job，值为programmer的POST请求，
	在创建好包含名值对的哈希数组后，接着就可以通过curlSetPostByHashArray模块函数将数组中的数据和底层的curl操作指针进行绑定，
	当使用curlEasyPerform执行具体的请求操作时，就会根据这些数据来创建一个multipart/form-data类型的POST请求。

	上面脚本在执行时，会构建出类似如下所示的multipart/form-data类型的POST请求：

	POST /v0_2_0/post.zl HTTP/1.1
	................................
	Content-Type: multipart/form-data; boundary=------------------------------cb39d046a2e0
	................................

	------------------------------cb39d046a2e0
	Content-Disposition: form-data; name="name"

	zenglong
	------------------------------cb39d046a2e0
	Content-Disposition: form-data; name="job"

	programmer
	------------------------------cb39d046a2e0
	Content-Disposition: form-data; name="age"

	30
	------------------------------cb39d046a2e0
	Content-Disposition: form-data; name="money"

	550.35
	------------------------------cb39d046a2e0
	Content-Disposition: form-data; name="myjpg"; filename="upload_image.jpg"
	Content-Type: image/jpeg

	.......JFIF..............................
	.........................................
	------------------------------cb39d046a2e0
	Content-Disposition: form-data; name="mypng"; filename="kernel_shell.png"
	Content-Type: image/png

	..PNG....................................
	.........................................
	------------------------------cb39d046a2e0--

	该模块函数在底层会通过curl_formadd库函数，来进行实际的构建multipart/form-data类型的POST请求的操作，
	该库函数的官方地址：https://curl.haxx.se/libcurl/c/curl_formadd.html
 */
ZL_EXP_VOID module_curl_set_post_by_hash_array(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: curlSetPostByHashArray(curl_handle, hash_array): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [curl_handle] of curlSetPostByHashArray must be integer");
	}
	my_curl_handle_struct * my_curl_handle = (my_curl_handle_struct *)arg.val.integer;
	MAIN_DATA * my_data = st_assert_curl_handle(VM_ARG, my_curl_handle, "curlSetPostByHashArray");
	CURL * curl_handle = my_curl_handle->curl_handle;
	if(my_curl_handle->post != NULL) {
		curl_formfree(my_curl_handle->post);
		my_curl_handle->post = NULL;
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_MEMBLOCK)
		zenglApi_Exit(VM_ARG,"the second argument [hash_array] of curlSetPostByHashArray must be array");
	ZENGL_EXPORT_MOD_FUN_ARG mblk_val = {ZL_EXP_FAT_NONE,{0}};
	ZENGL_EXPORT_MEMBLOCK memblock = arg.val.memblock;
	BUILTIN_INFO_STRING infoString = { 0 };
	ZL_EXP_INT size,count,set_post_count,process_count,i;
	ZL_EXP_CHAR * key, * mblk_str;
	struct curl_httppost * last = NULL;
	zenglApi_GetMemBlockInfo(VM_ARG,&memblock,&size,ZL_EXP_NULL);
	count = zenglApi_GetMemBlockNNCount(VM_ARG, &memblock);
	set_post_count = 0;
	if(count > 0)
	{
		for(i=1,process_count=0; i<=size && process_count < count; i++)
		{
			mblk_val = zenglApi_GetMemBlock(VM_ARG,&memblock,i);
			zenglApi_GetMemBlockHashKey(VM_ARG,&memblock,i-1,&key);
			if(infoString.cur > 0 || infoString.count > 0) {
				builtin_reset_info_string(VM_ARG, &infoString);
			}
			if(key != ZL_EXP_NULL)
			{
				switch(mblk_val.type)
				{
				case ZL_EXP_FAT_INT:
					builtin_make_info_string(VM_ARG, &infoString, "%ld",mblk_val.val.integer);
					mblk_str = infoString.str;
					break;
				case ZL_EXP_FAT_FLOAT:
					builtin_make_info_string(VM_ARG, &infoString, "%.16g",mblk_val.val.floatnum);
					mblk_str = infoString.str;
					break;
				case ZL_EXP_FAT_STR:
					mblk_str = mblk_val.val.str;
					break;
				default:
					continue;
				}
				if(mblk_str[0] == '@' && strlen(mblk_str) > 1) {
					char * comma_pos = strchr(mblk_str, ',');
					char full_path[FULL_PATH_SIZE];
					if(comma_pos == NULL) {
						builtin_make_fullpath(full_path, &mblk_str[1], my_data);
						curl_formadd(&my_curl_handle->post, &last, CURLFORM_COPYNAME, key,
								CURLFORM_FILE, full_path, CURLFORM_END);
					}
					else {
						(*comma_pos) = '\0';
						builtin_make_fullpath(full_path, &mblk_str[1], my_data);
						(*comma_pos) = ',';
						char * contenttype = comma_pos + 1;
						curl_formadd(&my_curl_handle->post, &last, CURLFORM_COPYNAME, key,
								CURLFORM_FILE, full_path,
								CURLFORM_CONTENTTYPE, contenttype, CURLFORM_END);
					}
				}
				else
					curl_formadd(&my_curl_handle->post, &last, CURLFORM_COPYNAME, key,
							CURLFORM_COPYCONTENTS, mblk_str, CURLFORM_END);
				set_post_count++;
			}
		}
	}
	if(set_post_count > 0) {
		curl_easy_setopt(curl_handle, CURLOPT_HTTPPOST, my_curl_handle->post);
	}
	if(infoString.str != NULL) {
		zenglApi_FreeMem(VM_ARG, infoString.str);
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, set_post_count, 0);
}

/**
 * curlSetHeaderByArray模块函数，设置自定义的HTTP请求头，
 * 该模块函数的第一个参数必须是有效的my_curl_handle_struct类型的指针，该指针由curlEasyInit模块函数返回，
 * 第二个参数array必须是一个数组，数组中的每一项都对应一个自定义的请求头，
 * 如果自定义的请求头中只包含请求头名，而不包含对应的值时，表示如果存在该名称对应的请求头的话，就将其移除掉，
 * 例如：'Accept:' 就表示移除掉Accept请求头，
 * 当自定义的请求头名和已存在的请求头名称相同时，表示修改该请求头对应的值，
 * 例如：'Host: example.com'，表示将已存在的Host请求头的值修改为 example.com，
 * 可以设置一个空的没有值的请求头，例如: 'X-silly-header;' 表示设置一个名为X-silly-header，值为空的请求头，
 * 不过自定义这种没有值的请求头，在低版本的curl库中并不支持，例如：7.15和7.19的版本。
 *
 * 示例代码如下：

	use builtin, curl, request;
	def TRUE 1;
	def FALSE 0;

	rqtSetResponseHeader("Content-Type: text/html; charset=utf-8");

	print 'curl version: ' + curlVersion() + '<br/>';

	curl_handle = curlEasyInit();
	curlEasySetopt(curl_handle, 'URL', 'http://127.0.0.1:8084/v0_5_0/show_header.zl');
	curlEasySetopt(curl_handle, 'USERAGENT', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0');
	curlEasySetopt(curl_handle, 'FOLLOWLOCATION', TRUE);
	curlEasySetopt(curl_handle, 'SSL_VERIFYPEER', FALSE);
	curlEasySetopt(curl_handle, 'TIMEOUT', 30);
	curlSetHeaderByArray(curl_handle, bltArray('Accept:', 'Another: yes', 'Host: example.com', 'X-silly-header;'));
	ret = curlEasyPerform(curl_handle, &content);
	if(ret == 0)
		print content;
	else
		print 'error: ' + curlEasyStrError(ret);
	endif
	curlEasyCleanup(curl_handle);

	上面脚本中，通过curlSetHeaderByArray添加了一个Another: yes的请求头，移除了Accept请求头，修改了Host请求头，
	还设置了一个名为X-silly-header的值为空的请求头，该脚本的执行结果类似如下所示：

	curl version: libcurl/7.29.0 NSS/3.34 zlib/1.2.11 libidn/1.28 libssh2/1.4.3
	请求头信息：

	User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0
	Another: yes
	Host: example.com
	X-silly-header:

	该模块函数在底层会通过curl_slist_append库函数，来执行具体的构建自定义请求头的操作，
	该库函数的官方地址：https://curl.haxx.se/libcurl/c/curl_slist_append.html
 */
ZL_EXP_VOID module_curl_set_header_by_array(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: curlSetHeaderByArray(curl_handle, array): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [curl_handle] of curlSetHeaderByArray must be integer");
	}
	my_curl_handle_struct * my_curl_handle = (my_curl_handle_struct *)arg.val.integer;
	st_assert_curl_handle(VM_ARG, my_curl_handle, "curlSetHeaderByArray");
	CURL * curl_handle = my_curl_handle->curl_handle;
	if(my_curl_handle->chunk != NULL) {
		curl_slist_free_all(my_curl_handle->chunk);
		my_curl_handle->chunk = NULL;
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_MEMBLOCK)
		zenglApi_Exit(VM_ARG,"the second argument [array] of curlSetHeaderByArray must be array");
	ZENGL_EXPORT_MOD_FUN_ARG mblk_val = {ZL_EXP_FAT_NONE,{0}};
	ZENGL_EXPORT_MEMBLOCK memblock = arg.val.memblock;
	ZL_EXP_INT size,count,set_header_count,process_count,i;
	zenglApi_GetMemBlockInfo(VM_ARG,&memblock,&size,ZL_EXP_NULL);
	count = zenglApi_GetMemBlockNNCount(VM_ARG, &memblock);
	set_header_count = 0;
	if(count > 0)
	{
		for(i=1,process_count=0; i<=size && process_count < count; i++)
		{
			mblk_val = zenglApi_GetMemBlock(VM_ARG,&memblock,i);
			if(mblk_val.type == ZL_EXP_FAT_STR) {
				my_curl_handle->chunk = curl_slist_append(my_curl_handle->chunk, mblk_val.val.str);
				set_header_count++;
			}
		}
	}
	if(set_header_count > 0) {
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, my_curl_handle->chunk);
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, set_header_count, 0);
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
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlSetPostByHashArray",module_curl_set_post_by_hash_array);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlSetHeaderByArray",module_curl_set_header_by_array);
}
