/*
 * module_builtin.c
 *
 *  Created on: 2017-7-16
 *      Author: zengl
 */
#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif


#include "main.h"
#include "module_builtin.h"
#include "module_session.h"
#include "module_request.h"
/**
 * zenglServer通过crustache第三方库来解析mustache模板
 * crustache的github地址：https://github.com/vmg/crustache
 * mustache模板：https://mustache.github.io/
 * mustache模板的基本语法：https://mustache.github.io/mustache.5.html
 * 作者对crustache库代码做了一些修改(包括修复其中的bug)
 */
#include "crustache/crustache.h"
#include "crustache/buffer.h"
#include "md5.h"
#include "base64.h"
#include "fatal_error_callback.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

#define MODULE_BUILTIN_DUMP_INT 0
#define MODULE_BUILTIN_DUMP_UINT 1
#define MODULE_BUILTIN_DUMP_HEX 2
#define MODULE_BUILTIN_DUMP_CHAR 3
#define MODULE_BUILTIN_DUMP_OCTAL 4

#define WRITE_FILE_MODE_WRITE 1
#define WRITE_FILE_MODE_APPEND 2

#define GET_VERSION_STATUS_START 0
#define GET_VERSION_STATUS_IN_NUM 1

static int builtin_crustache__context_get(
		ZL_EXP_VOID * VM_ARG,
		builtin_mustache_context * new_context,
		crustache_var *var, void *ctx, const char *key, size_t key_size);

static int builtin_crustache__list_get(
		ZL_EXP_VOID * VM_ARG,
		builtin_mustache_context * new_context,
		crustache_var *var, void *list, size_t i);

static int builtin_crustache__partial(ZL_EXP_VOID * VM_ARG, crustache_template **partial, char * partial_name, size_t name_size);

// 判断是否初始化过随机种子，如果没有初始化过，则进行初始化
static __thread ZL_EXP_BOOL st_is_init_rand_seed = ZL_EXP_FALSE;

static char st_trim_mask[256];
static ZL_EXP_BOOL st_trim_mask_init = ZL_EXP_FALSE;

/**
 * crustache第三方库在解析mustache模板时，会调用的回调函数(回调函数定义在builtin模块中)
 */
crustache_api builtin_crustache__default_api = {
	builtin_crustache__context_get, // 从哈希数组之类的上下文中根据字符串key来获取对应的值的回调函数
	builtin_crustache__list_get,    // 从非哈希数组中，根据整数索引值来获取对应的值的回调函数
	NULL,
	NULL,
	builtin_crustache__partial,     // 解析partial模板语法时，会调用的回调函数
	ZL_EXP_TRUE
};

// 当使用随机数相关的模块函数时，如果没有初始化过随机种子，则使用当前的时间戳作为随机种子进行初始化，这样能让生成的伪随机数更具有随机性
static void builtin_init_rand_seed()
{
	if(!st_is_init_rand_seed) {
		time_t rawtime;
		time(&rawtime);
		srand((unsigned int)rawtime);
		st_is_init_rand_seed = ZL_EXP_TRUE;
	}
}

/**
 * 根据当前执行脚本的目录路径，加上filename文件名，来生成可以被fopen等C库函数使用的路径
 */
void builtin_make_fullpath(char * full_path, char * filename, MAIN_DATA * my_data)
{
	char * right_slash = strrchr(my_data->full_path, '/');
	if(right_slash) {
		int append_length = right_slash - my_data->full_path + 1;
		strncpy(full_path, my_data->full_path, append_length);
		append_length += main_full_path_append(full_path, append_length, FULL_PATH_SIZE, filename);
		full_path[append_length] = '\0';
	}
	else {
		char * webroot = main_get_webroot();
		int append_length = 0;
		append_length += main_full_path_append(full_path, append_length, FULL_PATH_SIZE, webroot);
		if(filename[0] != '/')
			append_length += main_full_path_append(full_path, append_length, FULL_PATH_SIZE, "/");
		append_length += main_full_path_append(full_path, append_length, FULL_PATH_SIZE, filename);
		full_path[append_length] = '\0';
	}
}

/**
 * 根据filename构建完整的模板路径，如果filename是以斜杠开头，就表示相对于webroot网站根目录的路径，否则就是相对于当前主执行脚本的路径
 */
static void builtin_template_get_fullpath(char * full_path, char * filename, MAIN_DATA * my_data)
{
	if(filename[0] == '/') {
		char * webroot = main_get_webroot();
		int append_length = 0;
		append_length += main_full_path_append(full_path, append_length, FULL_PATH_SIZE, webroot);
		append_length += main_full_path_append(full_path, append_length, FULL_PATH_SIZE, filename);
		full_path[append_length] = '\0';
	}
	else
		builtin_make_fullpath(full_path, filename, my_data);
}

/**
 * 根据full_path文件路径来获取文件的内容
 */
char * builtin_get_file_content(ZL_EXP_VOID * VM_ARG, char * full_path, char * api_name, int * arg_file_size)
{
	struct stat filestatus;
	if ( stat(full_path, &filestatus) != 0)
		zenglApi_Exit(VM_ARG,"%s stat file \"%s\" failed [%d] %s",api_name, full_path, errno, strerror(errno));
	int file_size = filestatus.st_size;
	FILE * fp = fopen(full_path, "rb");
	if (fp == NULL)
		zenglApi_Exit(VM_ARG,"%s open file \"%s\" failed [%d] %s",api_name, full_path, errno, strerror(errno));
	char * file_contents = (char *)zenglApi_AllocMem(VM_ARG, file_size + 1);
	int nread = fread(file_contents, file_size, 1, fp);
	if ( nread != 1 ) {
		fclose(fp);
		zenglApi_Exit(VM_ARG,"%s error: Unable t read content of \"%s\"", api_name, full_path);
	}
	fclose(fp);
	file_contents[file_size] = '\0';
	if(arg_file_size != NULL) {
		(*arg_file_size) = file_size;
	}
	return file_contents;
}

/**
 * 通过crustache_new第三方库函数，新建一个crustache模板
 * crustache_new会根据file_contents模板文件的内容，对其进行模板语法解析
 * 如果crustache_new返回的error的值小于0，则说明有语法错误
 * 当有语法错误时，就通过crustache_error_syntaxline，crustache_strerror之类的库函数
 * 获取具体出错的行，以及出错的原因，再将这些错误信息写入到日志中，并退出脚本
 * 如果没有语法错误，就将创建的crustache_template结构体的指针返回
 * crustache_template结构体定义在crustache目录中的crustache.c文件中
 */
static crustache_template * builtin_crustache_new_template(
		ZL_EXP_VOID * VM_ARG,
		char * file_contents,
		char * api_name,
		int file_size,
		char * full_path)
{
	crustache_template * template;
	int error = crustache_new(
			VM_ARG,
			&template,
			&builtin_crustache__default_api,
			file_contents,
			file_size);
	if (error < 0)
	{
		const char *error_line;
		size_t line_len, line_n, col_n;
		error_line = crustache_error_syntaxline(&line_n, &col_n, &line_len, template);
		char * alloc_error_str = (char *)zenglApi_AllocMem(VM_ARG, line_len + 1);
		memcpy(alloc_error_str, error_line, line_len);
		alloc_error_str[line_len] = '\0';
		if(col_n > (line_len + 1))
			col_n = line_len + 1;
		if(col_n < 1)
			col_n = 1;
		crustache_free(template);
		//zenglApi_Exit(VM_ARG, "%s error: %s (line %d, col %d)\n\t%.*s\n\t%*s\n", api_name,
		zenglApi_Exit(VM_ARG, "%s [%s] error: %s (line %d, col %d)\n\t...%s\n\t%*s\n", api_name, full_path,
				(char *)crustache_strerror(error), (int)line_n, (int)col_n,
				&alloc_error_str[col_n-1],
				4, "^");
				//(int)line_len, alloc_error_str);
				//(int)col_n, "^");
	}
	return template;
}

/**
 * 从哈希数组之类的上下文中根据字符串key来获取对应的值的回调函数
 * 例如：
 * <p><b>score: {{ score }}</b></p>
 * <p><b>money: {{ money }}$</b></p>
 * crustache在渲染{{ score }}时
 * 会调用下面这个回调函数，从上下文对应的哈希数组中根据"score"这个key去获取对应的值，并将该值渲染出来
 * 渲染{{ money }}时，则根据"money"这个key去获取相应的值进行渲染
 */
static int builtin_crustache__context_get(
		ZL_EXP_VOID * VM_ARG,
		builtin_mustache_context * new_context,
		crustache_var *var,
		void *ctx,
		const char * key,
		size_t key_size)
{
	builtin_mustache_context * context = (builtin_mustache_context *)ctx;
	switch(context->ctx.type) {
	case ZL_EXP_FAT_MEMBLOCK: // 从哈希数组中根据key来获取对应的值
		{
			char * mblk_key = (char *)key;
			char tmp = mblk_key[key_size];
			mblk_key[key_size] = '\0';
			ZENGL_EXPORT_MOD_FUN_ARG mblk_value = zenglApi_GetMemBlockByHashKey(VM_ARG, &context->ctx.val.memblock, mblk_key);
			mblk_key[key_size] = tmp;
			switch(mblk_value.type){
			case ZL_EXP_FAT_STR:
				var->type = CRUSTACHE_VAR_STR;
				var->data = (void *)mblk_value.val.str;
				var->size = strlen(mblk_value.val.str);
				break;
			case ZL_EXP_FAT_INT:
				var->type = CRUSTACHE_VAR_INTEGER;
				var->data = (void *)(&mblk_value.val.integer);
				var->size = sizeof(mblk_value.val.integer);
				break;
			case ZL_EXP_FAT_FLOAT:
				var->type = CRUSTACHE_VAR_FLOAT;
				var->data = (void *)(&mblk_value.val.floatnum);
				var->size = sizeof(mblk_value.val.floatnum);
				break;
			case ZL_EXP_FAT_MEMBLOCK: // 如果值本身又是一个数组，则将该数组作为新的上下文，可以用于渲染模板中的section
				{
					ZL_EXP_INT size;
					ZL_EXP_INT nncount;
					zenglApi_GetMemBlockInfo(VM_ARG, &mblk_value.val.memblock, &size, ZL_EXP_NULL);
					nncount = zenglApi_GetMemBlockNNCount(VM_ARG, &mblk_value.val.memblock);
					if(new_context != NULL) {
						new_context->ctx = mblk_value;
						zenglApi_GetMemBlockHashKey(VM_ARG, &mblk_value.val.memblock, 0,&mblk_key);
						if(mblk_key != ZL_EXP_NULL)
							var->type = CRUSTACHE_VAR_CONTEXT; // 包含字符串key的哈希数组
						else
							var->type = CRUSTACHE_VAR_LIST; // 只包含整数索引值的数组
						var->data = (void *)new_context;
						var->size = size;
						var->nncount = nncount; // 记录数组中包含的非NONE成员的数量
						return 0;
					}
					else
						return -1;
				}
				break;
			default:
				return -1;
			}
		}
		break;
	case ZL_EXP_FAT_INT: // 如果上下文是整数，则将{{ . }}渲染为当前整数的值
		{
			if(key_size == 1 && key[0] == '.') {
				var->type = CRUSTACHE_VAR_INTEGER;
				var->data = (void *)(&context->ctx.val.integer);
				var->size = sizeof(context->ctx.val.integer);
			}
			else
				return -1;
		}
		break;
	case ZL_EXP_FAT_FLOAT: // 如果上下文是浮点数，则将{{ . }}渲染为当前浮点数的值
		{
			if(key_size == 1 && key[0] == '.') {
				var->type = CRUSTACHE_VAR_FLOAT;
				var->data = (void *)(&context->ctx.val.floatnum);
				var->size = sizeof(context->ctx.val.floatnum);
			}
			else
				return -1;
		}
		break;
	case ZL_EXP_FAT_STR: // 如果上下文是字符串，则将{{ . }}渲染为当前字符串的值
		{
			if(key_size == 1 && key[0] == '.') {
				var->type = CRUSTACHE_VAR_STR;
				var->data = (void *)context->ctx.val.str;
				var->size = strlen(context->ctx.val.str);
			}
			else
				return -1;
		}
		break;
	default:
		return -1;
	}
	return 0;
}

/**
 * 从非哈希数组中，根据整数索引值来获取对应的值的回调函数
 */
static int builtin_crustache__list_get(
	ZL_EXP_VOID * VM_ARG,
	builtin_mustache_context * new_context,
	crustache_var *var,
	void *list,
	size_t i)
{
	builtin_mustache_context * context = (builtin_mustache_context *)list;
	ZENGL_EXPORT_MOD_FUN_ARG mblk_val;
	mblk_val = zenglApi_GetMemBlock(VM_ARG, &context->ctx.val.memblock, i+1);
	// 将值封装为新的上下文，用于渲染section中的模板内容
	switch(mblk_val.type) {
	case ZL_EXP_FAT_INT:
	case ZL_EXP_FAT_FLOAT:
	case ZL_EXP_FAT_STR:
	case ZL_EXP_FAT_MEMBLOCK:
		{
			if(new_context != NULL) {
				new_context->ctx = mblk_val;
				var->type = CRUSTACHE_VAR_CONTEXT;
				var->data = (void *)new_context;
				return 0;
			}
		}
		break;
	}
	return -1;
}

/**
 * 解析partial模板语法时，会调用的回调函数
 * 例如：
 * {{> header.tpl}}
 * 在渲染时，就会调用下面这个回调函数，将header.tpl子模板的内容读取并解析出来
 */
static int builtin_crustache__partial(ZL_EXP_VOID * VM_ARG, crustache_template **partial, char * partial_name, size_t name_size)
{
	char full_path[FULL_PATH_SIZE];
	if(name_size == 0)
		return -1;
	char tmp = partial_name[name_size];
	char * api_name = "bltMustacheFileRender";
	int file_size;
	partial_name[name_size] = '\0';
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	builtin_template_get_fullpath(full_path, partial_name, my_data);
	partial_name[name_size] = tmp;
	char * file_contents = builtin_get_file_content(VM_ARG, full_path, api_name, &file_size);
	(*partial) = builtin_crustache_new_template(VM_ARG, file_contents, api_name, file_size, full_path);
	zenglApi_FreeMem(VM_ARG, file_contents);
	return 0;
}

/**
 * 重置动态字符串的count字符数和cur当前游标，这样可以重新在该动态字符串中设置新的字符串
 */
void builtin_reset_info_string(ZL_EXP_VOID * VM_ARG, BUILTIN_INFO_STRING * infoStringPtr)
{
	infoStringPtr->count = 0;
	infoStringPtr->cur = 0;
}

/**
 * 将格式化后的字符串追加到infoStringPtr动态字符串的末尾，动态字符串会根据格式化的字符串的大小进行动态扩容
 */
void builtin_make_info_string(ZL_EXP_VOID * VM_ARG, BUILTIN_INFO_STRING * infoStringPtr, const char * format, ...)
{
	va_list arglist;
	int retcount = -1;
	if(infoStringPtr->str == NULL)
	{
		infoStringPtr->size = BUILTIN_INFO_STRING_SIZE;
		infoStringPtr->str = zenglApi_AllocMem(VM_ARG,infoStringPtr->size * sizeof(char));
	}
	do
	{
		va_start(arglist, format);
		retcount = vsnprintf((infoStringPtr->str + infoStringPtr->cur),
							(infoStringPtr->size - infoStringPtr->count), format, arglist);
		va_end(arglist);
		if(retcount >= 0 && retcount < (infoStringPtr->size - infoStringPtr->count))
		{
			infoStringPtr->count += retcount;
			infoStringPtr->cur = infoStringPtr->count;
			infoStringPtr->str[infoStringPtr->cur] = '\0';
			return;
		}

		infoStringPtr->size += BUILTIN_INFO_STRING_SIZE;
		infoStringPtr->str = zenglApi_ReAllocMem(VM_ARG, infoStringPtr->str, infoStringPtr->size * sizeof(char));
	} while(ZL_EXP_TRUE);
}

/**
 * 将zengl脚本中的数组转为json格式，并追加到infoString动态字符串
 * 如果数组中还包含了数组，那么所包含的数组在转为json时，会递归调用当前函数
 * 如果数组成员有对应的哈希key(字符串作为key)，那么生成的json会用大括号包起来
 * 例如：{"hello":"world","name":"zengl"}
 * 如果数组成员没有哈希key，那么生成的json会用中括号包起来
 * 例如：[1,2,3,3.14159,"zengl language"]
 */
static void builtin_write_array_to_string(ZL_EXP_VOID * VM_ARG, BUILTIN_INFO_STRING * infoString, ZENGL_EXPORT_MEMBLOCK memblock)
{
	ZL_EXP_INT size,count,process_count,i,j;
	ZL_EXP_CHAR * key, * mblk_str;
	ZL_EXP_CHAR * escape_str = ZL_EXP_NULL;
	// make_object用于判断是否生成对象格式的json，对象格式的json字符串会用大括号包起来，并用冒号来分隔数组成员的哈希key与值
	ZL_EXP_BOOL make_object = ZL_EXP_FALSE;
	ZENGL_EXPORT_MOD_FUN_ARG mblk_val = {ZL_EXP_FAT_NONE,{0}};
	zenglApi_GetMemBlockInfo(VM_ARG,&memblock,&size,ZL_EXP_NULL);
	count = zenglApi_GetMemBlockNNCount(VM_ARG, &memblock);
	if(count > 0)
	{
		for(i=1,process_count=0; i<=size && process_count < count; i++)
		{
			mblk_val = zenglApi_GetMemBlock(VM_ARG,&memblock,i);
			zenglApi_GetMemBlockHashKey(VM_ARG,&memblock,i-1,&key);
			switch(mblk_val.type)
			{
			case ZL_EXP_FAT_INT:
			case ZL_EXP_FAT_FLOAT:
			case ZL_EXP_FAT_STR:
			case ZL_EXP_FAT_MEMBLOCK:
				if(process_count == 0) {
					if(key != ZL_EXP_NULL) {
						builtin_make_info_string(VM_ARG, infoString, "{");
						make_object = ZL_EXP_TRUE;
					}
					else {
						builtin_make_info_string(VM_ARG, infoString, "[");
						make_object = ZL_EXP_FALSE;
					}
				}
				process_count++;
				break;
			default: // 如果是其他类型，例如NONE成员(没有被赋值初始化过的成员)，则跳过不处理
				continue;
			}
			switch(mblk_val.type)
			{
			case ZL_EXP_FAT_INT: // 对数组中的整数进行转换处理
				if(make_object) {
					if(key != ZL_EXP_NULL)
						builtin_make_info_string(VM_ARG, infoString, "\"%s\":%ld", key, mblk_val.val.integer);
					else
						builtin_make_info_string(VM_ARG, infoString, "\"%d\":%ld",i-1,mblk_val.val.integer);
				}
				else
					builtin_make_info_string(VM_ARG, infoString, "%ld",mblk_val.val.integer);
				break;
			case ZL_EXP_FAT_FLOAT: // 对数组中的浮点数进行转换处理
				if(make_object) {
					if(key != ZL_EXP_NULL)
						builtin_make_info_string(VM_ARG, infoString, "\"%s\":%.16g",key,mblk_val.val.floatnum);
					else
						builtin_make_info_string(VM_ARG, infoString, "\"%d\":%.16g",i-1,mblk_val.val.floatnum);
				}
				else
					builtin_make_info_string(VM_ARG, infoString, "%.16g",mblk_val.val.floatnum);
				break;
			case ZL_EXP_FAT_STR: // 对数组中的字符串进行处理
				// 通过strpbrk库函数来检测字符串中是否包含双引号、反斜杠、\n等需要转义的字符，如果都不包含则无需进行转义
				if(strpbrk(mblk_val.val.str, "\"\\/\b\f\n\r\t") == NULL) {
					mblk_str = mblk_val.val.str;
				}
				else {
					// 如果字符串中包含双引号等需要转义的字符，就需要先将这些字符进行转义
					session_escape_str(VM_ARG, &escape_str, mblk_val.val.str);
					mblk_str = escape_str;
				}
				if(make_object) {
					if(key != ZL_EXP_NULL)
						builtin_make_info_string(VM_ARG, infoString, "\"%s\":\"%s\"",key,mblk_str);
					else
						builtin_make_info_string(VM_ARG, infoString, "\"%d\":\"%s\"",i-1,mblk_str);
				}
				else
					builtin_make_info_string(VM_ARG, infoString, "\"%s\"",mblk_str);
				break;
			case ZL_EXP_FAT_MEMBLOCK: // 如果数组成员本身又是一个数组，那么就递归调用当前函数去生成内部数组的json格式
				if(make_object) {
					if(key != ZL_EXP_NULL)
						builtin_make_info_string(VM_ARG, infoString, "\"%s\":",key);
					else
						builtin_make_info_string(VM_ARG, infoString, "\"%d\":",i-1);
				}
				builtin_write_array_to_string(VM_ARG, infoString, mblk_val.val.memblock);
				break;
			}
			if(process_count == count)
				builtin_make_info_string(VM_ARG, infoString, "%s", (make_object ? "}" : "]")); // 如果处理完当前数组的所有成员，就用大括号或者中括号来闭合
			else
				builtin_make_info_string(VM_ARG, infoString, ","); // 数组成员之间在生成的json中用逗号分隔开
		}
		if(escape_str != ZL_EXP_NULL) { // 释放掉转义字符串所分配的内存
			zenglApi_FreeMem(VM_ARG, escape_str);
		}
	}
	else if(count == 0) { // 如果有效成员数为0，则返回[]也就是空数组
		builtin_make_info_string(VM_ARG, infoString, "[]");
	}
}

/**
 * 这是一个供其他模块函数调用的辅助函数，用于将str字符串进行html转义
 * html转义过程中，会将&替换为&amp; 将双引号替换为&quot; 将单引号替换为 &#39; 将左尖括号<替换为&lt;　将右尖括号>替换为&gt; 将斜杠替换为&#47;
 */
static void builtin_html_escape_str(ZL_EXP_VOID * VM_ARG, BUILTIN_INFO_STRING * infoString, char * str)
{
	const char * html_escape_table[] = {"", "&amp;", "&quot;", "&#39;", "&lt;", "&gt;", "&#47;"}; // &, ", ', <, >, /
	char * start = str;
	int str_len = strlen(str);
	int escape_index = 0;
	int i;
	for(i = 0; i < str_len;i++) {
		switch(str[i]) {
		case '&':
			escape_index = 1;
			break;
		case '"':
			escape_index = 2;
			break;
		case '\'':
			escape_index = 3;
			break;
		case '<':
			escape_index = 4;
			break;
		case '>':
			escape_index = 5;
			break;
		case '/':
			escape_index = 6;
			break;
		default:
			continue;
		}
		if(escape_index > 0) {
			char tmp = str[i];
			str[i] = '\0';
			builtin_make_info_string(VM_ARG, infoString, "%s%s", start, html_escape_table[escape_index]);
			str[i] = tmp;
			start = str + (i + 1);
		}
	}
	if(infoString->str != NULL) {
		if((start - str) < i) {
			builtin_make_info_string(VM_ARG, infoString, "%s", start);
		}
	}
}

static void module_builtin_free_ptr_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	zenglApi_FreeMem(VM_ARG, ptr);
}

/**
 * bltToLower和bltToUpper模块函数，最终都会通过下面这个函数来执行具体的转换大小写的操作，
 * 该函数则会通过tolower的C库函数来将所有的字符都转为小写字符，或者通过toupper的C库函数将所有的字符都转为大写字符
 */
static char * to_lower_upper(ZL_EXP_VOID * VM_ARG, char * str, ZL_EXP_BOOL is_tolower)
{
	int str_len = strlen(str);
	char * result = (char *)zenglApi_AllocMem(VM_ARG, (str_len + 1));
	for(int i = 0 ; i < str_len; i++) {
		result[i] = is_tolower ? tolower(str[i]) : toupper(str[i]);
	}
	result[str_len] = '\0';
	return result;
}

/**
 * 用于检测模块函数的某个参数是否是引用类型，
 * arg_index表示需要检测第几个参数，当arg_index为1时，表示检测第一个参数，为2时表示检测第二个参数，以此类推，
 * arg_desc存储检测到不是引用类型而报错时，参数的英文描述，例如：第二个参数一般用second argument [&...]来描述，
 * module_func_name表示进行类型检测的模块函数名，主要用于报错时进行显示
 */
void st_detect_arg_is_address_type(ZL_EXP_VOID * VM_ARG,
		int arg_index, ZENGL_EXPORT_MOD_FUN_ARG * arg_ptr, const char * arg_desc, const char * module_func_name)
{
	zenglApi_GetFunArgInfo(VM_ARG, arg_index, arg_ptr);
	switch(arg_ptr->type){
	case ZL_EXP_FAT_ADDR:
	case ZL_EXP_FAT_ADDR_LOC:
	case ZL_EXP_FAT_ADDR_MEMBLK:
		break;
	default:
		zenglApi_Exit(VM_ARG,"the %s of %s must be address type", arg_desc, module_func_name);
		break;
	}
}

/**
 * 将模块函数argnum位置对应的参数设置为指定的值
 */
static void st_set_arg_value(ZL_EXP_VOID * VM_ARG, int argnum, ZENGL_EXPORT_MOD_FUN_ARG_TYPE arg_type,
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
 * 将version_str字符串中找到的第一个数字，以整数的形式返回
 * 例如：假设version_str指向的字符串是'v12.0.5'，那么下面的C函数，就会将第一个数字12转为整数返回(也就是将主版本号返回)，同时会将version_str指向12后面的字符串'.0.5'
 * 那么，下次再将version_str指向的字符串'.0.5'传给该C函数时，就会将第一个数字0转为整数返回(也就是子版本号)，同时将version_str指向0后面的字符串'.5'
 * 最后再将version_str指向的字符串'.5'传给该函数时，就会将第一个数字5转为整数返回(从而得到修正版本号)
 * 这样通过反复将version_str传给该C函数，从而可以将'v12.0.5'字符串中的主版本号，子版本号，以及修正版本号的整数值都获取到了
 */
static int builtin_get_version_number(char ** version_str)
{
	int status = GET_VERSION_STATUS_START;
	int version = 0;
	char ch = '\0';
	for(;((ch = (*(*version_str))) != '\0');(*version_str)++) {
		switch(status) {
		case GET_VERSION_STATUS_START:
			if(ch >= '0' && ch <= '9') {
				version = (version * 10) + (ch - '0');
				status = GET_VERSION_STATUS_IN_NUM;
			}
			break;
		case GET_VERSION_STATUS_IN_NUM:
			if(ch >= '0' && ch <= '9') {
				version = (version * 10) + (ch - '0');
			}
			else {
				return version;
			}
			break;
		}
	}
	return version;
}

/**
 * 通过builtin_get_version_number函数获取version1和version2的主版本号，子版本号，修正版本号等，
 * 并依次对这些版本号进行比较，也就是version1和version2的主版本号和主版本号进行比较，子版本号和子版本号进行比较等，
 * 例如：假设version1是'v2.2.3'，version2是'v2.2.2'，那么先比较第一个主版本号，由于都是2，就再比较第二个子版本号，由于也都是2，
 * 就再比较最后一个修正版本号，由于3大于2，因此，version1大于version2
 *
 * 如果某一个分版本号没有明确提供的话，就表示该版本号是0，
 * 例如：假设version1是'v1.2.3'，version2是'v1.2'，由于'v1.2'的最后一个修正版本号未明确提供，那么该修正版本号就是0，因此，'v1.2'就相当于'v1.2.0'
 * 因此'v1.2.3'大于'v1.2'
 *
 * 最多可以比较8个分版本号
 * 例如：假设version1是'v12.11.10.9.8.7.6.5'，version2是'v12.11.10.9.8.7.6.6'进行比较，version1和version2都有8个分版本号
 * 由于version1的最后一个分版本号5小于version2的最后一个分版本号6，因此，本例中version1就小于version2
 */
static int builtin_version_compare(char * version1, char * version2)
{
	int num1 = 0;
	int num2 = 0;
	for(int i = 0;i < 8;i++) {
		num1 = builtin_get_version_number(&version1);
		num2 = builtin_get_version_number(&version2);
		if(num1 > num2)
			return 1;
		else if(num1 < num2)
			return -1;
		if((*version1) == '\0' && (*version2) == '\0') {
			return 0;
		}
	}
	return 0;
}

/**
 * bltIterArray模块函数，用于对数组成员进行迭代操作
 * 例如：
 * test['name'] = 'zengl';
 * test['job'] = 'programmer';
 * for(i=0;bltIterArray(test,&i,&k,&v);)
 * 		print k +": " + v + '<br/>';
 * endfor
 * 该脚本在浏览器中的输出结果就是(<br/>会被浏览器做换行处理)：
 * name: zengl
 * job: programmer
 *
 * 上面例子中，该模块函数的第一个参数test，是需要迭代的数组，
 * 第二个参数i是整数类型的变量的引用，用于表示需要访问的成员的索引值，
 * 该函数会将i索引位置处的名值对读取出来并分别设置到k，v参数中，所以k，v参数必须是引用，才能获取到值，
 * 如果i对应的成员是NONE类型(没有被赋予任何值)时，模块函数会跳过i，并自动往后去找有效的成员，
 * 第二个参数i之所以也是引用类型，是因为模块函数在结束时，会将下一次需要访问的索引值赋值给参数i
 *
 * 如果数组里的成员没有对应的key的话，第三个参数就会被设置为成员的整数索引值，例如：
 * test = bltArray('hello', 'world');
 * test[6] = "i'm end";
 * for(i=0;bltIterArray(test,&i,&k,&v);)
 * 		print k +": " + v + '<br/>';
 * endfor
 * 结果就是：
 * 0: hello
 * 1: world
 * 6: i'm end
 * 上面例子中hello成员的索引值为0，world的索引值为1，"i'm end"成员的索引值为6，模块函数会自动跳过索引值为2,3,4,5的成员，
 * 因为这些成员并没有被赋予具体的值，其成员类型是NONE类型
 *
 * 可以只设置三个参数，如果只设置三个参数的话，就只会将数组中的值迭代出来，例如：
 * test['name'] = 'zengl';
 * test['job'] = 'programmer';
 * for(i=0;bltIterArray(test,&i,&v);)
 * 		print v + '<br/>';
 * endfor
 * 结果会是：
 * zengl
 * programmer
 *
 * 当有成员可以进行迭代时，模块函数会返回整数1，否则返回整数0，因此，
 * 上面的for循环就可以根据，该模块函数的返回值来判断是否跳出循环，如果返回0，就跳出循环
 */
ZL_EXP_VOID module_builtin_iterate_array(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	ZL_EXP_BOOL no_index = ZL_EXP_FALSE;
	if(argcount == 3)
		no_index = ZL_EXP_TRUE;
	else if(argcount != 4)
		zenglApi_Exit(VM_ARG,"usage: bltIterArray(array, &index, &[key|curindex], &value) | bltIterArray(array, &index, &value)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	// 如果第一个参数不是数组之类的内存块，则无需迭代，直接返回0
	if(arg.type != ZL_EXP_FAT_MEMBLOCK) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		return;
	}
	ZENGL_EXPORT_MEMBLOCK memblock = {0};
	memblock = arg.val.memblock;

	zenglApi_GetFunArgInfo(VM_ARG,2,&arg);
	switch(arg.type){
	case ZL_EXP_FAT_ADDR:
	case ZL_EXP_FAT_ADDR_LOC:
	case ZL_EXP_FAT_ADDR_MEMBLK:
		break;
	default:
		zenglApi_Exit(VM_ARG,"second argument of bltIterArray must be address type");
		break;
	}

	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_INT)
		zenglApi_Exit(VM_ARG,"second argument value of bltIterArray must be integer");
	ZL_EXP_INT index = (ZL_EXP_INT)arg.val.integer;
	ZENGL_EXPORT_MOD_FUN_ARG mblk_val = {ZL_EXP_FAT_NONE,{0}};
	ZL_EXP_INT size;
	zenglApi_GetMemBlockInfo(VM_ARG,&memblock,&size, ZL_EXP_NULL);
check_index:
	if(index < 0 || index >= size) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		return;
	}
	mblk_val = zenglApi_GetMemBlock(VM_ARG,&memblock,index + 1);
	if(mblk_val.type == ZL_EXP_FAT_NONE) {
		index++;
		goto check_index;
	}

	zenglApi_GetFunArgInfo(VM_ARG,3,&arg);
	switch(arg.type){
	case ZL_EXP_FAT_ADDR:
	case ZL_EXP_FAT_ADDR_LOC:
	case ZL_EXP_FAT_ADDR_MEMBLK:
		break;
	default:
		zenglApi_Exit(VM_ARG,"the third argument of bltIterArray must be address type");
		break;
	}

	ZL_EXP_CHAR * key;
	if(no_index == ZL_EXP_FALSE) {
		zenglApi_GetMemBlockHashKey(VM_ARG,&memblock,index,&key);
		if(key != ZL_EXP_NULL) {
			arg.type = ZL_EXP_FAT_STR;
			arg.val.str = key;
			zenglApi_SetFunArg(VM_ARG,3,&arg);
		}
		else {
			arg.type = ZL_EXP_FAT_INT;
			arg.val.integer = index;
			zenglApi_SetFunArg(VM_ARG,3,&arg);
		}

		zenglApi_GetFunArgInfo(VM_ARG,4,&arg);
		switch(arg.type){
		case ZL_EXP_FAT_ADDR:
		case ZL_EXP_FAT_ADDR_LOC:
		case ZL_EXP_FAT_ADDR_MEMBLK:
			break;
		default:
			zenglApi_Exit(VM_ARG,"the forth argument of bltIterArray must be address type");
			break;
		}

		zenglApi_SetFunArg(VM_ARG,4,&mblk_val);
	}
	else {
		zenglApi_SetFunArg(VM_ARG,3,&mblk_val);
	}
	arg.type = ZL_EXP_FAT_INT;
	arg.val.integer = index + 1;
	zenglApi_SetFunArg(VM_ARG,2,&arg);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 1, 0);
}

/**
 * bltWriteFile模块函数，用于将字符串或者指针所指向的数据写入到指定的文件中
 * 例如：
 * body = rqtGetBody(&body_count, &body_source);
 * bltWriteFile('body.log', body);
 * bltWriteFile('body_source.log', body_source, body_count);
 * 该例子中，rqtGetBody会返回请求主体数据的字符串格式，同时将主体数据的字节数及指针值分别写入
 * 到body_count和body_source变量里，当然指针在zengl内部是以和指针长度一致的长整数的形式保存的，
 * 当请求主体数据中只包含字符串时，上面两个bltWriteFile写入文件的数据会是一样的，
 * 当主体数据中还包含了上传的文件时，两者就不一样了，body只会显示字符串能显示的开头的部分，直到被NULL字符阻止，
 * body_source配合body_count则可以将所有主体数据(包括上传的文件的二进制数据)都写入到文件中，
 * 从例子中可以看出，bltWriteFile模块函数既可以写入字符串，也可以写入指针指向的二进制数据
 *
 * 第一个参数filename表示需要写入的文件名(是相对于当前主执行脚本的文件路径)
 *
 * 第二个参数ptr|string表示需要写入文件的字符串，或者是指向了需要写入的二进制数据的整数类型的指针值
 *
 * 第三个参数length是可选参数(必须是整数类型)，可以设置写入数据的长度
 *  - 当没提供length参数时，或者length参数小于0时，会自动使用字符串或指针指向的二进制数据的实际可用长度
 *
 * 第四个参数mode也是可选参数(必须是整数类型)
 *  - 当mode值为1时表示从文件的开始位置处写入数据(同时会清空文件中的原有数据)，默认值就是1，也就是默认情况下，是从文件开头写入数据
 *  - 当mode值为2时表示从文件的结尾位置处写入数据(不会清空文件的原有数据，只是在原数据的基础上追加数据)
 *
 * 模块函数版本历史：
	 - v0.2.0版本新增此模块函数
	 - v0.23.0版本新增了mode可选参数，用于设置是在开头写入数据，还是在结尾追加数据
 */
ZL_EXP_VOID module_builtin_write_file(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	const char * func_name = "bltWriteFile";
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: %s(filename, ptr|string[, length[, mode]])", func_name);
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument of %s must be string", func_name);
	}
	char * filename = arg.val.str;
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	void * ptr = ZL_EXP_NULL;
	int ptr_size = 0;
	char * string = ZL_EXP_NULL;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(arg.type == ZL_EXP_FAT_STR) {
		ptr = arg.val.str;
		ptr_size = strlen(arg.val.str);
	}
	else if(arg.type == ZL_EXP_FAT_INT) {
		ptr = (void *)arg.val.integer;
		int ptr_idx = pointer_list_get_ptr_idx(&(my_data->pointer_list), ptr);
		if(ptr_idx < 0) {
			zenglApi_Exit(VM_ARG,"runtime error: the second argument [ptr] of %s is invalid pointer", func_name);
		}
		ptr_size = my_data->pointer_list.list[ptr_idx].ptr_size;
	}
	else {
		zenglApi_Exit(VM_ARG,"the second argument [ptr|string] of %s must be integer or string", func_name);
	}
	int length = ptr_size;
	int write_mode = WRITE_FILE_MODE_WRITE;
	if(argcount > 2) {
		zenglApi_GetFunArg(VM_ARG,3,&arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the third argument [length] of %s must be integer", func_name);
		}
		length = (int)arg.val.integer;
		if(length < 0 || length > ptr_size) {
			length = ptr_size;
		}
		if(argcount > 3) {
			zenglApi_GetFunArg(VM_ARG,4,&arg);
			if(arg.type != ZL_EXP_FAT_INT) {
				zenglApi_Exit(VM_ARG,"the fourth argument [mode] of %s must be integer", func_name);
			}
			write_mode = (int)arg.val.integer;
			if(write_mode != WRITE_FILE_MODE_WRITE && write_mode != WRITE_FILE_MODE_APPEND) {
				zenglApi_Exit(VM_ARG,"the fourth argument [mode] of %s must be %d(for write mode) or %d(for append mode)",
								func_name, WRITE_FILE_MODE_WRITE, WRITE_FILE_MODE_APPEND);
			}
		}
	}
	char full_path[FULL_PATH_SIZE];
	builtin_make_fullpath(full_path, filename, my_data);
	FILE * fp = NULL;
	if(write_mode == WRITE_FILE_MODE_APPEND)
		fp = fopen(full_path, "ab");
	else
		fp = fopen(full_path, "wb");
	if(fp != NULL) {
		size_t retval = fwrite(ptr, 1, length, fp);
		fclose(fp);
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)retval, 0);
	}
	else { // 如果打开文件失败，则将错误记录到日志中
		zenglApi_Exit(VM_ARG,"%s <%s> failed [%d] %s", func_name, full_path, errno, strerror(errno));
	}
}

/*bltExit模块函数，直接退出zengl脚本*/
ZL_EXP_VOID module_builtin_exit(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount > 0)
	{
		zenglApi_GetFunArg(VM_ARG,1,&arg); //得到第一个参数
		if(arg.type != ZL_EXP_FAT_STR)
		{
			zenglApi_Exit(VM_ARG,"first argument of bltExit must be string");
		}
		zenglApi_Exit(VM_ARG,arg.val.str);
	}
	else
	{
		zenglApi_Stop(VM_ARG); //如果没有参数则直接停止脚本的执行，不会产生出错信息
		return;
	}
}

/**
 * bltMustacheFileRender模块函数，渲染mustache模板
 * filename参数表示模板文件名(可以是相对于当前执行脚本的相对路径)，可选的array参数表示需要在模板中渲染的数据(一个哈希数组)
 * 例如：
 * use builtin;
 * data["val"] = "my world!";
 * data["zl"] = "welcome to zengl!";
 * schools[] = '哈佛大学';
 * schools[] = '牛津大学';
 * schools[] = '家里蹲大学';
 * data['schools'] = schools;
 * print bltMustacheFileRender("test.tpl",data);
 * 假设模板文件test.tpl的内容如下：
 * <b>hello {{val}}!</b>
 * <h3>{{ zl }}</h3>
 * {{# schools}} {{! 循环将schools里的成员显示出来}}
 *	<p>{{ . }}</p>
 * {{/ schools}}
 * 那么执行的结果类似如下所示：
 * <b>hello my world!!</b>
 * <h3>welcome to zengl!</h3>
 * <p>哈佛大学</p>
 * <p>牛津大学</p>
 * <p>家里蹲大学</p>
 */
ZL_EXP_VOID module_builtin_mustache_file_render(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltMustacheFileRender(filename[, array])");
	zenglApi_GetFunArg(VM_ARG,1,&arg); //得到第一个参数
	if(arg.type != ZL_EXP_FAT_STR)
		zenglApi_Exit(VM_ARG,"first argument filename of bltMustacheFileRender must be string");
	char * filename = arg.val.str;
	char full_path[FULL_PATH_SIZE];
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	builtin_template_get_fullpath(full_path, filename, my_data);
	int file_size;
	char * api_name = "bltMustacheFileRender";
	char * file_contents = builtin_get_file_content(VM_ARG, full_path, api_name, &file_size);
	crustache_template *template = builtin_crustache_new_template(VM_ARG, file_contents, api_name, file_size, full_path);
	zenglApi_FreeMem(VM_ARG, file_contents);
	builtin_mustache_context context = {0};
	if(argcount >= 2) {
		zenglApi_GetFunArg(VM_ARG,2,&arg);
		if(arg.type == ZL_EXP_FAT_MEMBLOCK) {
			context.ctx = arg;
		}
	}
	if(context.ctx.val.memblock.ptr == NULL) {
		if(zenglApi_CreateMemBlock(VM_ARG,&context.ctx.val.memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
	}
	crustache_var ctx;
	ctx.type = CRUSTACHE_VAR_CONTEXT;
	ctx.data = (void *)(&context);
	struct buf *output_buf = bufnew(128);
	int error = crustache_render(output_buf, template, &ctx);
	if (error < 0)
	{
		char error_node[256];
		crustache_error_rendernode(error_node, sizeof(error_node), template);
		crustache_free(template);
		bufrelease(output_buf);
		zenglApi_Exit(VM_ARG, "%s error: %s (%s)\n", api_name, (char *)crustache_strerror(error), error_node);
	}
	char * output_str = zenglApi_AllocMem(VM_ARG, output_buf->size + 1);
	memcpy(output_str, output_buf->data, output_buf->size);
	output_str[output_buf->size] = '\0';
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, output_str, 0, 0);
	crustache_free(template);
	bufrelease(output_buf);
	zenglApi_FreeMem(VM_ARG, output_str);
}

/**
 * bltJsonDecode模块函数，将字符串进行json解码
 * 例如：
 * json = '{"hello": "world!!", "name": "zengl", "val": "programmer", "arr":[1,2,3]}';
 * json = bltJsonDecode(json);
 * for(i=0; bltIterArray(json,&i,&k,&v); )
 *	if(k == 'arr')
 *		print 'arr:<br/>';
 *		for(j=0; bltIterArray(v,&j,&inner_k,&inner_v); )
 *			print ' -- ' + inner_k +": " + inner_v + '<br/>';
 *		endfor
 *	else
 *		print k +": " + v + '<br/>';
 *	endif
 * endfor
 * 执行结果如下：
 * hello: world!!
 * name: zengl
 * val: programmer
 * arr:
 * -- 0: 1
 * -- 1: 2
 * -- 2: 3
 * 上面将json字符串解码为了zengl数组
 * 第二个参数max_depth用于设置json最多解析的对象或数组的层次
 * 例如，将上面代码json = bltJsonDecode(json);修改为json = bltJsonDecode(json,1);后，执行时就会报500错误
 * 并在日志中输出 user defined error: json depth 2 is big than 1 的错误信息，也就是只能解析一层json对象或数组
 * 第三个参数max_memory用于设置json解析最多可以使用的内存，例如：
 * 将代码修改为：json = bltJsonDecode(json,2,400);表示最多解析两层json对象或数组，同时，最多只能分配400字节的内存，
 * 如果json解析时，使用的内存超过400字节时，就会报500错误，同时日志中输出
 * user defined error: bltJsonDecode error: Unable to parse data, json error: Memory allocation failure 的错误信息
 * 表示内存分配失败，这里是由于内存超出允许使用的最大值而引起的
 */
ZL_EXP_VOID module_builtin_json_decode(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltJsonDecode(str[, max_depth[, max_memory]])");
	zenglApi_GetFunArg(VM_ARG,1,&arg); //得到第一个参数
	if(arg.type != ZL_EXP_FAT_STR)
		zenglApi_Exit(VM_ARG,"first argument str of bltJsonDecode must be string");
	json_char * json = (json_char *)arg.val.str;
	json_settings settings = { 0 };
	settings.mem_alloc = my_json_mem_alloc;
	settings.mem_free = my_json_mem_free;
	settings.user_data = VM_ARG;
	settings.settings = json_enable_comments;
	unsigned int max_depth = 1000;
	if(argcount >= 2) {
		zenglApi_GetFunArg(VM_ARG,2,&arg); //得到第二个参数
		if(arg.type != ZL_EXP_FAT_INT)
			zenglApi_Exit(VM_ARG,"the second argument max_depth of bltJsonDecode must be integer");
		max_depth = (unsigned int)arg.val.integer;
		if(argcount >= 3) {
			zenglApi_GetFunArg(VM_ARG,3,&arg); //得到第三个参数
			if(arg.type != ZL_EXP_FAT_INT)
				zenglApi_Exit(VM_ARG,"the third argument max_memory of bltJsonDecode must be integer");
			settings.max_memory = (unsigned long)arg.val.integer;
		}
	}
	json_char json_error_str[json_error_max];
	json_value * value;
	size_t json_length = strlen(json);
	// 通过json-parser第三方解析程式来解析会话文件中的json数据，解析的结果是一个json_value结构
	value = json_parse_ex (&settings, json, json_length, json_error_str);
	if (value == NULL) {
		zenglApi_Exit(VM_ARG,"bltJsonDecode error: Unable to parse data, json error: %s", json_error_str);
	}
	ZENGL_EXPORT_MEMBLOCK memblock;
	switch (value->type) {
	case json_none: // 将json中的null转为整数0
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		break;
	case json_object:
	case json_array:
		// 如果是json对象或json数组，则创建一个memblock内存块
		if(zenglApi_CreateMemBlock(VM_ARG,&memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
		// 通过process_json_object_array函数，循环将value中的json成员填充到memblock中
		process_json_object_array(VM_ARG, &memblock, value, 1, max_depth);
		zenglApi_SetRetValAsMemBlock(VM_ARG,&memblock);
		break;
	case json_integer:
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)value->u.integer, 0);
		break;
	case json_double:
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_FLOAT, ZL_EXP_NULL, 0, value->u.dbl);
		break;
	case json_string:
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, value->u.string.ptr, 0, 0);
		break;
	case json_boolean: // 将json中的bool类型转为整数，例如：true转为1，false转为0
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)value->u.boolean, 0);
		break;
	default:
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		break;
	}
	json_value_free_ex (&settings, value);
}

/**
 * bltJsonEncode模块函数，将data参数进行json编码，返回json格式的字符串
 * 例如：
 * array['username'] = 'zenglong';
 * array['password'] = '123456';
 * tmp = bltArray(100,200,300,400,500,600);
 * array['tmp'] = tmp;
 * json = bltJsonEncode(array);
 * print 'array转json字符串：<br/>';
 * print json + '<br/><br/>';
 * 执行结果如下：
 * array转json字符串：
 * {"username":"zenglong","password":"123456","tmp":[100,200,300,400,500,600]}
 * 上面是数组转json的例子，对于整数，浮点数，直接返回整数和浮点数的字符串形式
 * 对于字符串类型的参数，直接将字符串的原值返回
 * 其他类型的参数都返回null字符串
 */
ZL_EXP_VOID module_builtin_json_encode(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltJsonEncode(data)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	BUILTIN_INFO_STRING infoString = { 0 };
	switch(arg.type) {
	case ZL_EXP_FAT_MEMBLOCK:
		// 通过builtin_write_array_to_string函数将zengl数组转为json格式的字符串
		builtin_write_array_to_string(VM_ARG, &infoString, arg.val.memblock);
		break;
	case ZL_EXP_FAT_INT:
		builtin_make_info_string(VM_ARG, &infoString, "%ld",arg.val.integer);
		break;
	case ZL_EXP_FAT_FLOAT:
		builtin_make_info_string(VM_ARG, &infoString, "%.16g",arg.val.floatnum);
		break;
	case ZL_EXP_FAT_STR:
		builtin_make_info_string(VM_ARG, &infoString, "%s",arg.val.str);
		break;
	default:
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, "null", 0, 0);
		return;
	}
	if(infoString.str != NULL) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, infoString.str, 0, 0);
		zenglApi_FreeMem(VM_ARG, infoString.str);
	}
	else
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, "null", 0, 0);
}

/**
 * bltMd5模块函数，获取字符串的md5值，第一个参数str是要转成md5的字符串
 * 第二个参数isLowerCase表示是否生成小写的md5值(默认值是1，也就是小写，将该参数设置为0，可以生成大写的md5值)
 * 第三个参数is32表示是否生成32位的md5值(默认值是1，也就是32位，将该参数设置为0,可以生成16位的md5值)
 * 例如：
 * def MD5_LOWER_CASE 1;
 * def MD5_UPPER_CASE 0;
 * def MD5_32BIT 1;
 * def MD5_16BIT 0;
 * print '"admin@123456"的md5值:<br/>';
 * print bltMd5('admin@123456') + ' [32位小写]<br/>';
 * print bltMd5('admin@123456', MD5_UPPER_CASE) + ' [32位大写]<br/>';
 * print bltMd5('admin@123456', MD5_LOWER_CASE, MD5_16BIT) + ' [16位小写]<br/>';
 * print bltMd5('admin@123456', MD5_UPPER_CASE, MD5_16BIT) + ' [16位大写]<br/><br/>';
 * 执行结果如下：
 * "admin@123456"的md5值:
 * f19b8dc2029cf707939e886e4b164681 [32位小写]
 * F19B8DC2029CF707939E886E4B164681 [32位大写]
 * 029cf707939e886e [16位小写]
 * 029CF707939E886E [16位大写]
 */
ZL_EXP_VOID module_builtin_md5(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltMd5(str[, isLowerCase[, is32]])");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR)
		zenglApi_Exit(VM_ARG,"first argument str of bltMd5 must be string");
	MD5_CTX md5;
	MD5Init(&md5);
	unsigned char * encrypt = (unsigned char *)arg.val.str;
	unsigned char decrypt[16];
	MD5Update(&md5,encrypt,strlen((char *)encrypt));
	MD5Final(&md5,decrypt);
	int isLowerCase = ZL_EXP_TRUE;
	int is32 = ZL_EXP_TRUE;
	if(argcount >= 2) {
		zenglApi_GetFunArg(VM_ARG,2,&arg);
		if(arg.type != ZL_EXP_FAT_INT)
			zenglApi_Exit(VM_ARG,"the second argument isLowerCase of bltMd5 must be integer");
		isLowerCase = arg.val.integer;
		if(argcount >= 3) {
			zenglApi_GetFunArg(VM_ARG,3,&arg);
			if(arg.type != ZL_EXP_FAT_INT)
				zenglApi_Exit(VM_ARG,"the third argument is32 of bltMd5 must be integer");
			is32 = arg.val.integer;
		}
	}
	char buf[33];
	char * p = buf;
	int start_idx = is32 ? 0 : 4;
	int end_idx = is32 ? 16 : 12;
	const char * format = isLowerCase ? "%02x" : "%02X";
	for(int i = start_idx; i < end_idx; i++) {
		sprintf(p, format, decrypt[i]);
		p += 2;
	}
	(*p) = '\0';
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, buf, 0, 0);
}

/**
 * bltStr模块函数，返回第一个参数的字符串形式
 * 第一个参数data|&data，表示需要转成字符串的源数据(可以是整数，浮点数之类的数据)
 * 第二个参数是可选参数
 * 	当第二个参数是整数类型时，表示isSetData即是否将转换的结果赋值给第一个参数(此时还需要将第一个参数的引用传递进来)
 * 	当第二个参数是字符串类型时，表示format即对整数或浮点数进行格式化，当第二个参数是format时，可以提供第三个可选参数来表示isSetData(是否将字符串结果赋值给第一个参数)
 *
 * 如果第一个参数的值为NONE类型，要获取他对应的字符串形式即空字符串，需要将第一个参数的引用传递过来
 * 例如：
 * use builtin;
 * print 'bltStr(test): "' + bltStr(test) + '"<br/>';
 * print 'bltStr(&amp;test): "' + bltStr(&test) + '"<br/>';
 * 执行的结果如下：
 * bltStr(test): "0"
 * bltStr(&test): ""
 * 上面test在没有被赋值的情况下，是NONE类型，NONE类型变量在参与运算或者以参数形式传递给函数时，是以整数0的形式进行运算和传递的
 * 因此，要将NONE转为空字符串返回，需要将test的引用传递进去
 * 如果将第二个参数设置为非0的整数值，bltStr会同时将转化的结果赋值给第一个参数(需要将第一个参数的引用传递进来)
 * 例如：
 * use builtin;
 * def TRUE 1;
 * def FALSE 0;
 * print 'test: "' + test + '"<br/>';
 * bltStr(&test, TRUE);
 * print 'test: "' + test + '"<br/><br/>';
 * 执行结果如下：
 * test: "0"
 * test: ""
 * 在经过bltStr(&test, TRUE);转化后，test就被赋值为了空字符串
 *
 * 当第二个参数是字符串类型时，表示format即对整数或浮点数进行格式化
 * 例如：
	use builtin;
	def TRUE 1;
	def FALSE 0;

	value = 1789.800000001;
	print bltStr(value, '%.2f');
	print bltStr(value, '%012.12f');
	print bltStr(value, '%.12E');
	print bltStr(&value, '%012.100f', TRUE);
	print 'value: ' + value + '\n';

	for(i=65;i <= 71;i++)
		print i + bltStr(i, ' - 0x%X') + bltStr(i, ' - %c');
	endfor

	上面会将浮点数进行格式化，例如：'%.2f'表示保留两位小数，此时可以把第三个参数设置为非0的整数值，来表示将转换结果赋值给第一个参数，执行结果类似如下所示：

	1789.80
	1789.800000001000
	1.789800000001E+03
	1789.80000000099994394986424595117568969726562500000000000000000000000000000000
	value: 1789.80000000099994394986424595117568969726562500000000000000000000000000000000

	65 - 0x41 - A
	66 - 0x42 - B
	67 - 0x43 - C
	68 - 0x44 - D
	69 - 0x45 - E
	70 - 0x46 - F
	71 - 0x47 - G

	模块函数版本历史：
	 - v0.8.0版本新增此模块函数
	 - v0.24.0版本增加format可选参数，用于对整数或浮点数进行格式化(格式化的语法请参考snprintf的C库函数，因为该模块函数的底层是通过snprintf来进行格式化的)
 */
ZL_EXP_VOID module_builtin_str(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltStr(data|&data[, isSetData=0]) or bltStr(data|&data[, format[, isSetData=0]])");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	int isSetData = ZL_EXP_FALSE;
	char * format = NULL;
	if(argcount >= 2) {
		ZENGL_EXPORT_MOD_FUN_ARG arg2 = {ZL_EXP_FAT_NONE,{0}};
		zenglApi_GetFunArg(VM_ARG,2,&arg2);
		if(arg2.type == ZL_EXP_FAT_INT)
			isSetData = arg2.val.integer;
		else if(arg2.type == ZL_EXP_FAT_STR)
			format = arg2.val.str;
		else
			zenglApi_Exit(VM_ARG,"the second argument of bltStr must be integer type as isSetData or string type as format");
		if(argcount >= 3 && format != NULL) {
			zenglApi_GetFunArg(VM_ARG,3,&arg2);
			if(arg2.type != ZL_EXP_FAT_INT)
				zenglApi_Exit(VM_ARG,"the third argument [isSetData] of bltStr must be integer");
			isSetData = arg2.val.integer;
		}
	}
	char * retstr;
	char tmpstr[80];
	switch(arg.type) {
	case ZL_EXP_FAT_STR:
		retstr = arg.val.str;
		break;
	case ZL_EXP_FAT_INT:
	case ZL_EXP_FAT_FLOAT:
		if(format == NULL) {
			if(arg.type == ZL_EXP_FAT_INT)
				format = "%ld";
			else
				format = "%.16g";
		}
		else if(strchr(format, '*') || strchr(format, 's')) {
			zenglApi_Exit(VM_ARG,"bltStr format error: can't use * or s in format!");
		}
		int retcount = 0;
		if(arg.type == ZL_EXP_FAT_INT)
			retcount = snprintf(tmpstr, sizeof(tmpstr), format, arg.val.integer);
		else
			retcount = snprintf(tmpstr, sizeof(tmpstr), format, arg.val.floatnum);
		if(retcount < 0) {
			zenglApi_Exit(VM_ARG,"bltStr error: %s", strerror(errno));
		}
		retstr = tmpstr;
		break;
	case ZL_EXP_FAT_MEMBLOCK:
		retstr = "[array or class obj type]";
		break;
	default:
		retstr = "";
		break;
	}
	if(isSetData) {
		if(arg.type != ZL_EXP_FAT_STR) {
			arg.type = ZL_EXP_FAT_STR;
			arg.val.str = retstr;
			zenglApi_SetFunArg(VM_ARG,1,&arg);
		}
	}
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, retstr, 0, 0);
}

/**
 * bltInt模块函数，返回第一个参数的整数形式
 * 例如：
 * test = "12345abc";
 * print 'test: ' + test + '<br/>';
 * print 'bltInt(test): ' + bltInt(test) + '<br/>';
 * 执行结果如下：
 * test: 12345abc
 * bltInt(test): 12345
 * 如果将第二个参数设置为非0值，bltInt会同时将转化的结果赋值给第一个参数(需要将第一个参数的引用传递过来)
 * 例如：
 * def TRUE 1;
 * def FALSE 0;
 * test = "12345abc";
 * print 'test: ' + test + '<br/>';
 * print 'bltInt(&amp;test, TRUE): ' + bltInt(&test, TRUE) + '<br/>';
 * print 'test: ' + test + '<br/><br/>';
 * 执行结果如下：
 * test: 12345abc
 * bltInt(&test, TRUE): 12345
 * test: 12345
 * 在经过bltInt(&test, TRUE);转化后，test就被转为了整数
 */
ZL_EXP_VOID module_builtin_int(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltInt(data|&data[, isSetData=0])");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	int isSetData = ZL_EXP_FALSE;
	if(argcount >= 2) {
		ZENGL_EXPORT_MOD_FUN_ARG arg2 = {ZL_EXP_FAT_NONE,{0}};
		zenglApi_GetFunArg(VM_ARG,2,&arg2);
		if(arg2.type != ZL_EXP_FAT_INT)
			zenglApi_Exit(VM_ARG,"the second argument isSetData of bltInt must be integer");
		isSetData = arg2.val.integer;
	}
	ZL_EXP_LONG retval;
	switch(arg.type) {
	case ZL_EXP_FAT_STR:
		retval = atol((const char *)arg.val.str);
		break;
	case ZL_EXP_FAT_INT:
		retval = arg.val.integer;
		break;
	case ZL_EXP_FAT_FLOAT:
		retval = (ZL_EXP_LONG)arg.val.floatnum;
		break;
	default:
		retval = 0;
		break;
	}
	if(isSetData) {
		if(arg.type != ZL_EXP_FAT_INT) {
			arg.type = ZL_EXP_FAT_INT;
			arg.val.integer = retval;
			zenglApi_SetFunArg(VM_ARG,1,&arg);
		}
	}
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, retval, 0);
}

/**
 * bltFloat模块函数，返回第一个参数的浮点数形式
 * 例如：
 * test2 = "3.14159mdbknf";
 * print 'test2: ' + test2 + '<br/>';
 * print 'bltFloat(test2): ' + bltFloat(test2) + '<br/>';
 * 执行结果如下：
 * test2: 3.14159mdbknf
 * bltFloat(test2): 3.14159
 * 如果将第二个参数设置为非0值，bltFloat会同时将转化的结果赋值给第一个参数(需要将第一个参数的引用传递过来)
 * def TRUE 1;
 * def FALSE 0;
 * test2 = "3.14159mdbknf";
 * print 'test2: ' + test2 + '<br/>';
 * print 'bltFloat(&amp;test2, TRUE): ' + bltFloat(&test2, TRUE) + '<br/>';
 * print 'test2: ' + test2 + '<br/><br/>';
 * 执行结果如下：
 * test2: 3.14159mdbknf
 * bltFloat(&test2, TRUE): 3.14159
 * test2: 3.14159
 * 在经过bltFloat(&test2, TRUE);转化后，test2就被转为了浮点数
 */
ZL_EXP_VOID module_builtin_float(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltFloat(data|&data[, isSetData=0])");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	int isSetData = ZL_EXP_FALSE;
	if(argcount >= 2) {
		ZENGL_EXPORT_MOD_FUN_ARG arg2 = {ZL_EXP_FAT_NONE,{0}};
		zenglApi_GetFunArg(VM_ARG,2,&arg2);
		if(arg2.type != ZL_EXP_FAT_INT)
			zenglApi_Exit(VM_ARG,"the second argument isSetData of bltFloat must be integer");
		isSetData = arg2.val.integer;
	}
	ZL_EXP_DOUBLE retfloat;
	switch(arg.type) {
	case ZL_EXP_FAT_STR:
		retfloat = atof((const char *)arg.val.str);
		break;
	case ZL_EXP_FAT_INT:
		retfloat = (ZL_EXP_DOUBLE)arg.val.integer;
		break;
	case ZL_EXP_FAT_FLOAT:
		retfloat = arg.val.floatnum;
		break;
	default:
		retfloat = 0;
		break;
	}
	if(isSetData) {
		if(arg.type != ZL_EXP_FAT_FLOAT) {
			arg.type = ZL_EXP_FAT_FLOAT;
			arg.val.floatnum = retfloat;
			zenglApi_SetFunArg(VM_ARG,1,&arg);
		}
	}
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_FLOAT, ZL_EXP_NULL, 0, retfloat);
}

/**
 * bltCount模块函数，获取数组的有效成员数，或者获取字符串的有效长度
 */
ZL_EXP_VOID module_builtin_count(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltCount(data)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	int retcount;
	switch(arg.type) {
	case ZL_EXP_FAT_STR:
		retcount = strlen(arg.val.str);
		break;
	case ZL_EXP_FAT_MEMBLOCK:
		retcount = zenglApi_GetMemBlockNNCount(VM_ARG, &arg.val.memblock);
		break;
	default:
		retcount = 0;
		break;
	}
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, retcount, 0);
}

/**
 * bltGetZenglServerVersion模块函数，获取zenglServer的版本号
 */
ZL_EXP_VOID module_builtin_get_zengl_server_version(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	ZENGL_EXPORT_MEMBLOCK memblock;
	if(zenglApi_CreateMemBlock(VM_ARG,&memblock,0) == -1) {
		zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
	}
	arg.type = ZL_EXP_FAT_INT;
	arg.val.integer = ZLSERVER_MAJOR_VERSION;
	zenglApi_SetMemBlock(VM_ARG,&memblock,1,&arg);
	arg.val.integer = ZLSERVER_MINOR_VERSION;
	zenglApi_SetMemBlock(VM_ARG,&memblock,2,&arg);
	arg.val.integer = ZLSERVER_REVISION;
	zenglApi_SetMemBlock(VM_ARG,&memblock,3,&arg);
	zenglApi_SetRetValAsMemBlock(VM_ARG,&memblock);
}

/**
 * bltGetZenglVersion模块函数，获取zengl语言的版本号
 */
ZL_EXP_VOID module_builtin_get_zengl_version(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	ZENGL_EXPORT_MEMBLOCK memblock;
	if(zenglApi_CreateMemBlock(VM_ARG,&memblock,0) == -1) {
		zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
	}
	arg.type = ZL_EXP_FAT_INT;
	arg.val.integer = ZL_EXP_MAJOR_VERSION;
	zenglApi_SetMemBlock(VM_ARG,&memblock,1,&arg);
	arg.val.integer = ZL_EXP_MINOR_VERSION;
	zenglApi_SetMemBlock(VM_ARG,&memblock,2,&arg);
	arg.val.integer = ZL_EXP_REVISION;
	zenglApi_SetMemBlock(VM_ARG,&memblock,3,&arg);
	zenglApi_SetRetValAsMemBlock(VM_ARG,&memblock);
}

/**
 * bltHtmlEscape模块函数，将字符串进行html转义，并将转义的结果返回
 * html转义过程中，会将&替换为&amp; 将双引号替换为&quot; 将单引号替换为 &#39; 将左尖括号<替换为&lt;　将右尖括号>替换为&gt;
 * 例如：
 * test3 = '大家好&"\'<html></html>&&&';
 * print 'bltHtmlEscape(test3): ' +bltHtmlEscape(test3) + '<br/>';
 * 执行结果如下：
 * bltHtmlEscape(test3): 大家好&amp;&quot;&#39;&lt;html&gt;&lt;/html&gt;&amp;&amp;&amp;<br/>
 * 如果将第二个参数设置为非0值，bltHtmlEscape会同时将转化的结果赋值给第一个参数(需要将第一个参数的引用传递过来)
 * 例如：
 * use builtin;
 * def TRUE 1;
 * def FALSE 0;
 * test3 = '大家好&"\'<html></html>&&&';
 * print 'bltHtmlEscape(&amp;test3, TRUE): ' + bltHtmlEscape(&test3, TRUE) + '<br/>';
 * print 'test3: ' + test3 + '<br/><br/>';
 * 执行结果如下：
 * bltHtmlEscape(&amp;test3, TRUE): 大家好&amp;&quot;&#39;&lt;html&gt;&lt;/html&gt;&amp;&amp;&amp;<br/>
 * test3: 大家好&amp;&quot;&#39;&lt;html&gt;&lt;/html&gt;&amp;&amp;&amp;<br/><br/>
 */
ZL_EXP_VOID module_builtin_html_escape(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltHtmlEscape(str|&str[, isSetData=0])");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	int isSetData = ZL_EXP_FALSE;
	if(argcount >= 2) {
		ZENGL_EXPORT_MOD_FUN_ARG arg2 = {ZL_EXP_FAT_NONE,{0}};
		zenglApi_GetFunArg(VM_ARG,2,&arg2);
		if(arg2.type != ZL_EXP_FAT_INT)
			zenglApi_Exit(VM_ARG,"the second argument isSetData of bltHtmlEscape must be integer");
		isSetData = arg2.val.integer;
	}
	BUILTIN_INFO_STRING infoString = { 0 };
	switch(arg.type) {
	case ZL_EXP_FAT_STR:
		builtin_html_escape_str(VM_ARG, &infoString, arg.val.str);
		break;
	case ZL_EXP_FAT_INT: // 整数直接返回原值
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, arg.val.integer, 0);
		return;
	case ZL_EXP_FAT_FLOAT: // 浮点数直接返回原值
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_FLOAT, ZL_EXP_NULL, 0, arg.val.floatnum);
		return;
	case ZL_EXP_FAT_MEMBLOCK: // 数组之类的内存块也直接返回原内存块
		zenglApi_SetRetValAsMemBlock(VM_ARG,&arg.val.memblock);
		return;
	default: // 其他类型统一设置为空字符串
		builtin_make_info_string(VM_ARG, &infoString, "");
		break;
	}
	if(infoString.str != NULL) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, infoString.str, 0, 0);
		if(isSetData) {
			arg.type = ZL_EXP_FAT_STR;
			arg.val.str = infoString.str;
			zenglApi_SetFunArg(VM_ARG,1,&arg);
		}
		zenglApi_FreeMem(VM_ARG, infoString.str);
	}
	else
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, arg.val.str, 0, 0);
}

/**
 * bltDate模块函数，将时间戳转为字符串格式返回
 * 第一个参数format表示需要生成的字符串格式，第二个可选参数timestamp表示需要进行转换的时间戳，如果没有提供第二个参数，则默认使用当前时间对应的时间戳
 * 例如：
 * print bltDate('%Y-%m-%d %H:%M:%S') + '<br/>';
 * print bltDate('%Y-%m-%d %H:%M:%S', 574210255)+ '<br/>';
 * 执行结果如下：
 * 2018-06-18 10:53:28
 * 1988-03-13 06:50:55
 * 上面第一个语句中，没有提供第二个参数，则使用当前时间戳。第二个语句中第二个参数574210255时间戳对应的日期时间是：1988-03-13 06:50:55
 * 由于该模块函数底层是使用strftime来生成格式化字符串的，因此，具体的格式是由strftime来决定的，例如：%Y表示年，%m表示月等
 * 可以使用man strftime来查看具体有哪些格式
 */
ZL_EXP_VOID module_builtin_date(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltDate(format[, timestamp])");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [format] of bltDate must be string");
	}
	char * format = arg.val.str;
	time_t rawtime;
	if(argcount > 1) {
		zenglApi_GetFunArg(VM_ARG,2,&arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the second argument [timestamp] of bltDate must be integer");
		}
		rawtime = (time_t)arg.val.integer;
	}
	else {
		time(&rawtime);
	}
	struct tm * timeinfo;
	char buffer[128];
	timeinfo = localtime(&rawtime);
	size_t ret = strftime (buffer,sizeof(buffer), format,timeinfo);
	if(ret == 0) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, "", 0, 0);
	}
	else {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, buffer, 0, 0);
	}
}

/**
 * bltMkdir模块函数，根据指定的路径，创建目录
 * 第一个参数path表示相对于当前执行脚本的路径，该模块函数将根据该路径来创建目录，第二个可选参数file_mode表示创建目录的读写执行权限
 * 例如：
 * use builtin;
 * def TRUE 1;
 * def FALSE 0;
 * path = 'tmpdir';
 * if(bltMkdir(path, 0e777) == TRUE)
 *	print 'mkdir ' + path + ' success!' + '<br/>';
 * else
 *	print 'the ' + path + ' exists, no need real mkdir' + '<br/>';
 * endif
 * 上面这段脚本在执行后，将在当前执行脚本的目录中创建一个名为tmpdir的子目录，如果tmpdir已经存在，则bltMkdir模块函数会返回0
 * 上面脚本中bltMkdir的第二个参数0e777是一个八进制值，表示需要创建的目录的读写执行权限是rwxrwxrwx，也就是所有用户都可以操作该目录
 */
ZL_EXP_VOID module_builtin_mkdir(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltMkdir(path[, file_mode])");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [path] of bltMkdir must be string");
	}
	char full_path[FULL_PATH_SIZE];
	char * filename = arg.val.str;
	mode_t file_mode;
	if(argcount > 1) {
		zenglApi_GetFunArg(VM_ARG,2,&arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the second argument [file_mode] of bltMkdir must be integer");
		}
		file_mode = (mode_t)arg.val.integer;
	}
	else {
		file_mode = 0755;
	}
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	builtin_make_fullpath(full_path, filename, my_data);
	struct stat st = {0};
	if (stat(full_path, &st) == -1) {
		if(mkdir(full_path, file_mode) != 0) {
			zenglApi_Exit(VM_ARG,"bltMkdir <%s> failed [%d] %s", full_path, errno, strerror(errno));
		}
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
	}
	else
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
}

/**
 * bltUnlink模块函数，删除指定路径对应的文件
 * 该模块函数的第一个参数path表示相对于当前执行脚本的路径，如果path对应的文件存在，且具有权限，则模块函数会将该文件给删除掉
 * 例如：
 * bltUnlink('thumb.jpg');
 * 上面脚本中，如果thumb.jpg存在，则将其删除，如果文件不存在则直接返回0
 * 该模块函数只能用于删除常规文件，不可以删除目录
 */
ZL_EXP_VOID module_builtin_unlink(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltUnlink(path)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [path] of bltUnlink must be string");
	}
	char full_path[FULL_PATH_SIZE];
	char * filename = arg.val.str;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	builtin_make_fullpath(full_path, filename, my_data);
	struct stat st = {0};
	if (stat(full_path, &st) == -1)
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
	else {
		if(unlink(full_path) != 0) {
			zenglApi_Exit(VM_ARG,"bltUnlink <%s> failed [%d] %s", full_path, errno, strerror(errno));
		}
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
	}
}

/**
 * bltFileExists模块函数，检测指定路径的文件是否存在
 * 该模块函数的第一个参数path表示相对于当前执行脚本的路径，如果path对应的文件存在，则返回1，否则返回0
 * 例如：
 * file = 'thumb.jpg';
 * if(bltFileExists(file))
 *	bltUnlink(file);
 *	print 'unlink ' + file + ' success!' + '<br/>';
 * else
 *	print file + ' not exists, no need real unlink' + '<br/>';
 * endif
 * 上面脚本在执行时，如果bltFileExists模块函数检测到thumb.jpg文件存在，则会将该文件删除，并提示unlink thumb.jpg success!
 * 如果文件不存在，则bltFileExists模块函数会返回0，并提示thumb.jpg not exists, no need real unlink
 * bltFileExists模块函数还可以检测目录是否存在
 */
ZL_EXP_VOID module_builtin_file_exists(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltFileExists(path)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [path] of bltFileExists must be string");
	}
	char full_path[FULL_PATH_SIZE];
	char * filename = arg.val.str;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	builtin_make_fullpath(full_path, filename, my_data);
	struct stat st = {0};
	int retval = stat(full_path, &st);
	if (retval == -1) {
		if(errno == ENOENT)
			zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
		else
			zenglApi_Exit(VM_ARG,"bltFileExists <%s> failed [%d] %s", full_path, errno, strerror(errno));
	}
	else if(retval == 0)
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
	else
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
}

/**
 * bltOutputBlob模块函数，直接将二进制数据输出到客户端
 * 该模块函数的第一个参数blob为字节指针，指向需要输出的二进制数据。第二个参数length表示二进制数据的字节大小
 *  从v0.22.0版本开始，第一个参数blob还可以是字符串类型，如果是字符串类型，则会将字符串输出到客户端，之前版本一直用print指令输出字符串到客户端，但是
 *  print指令会在末尾自动添加换行符，而bltOutputBlob模块函数在输出字符串到客户端时，只会原样输出字符串信息，不会在后面加换行符之类的
 *
 * 例如：
 * output = magickGetImageBlob(wand, &length); // 获取图像的二进制数据
 * rqtSetResponseHeader("Content-Type: image/" + magickGetImageFormat(wand));
 * bltOutputBlob(output, length); // 输出二进制数据
 *
 * 上面代码片段中，先通过magickGetImageBlob获取图像的二进制数据和二进制数据的长度(以字节为单位的大小)，
 * 接着就可以通过bltOutputBlob模块函数将图像的二进制数据输出到客户端
 *
 * use builtin;
 * retval = 'success';
 * bltOutputBlob(retval, -1);
 *
 * 上面代码片段会将retval对应的字符串'success'输出到客户端，并且不会在末尾加换行符，也就是将参数原样输出
 * 当第二个参数小于0时，例如上面设置的-1时，该模块函数会自动根据第一个参数的长度来进行输出
 *
 * 模块函数版本历史：
 *  - v0.12.0版本新增此模块函数
 *  - v0.22.0版本中第一个参数可以是字符串类型，此外，当第二个参数小于0时，会自动判断第一个参数的长度
 */
ZL_EXP_VOID module_builtin_output_blob(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: bltOutputBlob(blob|str, length)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT && arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [blob|str] of bltOutputBlob must be integer or string");
	}
	ZL_EXP_BOOL is_blob_ptr = ZL_EXP_TRUE;
	char * blob = NULL;
	if(arg.type == ZL_EXP_FAT_INT)
		blob = (char *)arg.val.integer;
	else {
		blob = arg.val.str;
		is_blob_ptr = ZL_EXP_FALSE;
	}
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int ptr_size = 0;
	if(is_blob_ptr) {
		int ptr_idx = pointer_list_get_ptr_idx(&(my_data->pointer_list), blob);
		if(ptr_idx < 0) {
			zenglApi_Exit(VM_ARG,"runtime error: the first argument [blob] of bltOutputBlob is invalid pointer");
		}
		ptr_size = my_data->pointer_list.list[ptr_idx].ptr_size;
	}
	else {
		ptr_size = (int)strlen(blob);
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the second argument [length] of bltOutputBlob must be integer");
	}
	int length = arg.val.integer;
	if(length < 0 || length > ptr_size) {
		length = ptr_size;
	}
	dynamic_string_append(&my_data->response_body, blob, length, RESPONSE_BODY_STR_SIZE);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, length, 0);
}

/**
 * bltRandomStr模块函数，根据指定的字符序列和长度，生成随机的字符串
 * 第一个参数str表示用于生成随机字符串的字符序列，第二个参数length表示需要生成的随机字符串的长度
 * 例如：
 * captcha = bltRandomStr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 6);
 * 上面代码执行后可以得到一个包含字母和数字的长度为6的随机字符串
 */
ZL_EXP_VOID module_builtin_random_str(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: bltRandomStr(str, length): string");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [str] of bltRandomStr must be string");
	}
	char * charset = arg.val.str;
	int str_len = strlen(charset);
	if(str_len <= 0) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, "", 0, 0);
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the second argument [length] of bltRandomStr must be integer");
	}
	int length = arg.val.integer;
	if(length <= 0) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, "", 0, 0);
	}
	char * dest = (char *)zenglApi_AllocMem(VM_ARG, (length + 1));
	builtin_init_rand_seed();
	int next_seed = 0;
	for(int i = 0; i < length;i++) {
		next_seed = rand();
		int index = (double) next_seed / RAND_MAX * (str_len - 1);
		dest[i] = charset[index];
	}
	srand((unsigned int)next_seed);
	dest[length] = '\0';
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, dest, 0, 0);
	zenglApi_FreeMem(VM_ARG, dest);
}

/**
 * bltRand模块函数，根据指定的最小值和最大值，得到这两个值之间的随机整数
 * 该模块函数的第一个参数min表示可能生成的随机数的最小值，第二个参数max表示可能生成的最大值
 * 例如：bltRand( 0, 30 ) 将返回0到30之间的随机数
 */
ZL_EXP_VOID module_builtin_rand(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: bltRand(min, max): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [min] of bltRand must be integer");
	}
	int min = arg.val.integer;
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the second argument [max] of bltRand must be integer");
	}
	int max = arg.val.integer;
	builtin_init_rand_seed();
	int next_seed = rand();
	int retval = ((double) next_seed / RAND_MAX * (max - min)) + min;
	srand((unsigned int)next_seed);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, retval, 0);
}

/**
 * bltUtfStrLen模块函数，计算utf8字符串的长度，主要用于计算有多少个utf8编码的汉字
 * 第一个参数str是需要计算长度的字符串
 * 例如：
 * len = bltUtfStrLen('世界s你好！abcd');
 * 上面代码返回的结果会是10，其中有5个汉字和5个英文字母
 * 具体的计算方法来源于下面这个链接
 * https://stackoverflow.com/questions/32936646/getting-the-string-length-on-utf-8-in-c
 */
ZL_EXP_VOID module_builtin_utf_str_len(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltUtfStrLen(str): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [str] of bltUtfStrLen must be string");
	}
	char * s = arg.val.str;
	int count = 0;
	while (*s) {
		count += (*s++ & 0xC0) != 0x80;
	}
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, count, 0);
}

/**
 * bltStrLen模块函数，以字节为单位计算字符串的长度，第一个参数str是要计算长度的字符串
 * 例如：len = bltStrLen('世界s你好！abcd'); 返回的结果会是20，由于一个utf8编码的汉字包含3个字节，5个汉字就是15个字节，再加上5个英文字母，返回的长度就是20
 * 该模块函数是直接调用底层的strlen的C库函数来计算长度的
 */
ZL_EXP_VOID module_builtin_str_len(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltStrLen(str): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [str] of bltStrLen must be string");
	}
	char * s = arg.val.str;
	int count = strlen(s);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, count, 0);
}

/**
 * bltStrReplace模块函数，可以用于执行字符串的替换操作
 * 第一个参数str表示源字符串，第二个参数search是要搜索的子字符串，第三个参数replace表示要进行替换的字符串，最后一个可选参数isSetData表示是否将替换后的结果设置到第一个参数
 * 默认情况下isSetData是0，也就是只返回替换的结果，不会设置第一个参数，如果isSetData是不为0的整数值，则会将替换的结果设置到第一个参数(第一个参数需要是引用类型，才能设置成功)
 * 例如：
 * use builtin;
 * def TRUE 1;
 * str = '世界s你好！abcd';
 * print bltStrReplace(&str, 'abcd', 'hello world!', TRUE) + '<br/>';
 * print str + '<br/>';
 * 上面脚本执行的结果会是：
 * 世界s你好！hello world!
 * 世界s你好！hello world!
 * 上面将str中的abcd替换为了hello world!，同时由于bltStrReplace模块函数的最后一个参数设置为了TRUE(也就是1)，
 * 因此，源字符串str也被设置为了替换后的字符串：世界s你好！hello world!
 */
ZL_EXP_VOID module_builtin_str_replace(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 3)
		zenglApi_Exit(VM_ARG,"usage: bltStrReplace(str|&str, search, replace[, isSetData=0]): string");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [str] of bltStrReplace must be string");
	}
	char * str = arg.val.str;
	if(strlen(str) == 0) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, "", 0, 0);
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [search] of bltStrReplace must be string");
	}
	char * search = arg.val.str;
	if(strlen(search) == 0) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, str, 0, 0);
	}
	zenglApi_GetFunArg(VM_ARG,3,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the third argument [replace] of bltStrReplace must be string");
	}
	char * replace = arg.val.str;
	char * point = NULL;
	char * start = str;
	int replace_len = strlen(replace);
	int search_len = strlen(search);
	int isSetData = ZL_EXP_FALSE;
	if(argcount >= 4) {
		zenglApi_GetFunArg(VM_ARG,4,&arg);
		if(arg.type != ZL_EXP_FAT_INT)
			zenglApi_Exit(VM_ARG,"the fourth argument isSetData of bltStrReplace must be integer");
		isSetData = arg.val.integer;
	}
	BUILTIN_INFO_STRING infoString = { 0 };
	while((point = strstr(start, search)) != NULL) {
		char old_char = point[0];
		point[0] = '\0';
		builtin_make_info_string(VM_ARG, &infoString, "%s",start);
		if(replace_len > 0) {
			builtin_make_info_string(VM_ARG, &infoString, "%s", replace);
		}
		point[0] = old_char;
		start = point + search_len;
	}
	if(infoString.str != NULL) {
		if((*start) != '\0') { // 拷贝剩余的字符
			builtin_make_info_string(VM_ARG, &infoString, "%s",start);
		}
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, infoString.str, 0, 0);
		if(isSetData) {
			arg.type = ZL_EXP_FAT_STR;
			arg.val.str = infoString.str;
			zenglApi_SetFunArg(VM_ARG,1,&arg);
		}
		zenglApi_FreeMem(VM_ARG, infoString.str);
	}
	else
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, str, 0, 0);
}

/**
 * bltIsNone模块函数，检测某个变量是否是NONE类型(未初始化时的类型)，需要将变量的引用作为第一个参数传递进来
 * 如果变量被初始化过了，则返回0，如果没有被初始化过，也就是没有被设置过具体的类型(例如整数，浮点数，字符串等)，则返回1
 * 例如：
 * str = '世界s你好！abcd';
 * print 'bltIsNone(&str): ' + (bltIsNone(&str) ? 'TRUE' : 'FALSE')  + '<br/>';
 * print 'bltIsNone(&test): ' + (bltIsNone(&test) ? 'TRUE' : 'FALSE');
 * 上面脚本执行的结果会是：
 * bltIsNone(&str): FALSE
 * bltIsNone(&test): TRUE
 * 由于str被初始化为了字符串，因此，str变量不是NONE类型，test变量没有被初始化过，所以是NONE类型
 */
ZL_EXP_VOID module_builtin_is_none(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltIsNone(&data): integer");
	zenglApi_GetFunArgInfo(VM_ARG,1,&arg);
	switch(arg.type){
	case ZL_EXP_FAT_ADDR:
	case ZL_EXP_FAT_ADDR_LOC:
	case ZL_EXP_FAT_ADDR_MEMBLK:
		break;
	default:
		zenglApi_Exit(VM_ARG,"the first argument [data] of bltIsNone must be address type");
		break;
	}
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type == ZL_EXP_FAT_NONE)
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
	else
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
}

/**
 * bltFree模块函数，用于释放掉zengl脚本中分配的指针资源
 * 某些模块函数会分配一些指针以供调用者使用，
 * 例如，curl模块的curlEasyPerform模块函数，当提供了&ptr参数时，
 * 就会在内部分配一个指针，该指针指向的内存空间中存储了curl抓取到的数据，当抓取到的数据是jpg，png之类的图像等的二进制数据时，
 * 脚本中就可以利用指针将这些二进制数据写入文件，从而可以将curl下载的图像数据保存为文件，
 * 当这些指针不再需要使用时，可以用bltFree模块函数将其释放掉，如果没有使用该模块函数进行释放，
 * 在脚本退出时，zengl虚拟机也会自动清理这些指针
 *
 * 该模块函数的第一个参数ptr表示需要释放的指针，在zengl脚本中，指针其实就是一个整数，该整数代表了指针所指向的内存地址
 */
ZL_EXP_VOID module_builtin_free(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltFree(ptr): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [ptr] of bltFree must be integer");
	}
	ZL_EXP_VOID * ptr = (ZL_EXP_VOID *)arg.val.integer;
	if(ptr != NULL) {
		MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
		int ptr_idx = pointer_list_get_ptr_idx(&(my_data->pointer_list), ptr);
		if(ptr_idx >= 0) {
			pointer_list_remove_member(VM_ARG, &(my_data->pointer_list), ptr, ZL_EXP_TRUE);
		}
	}
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
}

/**
 * bltReadFile模块函数，根据文件名读取文件内容
 * 该模块函数的第一个参数filename表示需要读取的文件的文件名，该文件名是一个相对于当前主执行脚本的路径，
 * 第二个&content参数必须是引用类型，用于存储读取的文件内容，
 * 第三个&size参数是可选的，当提供了该参数时，也必须是引用类型，用于存储文件的字节大小，
 * 第四个&ptr参数也是可选的，当提供了该参数时，也必须是引用类型，用于存储数据指针，该指针指向了文件内容对应的二进制数据(通常用于图像文件，加密数据文件等，这些文件的内容是一些二进制数据)
 * 该模块函数如果执行成功会返回整数0，执行失败则返回小于0的值，当返回值为-1时表示文件不存在，返回值为-2时表示无法打开文件，
 * 例如：
	use builtin;
	ret = bltReadFile('cookies.txt', &file_content, &file_size);
	if(ret == 0)
		print 'cookies.txt file size: ' + file_size;
		print 'file content: \n' + file_content;
	else
		print 'read cookies.txt failed, maybe the file does not exists, or open failed.';
	endif
 * 上面这段代码会将cookies.txt文件的内容读取到file_content变量，同时将该文件的字节大小存储到file_size变量
 */
ZL_EXP_VOID module_builtin_read_file(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: bltReadFile(filename, &content[, &size[, &ptr]]): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [filename] of bltReadFile must be string");
	}
	char * filename = arg.val.str;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	char full_path[FULL_PATH_SIZE];
	builtin_make_fullpath(full_path, filename, my_data);
	for(int i = 2; i <= argcount && i < 4; i++) {
		const char * arg_desces[] = {"second argument [&content]",
				"third argument [&size]"};
		st_detect_arg_is_address_type(VM_ARG, i, &arg, arg_desces[i - 2], "bltReadFile");
	}
	int file_size;
	struct stat filestatus;
	if ( stat(full_path, &filestatus) != 0) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, -1, 0);
		return;
	}
	file_size = filestatus.st_size;
	FILE * fp = fopen(full_path, "rb");
	if (fp == NULL) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, -2, 0);
		return;
	}
	char * file_contents = (char *)zenglApi_AllocMem(VM_ARG, (file_size+1));
	int nread = fread(file_contents, file_size, 1, fp);
	if ( nread != 1 ) {
		fclose(fp);
		zenglApi_Exit(VM_ARG,"bltReadFile error: Unable to read content of \"%s\"", filename);
	}
	fclose(fp);
	file_contents[file_size] = '\0';
	arg.type = ZL_EXP_FAT_STR;
	arg.val.str = file_contents;
	zenglApi_SetFunArg(VM_ARG,2,&arg);
	ZL_EXP_BOOL need_ptr = ZL_EXP_TRUE;
	if(argcount > 2) {
		arg.type = ZL_EXP_FAT_INT;
		arg.val.integer = file_size;
		zenglApi_SetFunArg(VM_ARG,3,&arg);
		if(argcount > 3) {
			arg.type = ZL_EXP_FAT_INT;
			arg.val.integer = (ZL_EXP_LONG)file_contents;
			zenglApi_SetFunArg(VM_ARG,4,&arg);
			int ret_set_ptr = pointer_list_set_member(&(my_data->pointer_list), file_contents, file_size, module_builtin_free_ptr_callback);
			if(ret_set_ptr != 0) {
				zenglApi_Exit(VM_ARG, "bltReadFile add pointer to pointer_list failed, pointer_list_set_member error code:%d", ret_set_ptr);
			}
			need_ptr = ZL_EXP_FALSE;
		}
	}
	if(need_ptr)
		zenglApi_FreeMem(VM_ARG, file_contents);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
}

/**
 * bltIsRunInCmd模块函数，判断当前脚本是否是在命令行中运行
 * 返回整数1则表示在命令行中运行，否则就不是命令行模式
 * 例如：
 * if(bltIsRunInCmd())
 		bltSetImmediatePrint(TRUE);
 		print 'now in cmd';
   else
 		print 'must be run in cmd';
 		bltExit();
   endif
 */
ZL_EXP_VOID module_builtin_is_run_in_cmd(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	ZL_EXP_BOOL arg_is_run_in_cmd;
	main_check_is_run_in_cmd(&arg_is_run_in_cmd);
	if(arg_is_run_in_cmd) // 返回整数1则表示在命令行中运行，否则就不是命令行模式
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 1, 0);
	else
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
}

/**
 * bltSetImmediatePrint模块函数，在命令行模式下开启或关闭立即打印模式
 * 该模块函数的第一个参数is_immediate_print表示是否开启立即打印模式，如果是不为0的整数就表示开启，否则表示关闭
 * 在立即打印模式中，命令行下运行的脚本在使用print指令输出信息时，会立即输出到命令行终端
 * 示例代码，参考上面的bltIsRunInCmd模块函数的示例
 */
ZL_EXP_VOID module_builtin_set_immediate_print(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltSetImmediatePrint(is_immediate_print): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [is_immediate_print] of bltSetImmediatePrint must be integer");
	}
	ZL_EXP_BOOL arg_is_immediate_print = ZL_EXP_FALSE;
	if(arg.val.integer) {
		arg_is_immediate_print = ZL_EXP_TRUE;
	}
	main_set_is_immediate_print(arg_is_immediate_print);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
}

/**
 * bltSleep模块函数，让当前线程睡眠一段时间
 * 该模块函数的第一个参数seconds表示睡眠多少秒
 * 例如：
 * for(i=1; i <= maxsec; i++)
 		print 'I\'ll sleep for ' + i + ' seconds';
 		bltSleep(i);
   endfor
 */
ZL_EXP_VOID module_builtin_sleep(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltSleep(seconds): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [seconds] of bltSleep must be integer");
	}
	ZL_EXP_LONG retval = (ZL_EXP_LONG)sleep((unsigned int)arg.val.integer);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, retval, 0);
}

/**
 * bltDumpPtrData模块函数，以十进制，十六进制，八进制等形式显示出指针所指向的二进制数据
 * 第一个ptr必须是整数类型的数据指针，每个数据指针(和资源指针不同)都会记录在内部的pointer_list列表中，不在该列表中的指针都是无效的数据指针
 * 第二个参数ptr_data_len必须是整数类型，表示需要将该指针所指向的多少字节的数据给显示出来，每个数据指针所指向的数据都有一个尺寸，超出尺寸的数据不会被显示出来
 * 第三个参数format也必须是整数类型，表示以什么格式来显示二进制数据
 *  - 当format为0时，表示以十进制整数显示出来，可能是负数
 *  - 当format为1时，表示以十进制无符号整数显示出来，没有负数
 *  - 当format为2时，表示以十六进制格式显示出来
 *  - 当format为3时，表示以ASCII字符形式显示出来
 *  - 当format为4时，表示以八进制格式显示出来
 *
 * 例如：
	use builtin;
	def DUMP_HEX 2;

	........................ // 省略中间代码

	bltReadFile('private_enc.data', &file_data, &file_size, &file_data_ptr);
	print file_name + ' - size:' + file_size;
	print file_name + ' - data:' + bltDumpPtrData(file_data_ptr, file_size, DUMP_HEX);

	上面代码片段，将文件数据读取出来，并将file_data_ptr设置为指向这些数据的指针，最后通过bltDumpPtrData根据file_data_ptr指针，将这些数据以十六进制格式显示出来

	以上代码片段的执行结果类似如下所示：

	private_enc.data - size:1024
	private_enc.data - data:C4 CC 02 82 F3 2D 83 F6 B7 40 4F EC 38 03 82 54 65 63 AD FE 0C 8D AF 82 98 A7 7C 79 EE ......................
 */
ZL_EXP_VOID module_builtin_dump_ptr_data(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 3)
		zenglApi_Exit(VM_ARG,"usage: bltDumpPtrData(ptr, ptr_data_len, format): string");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT && arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [ptr] of bltDumpPtrData must be integer or string");
	}
	unsigned char * ptr = NULL;
	ZL_EXP_BOOL is_ptr_str = ZL_EXP_FALSE;
	if(arg.type == ZL_EXP_FAT_INT)
		ptr = (unsigned char *)arg.val.integer;
	else {
		ptr = (unsigned char *)arg.val.str;
		is_ptr_str = ZL_EXP_TRUE;
	}
	int ptr_size = 0;
	if(!is_ptr_str) {
		MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
		int ptr_idx = pointer_list_get_ptr_idx(&(my_data->pointer_list), ptr);
		if(ptr_idx < 0) {
			zenglApi_Exit(VM_ARG,"runtime error: the first argument [ptr] of bltDumpPtrData is invalid pointer");
		}
		ptr_size = my_data->pointer_list.list[ptr_idx].ptr_size;
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the second argument [ptr_data_len] of bltDumpPtrData must be integer");
	}
	int ptr_data_len = (int)arg.val.integer;
	if(ptr_data_len < 0)
		ptr_data_len = 0;
	if(is_ptr_str) {
		if(ptr_data_len > strlen((char *)ptr))
			ptr_data_len = strlen((char *)ptr);
	}
	else if(ptr_size > 0 && ptr_data_len > ptr_size) {
		ptr_data_len = ptr_size;
	}
	zenglApi_GetFunArg(VM_ARG,3,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the third argument [format] of bltDumpPtrData must be integer");
	}
	int format = arg.val.integer;
	BUILTIN_INFO_STRING infoString = { 0 };
	int i;
	for(i = 0; i < ptr_data_len; i++) {
		switch (format) {
		case MODULE_BUILTIN_DUMP_INT:
			builtin_make_info_string(VM_ARG, &infoString, "%03d ", (int)ptr[i]);
			break;
		case MODULE_BUILTIN_DUMP_UINT:
			builtin_make_info_string(VM_ARG, &infoString, "%03u ", (unsigned int)ptr[i]);
			break;
		case MODULE_BUILTIN_DUMP_HEX:
			builtin_make_info_string(VM_ARG, &infoString, "%02X ", (unsigned int)ptr[i]);
			break;
		case MODULE_BUILTIN_DUMP_OCTAL:
			builtin_make_info_string(VM_ARG, &infoString, "%03o ", (unsigned int)ptr[i]);
			break;
		case MODULE_BUILTIN_DUMP_CHAR:
			builtin_make_info_string(VM_ARG, &infoString, "%c ", (unsigned char)ptr[i]);
			break;
		default:
			zenglApi_Exit(VM_ARG,"the third argument [format] of bltDumpPtrData is invalid number");
			break;
		}
	}
	if(infoString.str != NULL) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, infoString.str, 0, 0);
		zenglApi_FreeMem(VM_ARG, infoString.str);
	}
	else
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, "", 0, 0);
}

/**
 * bltBase64Encode模块函数，对数据进行base64编码
 * 第一个参数data必须是字符串，或者是整数类型的数据指针
 * 第二个参数data_len是可选参数，当提供了该参数时，必须是整数类型，表示需要编码的data数据的尺寸大小，默认值是-1，表示自动检测data的尺寸大小
 * 返回值是将data数据经过了base64编码后的字符串
 * 例如：
	use builtin;
	def TRUE 1;

	encode_str = bltBase64Encode("hello world");
	print encode_str;

	上面脚本使用bltBase64Encode来对hello world字符串进行base64编码

	use builtin;
	def TRUE 1;

	encode_str = bltBase64Encode("hello world", 4);
	print encode_str;

	上面代码片段，在提供了第二个参数4后，就只会对hello world的前4个字符进行base64编码

	use builtin,openssl;

	def RSA_PUBLIC 1;
	def RSA_PRIVATE 0;

	def DUMP_HEX 2;

	...................................................

	key = read_rsa_key('rsa_public.key', RSA_PUBLIC);
	p_key = read_rsa_key('rsa_private.key', RSA_PRIVATE);

	print 'source string:' + (src_str = "hello world! I'm a programmer!") + br;
	enc_len = opensslPrivateEncrypt(src_str, -1, p_key, &enc);
	print 'encrypt: ' + bltDumpPtrData(enc, enc_len, DUMP_HEX) + br;
	print 'encrypt base64 encode: ' + (encode = bltBase64Encode(enc)) + br;

	以上代码片段，通过将数据指针enc传递给bltBase64Encode，从而对openssl加密后的二进制数据进行base64编码
 */
ZL_EXP_VOID module_builtin_base64_encode(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	const char * func_name = "bltBase64Encode";
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: %s(data[, data_len = -1]): string", func_name);
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
	int data_len = -1;
	if(argcount > 1) {
		zenglApi_GetFunArg(VM_ARG,2,&arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the second argument [data_len] of %s must be integer", func_name);
		}
		data_len = (int)arg.val.integer;
	}
	if(data_len < 0) {
		if(is_data_str) {
			data_len = (int)strlen((char *)data);
		}
		else {
			data_len = data_ptr_size;
		}
	}
	if(data_ptr_size > 0 && data_len > data_ptr_size) {
		data_len = data_ptr_size;
	}
	if(data_len > 0) {
		unsigned int encode_len = b64e_size(data_len) + 1;
		unsigned char * encode_str = malloc((sizeof(char) * encode_len));
		encode_len = b64_encode(data, (unsigned int)data_len, encode_str);
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, (char *)encode_str, 0, 0);
		free(encode_str);
	}
	else {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, "", 0, 0);
	}
}

/**
 * bltBase64Decode模块函数，对数据进行base64解码
 * 第一个参数data表示需要解码的base64编码，必须是字符串类型
 * 第二个参数result必须是引用类型，用于存储base64解码后的结果
 * 第三个参数decode_to_str是可选的，必须是整数类型，表示是否将第二个result参数转为字符串类型，默认为0表示不转为字符串，因此，默认情况下，result存储的会是整数类型的数据指针
 * 	如果decode_to_str的值为1则result存储的会是字符串类型的结果
 * 返回值表示result结果的字节长度
 * 例如：
	use builtin;
	def TRUE 1;

	encode_str = bltBase64Encode("hello world");
	print encode_str;

	decode_len = bltBase64Decode(encode_str, &decode, TRUE);
	print 'decode_len: ' + decode_len;
	print 'decode: ' + decode;

	上面代码片段先将hello world字符串进行base64编码，接着通过bltBase64Decode模块函数将编码的字符串进行解码，同时将解码的结果转为字符串类型(通过将第三个参数设置为1)

	use builtin,openssl;
	def RSA_PUBLIC 1;
	def RSA_PRIVATE 0;
	def RSA_PKCS1_PADDING 0;

	def DUMP_HEX 2;

	.................................................................

	key = read_rsa_key('rsa_public.key', RSA_PUBLIC);
	p_key = read_rsa_key('rsa_private.key', RSA_PRIVATE);

	print 'source string:' + (src_str = "hello world! I'm a programmer!") + br;
	enc_len = opensslPrivateEncrypt(src_str, -1, p_key, &enc);
	print 'encrypt: ' + bltDumpPtrData(enc, enc_len, DUMP_HEX) + br;
	print 'encrypt base64 encode: ' + (encode = bltBase64Encode(enc)) + br;

	decode_len = bltBase64Decode(encode, &decode);
	print 'decode_len: ' + decode_len + br;
	print 'decode: ' + bltDumpPtrData(decode, decode_len, DUMP_HEX) + br;

	dec_len = opensslPublicDecrypt(decode, decode_len, key, &dec, RSA_PKCS1_PADDING, TRUE);
	print 'decrypt string: ' + dec + br;

	以上代码片段先将openssl加密后的二进制数据进行base64编码，接着通过bltBase64Decode将编码数据进行解码，从而获取到原始的加密二进制数据，最后通过openssl模块函数
	将二进制数据解密为原始的字符串值
 */
ZL_EXP_VOID module_builtin_base64_decode(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	const char * func_name = "bltBase64Decode";
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: %s(data, &result[, decode_to_str = 0]): integer", func_name);
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [data] of %s must be string", func_name);
	}
	unsigned char * data = (unsigned char *)arg.val.str;
	int data_len = (int)strlen((char *)data);
	if(data_len > 0) {
		st_detect_arg_is_address_type(VM_ARG, 2, &arg, "second argument [&result]", func_name);
		int result_size = b64d_size(data_len);
		unsigned char * result = (unsigned char *)zenglApi_AllocMem(VM_ARG, (sizeof(char) * result_size) +1);
		memset(result, 0, ((sizeof(char) * result_size) +1));
		int result_len = b64_decode(data, (unsigned int)data_len, result);
		int decode_to_str = 0;
		if(argcount > 2) {
			zenglApi_GetFunArg(VM_ARG,3,&arg);
			if(arg.type != ZL_EXP_FAT_INT) {
				zenglApi_Exit(VM_ARG,"the third argument [decode_to_str] of %s must be integer", func_name);
			}
			decode_to_str = (int)arg.val.integer;
		}
		if(decode_to_str) {
			st_set_arg_value(VM_ARG, 2, ZL_EXP_FAT_STR, (char *)result, 0);
			zenglApi_FreeMem(VM_ARG, result);
		}
		else {
			st_set_arg_value(VM_ARG, 2, ZL_EXP_FAT_INT, NULL, (ZL_EXP_LONG)result);
			MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
			int ret_set_ptr = pointer_list_set_member(&(my_data->pointer_list), result, result_len, module_builtin_free_ptr_callback);
			if(ret_set_ptr != 0) {
				zenglApi_Exit(VM_ARG, "%s add pointer to pointer_list failed, pointer_list_set_member error code:%d", func_name, ret_set_ptr);
			}
		}
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, result_len, 0);
	}
	else {
		st_set_arg_value(VM_ARG, 2, ZL_EXP_FAT_INT, NULL, 0);
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
	}
}

/**
 * bltUrlEncode模块函数，对字符串参数进行url编码
 * 第一个参数str表示需要进行url编码的字符串
 * 返回值是将str参数经过url编码后的结果字符串
 * 例如：
	use builtin;

	str = 'hello world!世界你好！ 我是zengl!';

	print '\nurl encode:' + (enc_str = bltUrlEncode(str));

	上面代码片段会将str变量对应的字符串'hello world!世界你好！ 我是zengl!'进行url编码，并将编码后的结果打印出来，执行结果如下：

	url encode:hello+world%21%E4%B8%96%E7%95%8C%E4%BD%A0%E5%A5%BD%EF%BC%81+%E6%88%91%E6%98%AFzengl%21

	url编码时，a-zA-Z0-9以及. - * _会保持不变，空格符会转为+号，其他字符会转为%加字节值的ASCII形式，例如0xE4字节会转为%E4等

	模块函数版本历史：
	 - v0.22.0版本新增此模块函数
 */
ZL_EXP_VOID module_builtin_url_encode(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	const char * func_name = "bltUrlEncode";
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: %s(str): str", func_name);
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [str] of %s must be string", func_name);
	}
	char * str = (char *)arg.val.str;
	int str_len = (int)strlen(str);
	int encode_size = sizeof(char) * str_len * 3 + 1;
	char * encode_str = (char *)zenglApi_AllocMem(VM_ARG, encode_size);
	memset(encode_str, 0, encode_size);
	const char * hex = "0123456789ABCDEF";
	int pos = 0;
	for (int i = 0; i < str_len; i++) {
		if (('a' <= str[i] && str[i] <= 'z')
			|| ('A' <= str[i] && str[i] <= 'Z')
			|| ('0' <= str[i] && str[i] <= '9')
			|| str[i] == '.' || str[i] == '-' || str[i] == '*' || str[i] == '_') {
				encode_str[pos++] = str[i];
			} else if (str[i] == ' ') {
				encode_str[pos++] = '+';
			}else {
				encode_str[pos++] = '%';
				encode_str[pos++] = hex[(unsigned char)str[i] >> 4];
				encode_str[pos++] = hex[(unsigned char)str[i] & 0xF];
			}
	}
	encode_str[pos] = '\0';
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, encode_str, 0, 0);
	zenglApi_FreeMem(VM_ARG, encode_str);
}

/**
 * bltUrlDecode模块函数，将参数进行url解码
 * 第一个参数str必须是字符串类型，表示经过了url编码的字符串
 * 返回值是将参数str经过url解码后的字符串
 * 示例：
	use builtin;

	str = 'hello world!世界你好！ 我是zengl!';

	print '\nurl encode:' + (enc_str = bltUrlEncode(str));

	print '\nurl decode:' + bltUrlDecode(enc_str) + '\n';

	上面代码片段会先将字符串'hello world!世界你好！ 我是zengl!'进行url编码，再将其解码，并将编解码的结果打印出来，执行结果如下：

	url encode:hello+world%21%E4%B8%96%E7%95%8C%E4%BD%A0%E5%A5%BD%EF%BC%81+%E6%88%91%E6%98%AFzengl%21

	url decode:hello world!世界你好！ 我是zengl!

	模块函数版本历史：
	 - v0.22.0版本新增此模块函数
 */
ZL_EXP_VOID module_builtin_url_decode(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	const char * func_name = "bltUrlDecode";
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: %s(str): str", func_name);
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [str] of %s must be string", func_name);
	}
	char * str = (char *)arg.val.str;
	int str_len = (int)strlen(str);
	int decode_size = sizeof(char) * str_len + 1;
	char * decode_str = (char *)zenglApi_AllocMem(VM_ARG, decode_size);
	memset(decode_str, 0, decode_size);
	gl_request_url_decode(decode_str, str, str_len);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, decode_str, 0, 0);
	zenglApi_FreeMem(VM_ARG, decode_str);
}

/**
 * bltTrim模块函数，去除字符串左右两侧的指定字符
 * 第一个参数str必须是字符串类型，表示需要进行操作的源字符串
 * 第二个参数chars是可选参数，也必须是字符串类型，表示需要去除哪些字符，默认值为' \t\n\r\v'，表示需要去除字符串左右两侧的空格符，\t(tab制表符)，\n(换行符)等
 *  - chars字符串中的每个字符都会被去除掉
 * 第三个参数mode也是可选参数，必须是整数类型，表示去除模式，有三种模式：
 *  - 当mode参数的值为1时，表示只去除字符串左侧的字符
 *  - 当mode参数的值为2时，表示只去除字符串右侧的字符
 *  - 当mode参数的值为3时，表示左右两侧的字符都要去除掉，mode的默认值就是3，也就是左右两侧的字符都会被去除掉
 *
 * 返回值：此模块函数会将处理后(也就是去除了左右两侧的指定字符)的字符串作为结果返回
 *
 * 示例：
 * 	use builtin;
	def TRIM_LEFT 1;
	def TRIM_RIGHT 2;
	def TRIM_BOTH 3;

	test = '
		hello world !!!!!
	  ';

	print 'test: ' + test;
	print '----------------------------------------';
	print '[bltTrim(test)]: ' + '[' + bltTrim(test) + ']';
	print '----------------------------------------';
	print "[bltTrim(test, ' \\n\\t', TRIM_LEFT)]: " + '[' + bltTrim(test, ' \n\t', TRIM_LEFT) + ']';
	print '----------------------------------------';
	print "[bltTrim(test, ' \\n\\t', TRIM_RIGHT)]: " + '[' + bltTrim(test, ' \n\t', TRIM_RIGHT) + ']';
	print '----------------------------------------';
	print '[bltTrim("  hahahaha~~~~  ", \' \', TRIM_BOTH)]: ' + '[' + bltTrim("  hahahaha~~~~  ", ' ', TRIM_BOTH) + ']';
	print '----------------------------------------';

	以上代码对三种模式都进行了测试，执行结果类似如下所示：

	test:
		hello world !!!!!

	----------------------------------------
	[bltTrim(test)]: [hello world !!!!!]
	----------------------------------------
	[bltTrim(test, ' \n\t', TRIM_LEFT)]: [hello world !!!!!
	  ]
	----------------------------------------
	[bltTrim(test, ' \n\t', TRIM_RIGHT)]: [
		hello world !!!!!]
	----------------------------------------
	[bltTrim("  hahahaha~~~~  ", ' ', TRIM_BOTH)]: [hahahaha~~~~]
	----------------------------------------

	上面的bltTrim(test)表示将test字符串变量左右两侧的空格符，换行符等都去除掉，
	bltTrim(test, ' \n\t', TRIM_LEFT)表示只将test左侧的空格符，换行符，回车符去除掉
	bltTrim(test, ' \n\t', TRIM_RIGHT)表示只将test右侧的空格符，换行符，回车符去除掉
	bltTrim("  hahahaha~~~~  ", ' ', TRIM_BOTH)表示将"  hahahaha~~~~  "字符串左右两侧的' '(空格符)给去除掉

	模块函数版本历史：
	 - v0.23.0版本新增此模块函数
 */
ZL_EXP_VOID module_builtin_trim(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	const char * func_name = "bltTrim";
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: %s(str[, chars = ' \t\n\r\v'[, mode = 3]]): str", func_name);
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [str] of %s must be string", func_name);
	}
	char * str = (char *)arg.val.str;
	int str_len = strlen(str);
	char * chars = " \t\n\r\v";
	int chars_len = strlen(chars);
	int mode = 3;
	if(argcount > 1) {
		zenglApi_GetFunArg(VM_ARG,2,&arg);
		if(arg.type != ZL_EXP_FAT_STR) {
			zenglApi_Exit(VM_ARG,"the second argument [chars] of %s must be string", func_name);
		}
		chars = (char *)arg.val.str;
		chars_len = strlen(chars);
		if(argcount > 2) {
			zenglApi_GetFunArg(VM_ARG,3,&arg);
			if(arg.type != ZL_EXP_FAT_INT) {
				zenglApi_Exit(VM_ARG,"the third argument [mode] of %s must be integer", func_name);
			}
			mode = (int)arg.val.integer;
		}
	}
	char * start = str;
	char * end = (str_len > 0) ? (str + str_len) : str;
	if (chars_len <= 0) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, str, 0, 0);
		return;
	}
	if(!st_trim_mask_init) {
		memset(st_trim_mask, 0, 256);
		st_trim_mask_init = ZL_EXP_TRUE;
	}
	unsigned char c;
	for(int i = 0; i < chars_len ;i++) {
		c = (unsigned char)chars[i];
		st_trim_mask[c] = 1;
	}

	if(mode & 1) {
		while(start != end) {
			if(st_trim_mask[(unsigned char)*start])
				start++;
			else
				break;
		}
	}
	if(mode & 2) {
		while(start != end) {
			if(st_trim_mask[(unsigned char)*(end-1)])
				end--;
			else
				break;
		}
	}

	for(int i = 0; i < chars_len ;i++) {
		c = (unsigned char)chars[i];
		st_trim_mask[c] = 0;
	}

	char orig_end_char = *end;
	*end = '\0';
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, start, 0, 0);
	*end = orig_end_char;
}

/**
 * bltFatalErrorCallback模块函数，设置当发生严重的运行时错误时，需要执行的脚本中的回调函数名，如果是类中定义的方法，还可以设置相关的类名
 * 第一个参数function_name表示需要设置的脚本中的回调函数名(必须是字符串类型，且不能为空字符串)
 * 第二个参数class_name是可选参数，表示需要设置的类名(也必须是字符串类型，如果第一个参数function_name是某个类中定义的方法的话，就可以通过此参数来设置类名)
 * 		- 默认值是空字符串，表示不设置类名，当需要跳过该参数设置第三个default_cmd_action参数时，也可以手动传递空字符串来表示不设置类名
 * 第三个参数default_cmd_action也是可选的，表示在命令行模式下，当执行完运行时错误回调函数后，是否还需要执行默认的输出错误信息到命令行的动作，
 * 		- 默认值为1，表示需要执行默认动作，如果脚本回调函数里已经将错误信息输出到了命令行的话，就可以将该参数设置为0，表示不需要再执行默认动作了
 *
 * 示例：
	use builtin;
	def WRITE_MODE 1;
	def APPEND_MODE 2;
	def TRUE 1;
	def FALSE 0;
	def DEFAULT_LEN -1;

	fun fatal_error(error, stack)
		print '\n hahaha fatal error [' + bltDate('%Y-%m-%d %H:%M:%S') + ']: \n' + error + ' backtrace: \n' + stack + '\n';
		bltWriteFile('fatal_error.log', bltDate('%Y-%m-%d %H:%M:%S') + ' - ' + error + ' backtrace: \n' + stack + '\n', DEFAULT_LEN, APPEND_MODE);
	endfun

	bltFatalErrorCallback('fatal_error', '', FALSE);

	class Test
		fun test()
			a = bltTestHa();
		endfun
	endclass

	Test.test();

	以上代码会将fatal_error脚本函数设置为运行时错误回调函数，当脚本准备执行bltTestHa函数时，由于bltTestHa函数没有被定义过，也不属于有效的模块函数，
	因此，在执行bltTestHa函数时就会发生运行时错误，此时就会调用上面的fatal_error脚本函数来处理该运行时错误，zenglServer会将错误信息和函数栈追踪信息
	以参数的形式传递给fatal_error脚本函数，也就是上面的error及stack参数，其中error表示具体的错误信息，stack表示发生错误时的脚本函数栈追踪信息，
	上面在fatal_error脚本回调函数中，在将错误信息和函数栈追踪信息通过print打印出来后，还会将这些信息写入到fatal_error.log日志文件中

	上面这段脚本的执行结果类似如下所示：

	hahaha fatal error [2020-10-24 21:55:44]:

	err: run func err , function 'bltTestHa' is invalid pc=89 (解释器运行时错误：函数'bltTestHa'无效)

	source code info: [ bltTestHa ] 17:7 <'my_webroot/v0_23_0/test_fatal_error.zl'>
	backtrace:
	my_webroot/v0_23_0/test_fatal_error.zl:17 Test:test
	my_webroot/v0_23_0/test_fatal_error.zl:21

	模块函数版本历史：
	 - v0.23.0版本新增此模块函数
 */
ZL_EXP_VOID module_builtin_fatal_error_callback(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	const char * func_name = "bltFatalErrorCallback";
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: %s(function_name[, class_name[, default_cmd_action]])", func_name);
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [function_name] of %s must be string", func_name);
	}
	char * function_name = (char *)arg.val.str;
	if(strlen(function_name) == 0) {
		zenglApi_Exit(VM_ARG,"the first argument [function_name] of %s can't be empty", func_name);
	}
	// 在设置运行时错误回调函数名之前，先将之前可能设置过的回调函数相关的函数名，类名等重置为默认值，可以防止受到之前设置的影响
	fata_error_free_all_ptrs();
	fatal_error_set_function_name(function_name);
	char * class_name = NULL;
	if(argcount > 1) {
		zenglApi_GetFunArg(VM_ARG,2,&arg);
		if(arg.type != ZL_EXP_FAT_STR) {
			zenglApi_Exit(VM_ARG,"the second argument [class_name] of %s must be string", func_name);
		}
		class_name = (char *)arg.val.str;
		if(strlen(class_name) > 0) {
			fatal_error_set_class_name(class_name);
		}
		if(argcount > 2) {
			zenglApi_GetFunArg(VM_ARG,3,&arg);
			if(arg.type != ZL_EXP_FAT_INT) {
				zenglApi_Exit(VM_ARG,"the third argument [default_cmd_action] of %s must be integer", func_name);
			}
			fatal_error_set_default_cmd_action((int)arg.val.integer);
		}
	}
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
}

/**
 * bltToLower模块函数，将字符串转为小写，并将转换的结果返回给调用者
 * 第一个参数str必须是字符串类型，表示需要进行转换的源字符串
 *
 * 示例：
	use builtin,request;

	headers = rqtGetHeaders();
	for(i=0; bltIterArray(headers,&i,&k,&v); )
		print k +": " + v + '<br/>';
		lowers[bltToLower(k)] = bltToLower(v);
	endfor

	print '=============================================<br/>lowers: <br/>';

	for(i=0; bltIterArray(lowers,&i,&k,&v); )
		print k +": " + v + '<br/>';
	endfor

	执行的结果类似如下：

	Host: 192.168.1.113:8083
	User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:81.0) Gecko/20100101 Firefox/81.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9
	Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
	Accept-Encoding: gzip, deflate
	Connection: keep-alive
	Upgrade-Insecure-Requests: 1
	=============================================
	lowers:
	host: 192.168.1.113:8083
	user-agent: mozilla/5.0 (windows nt 10.0; win64; x64; rv:81.0) gecko/20100101 firefox/81.0
	accept: text/html,application/xhtml+xml,application/xml;q=0.9
	accept-language: zh-cn,zh;q=0.8,zh-tw;q=0.7,zh-hk;q=0.5,en-us;q=0.3,en;q=0.2
	accept-encoding: gzip, deflate
	connection: keep-alive
	upgrade-insecure-requests: 1

	可以看到经过bltToLower转换后，所有的字符都转为了小写字符

	模块函数版本历史：
	 - v0.23.0版本新增此模块函数
 */
ZL_EXP_VOID module_builtin_to_lower(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	const char * func_name = "bltToLower";
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: %s(str)", func_name);
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [str] of %s must be string", func_name);
	}
	char * str = (char *)arg.val.str;
	char * result = to_lower_upper(VM_ARG, str, ZL_EXP_TRUE);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, result, 0, 0);
	zenglApi_FreeMem(VM_ARG, result);
}

/**
 * bltToUpper模块函数，将字符串转为大写，并将转换的结果返回给调用者
 * 第一个参数str必须是字符串类型，表示需要进行转换的源字符串
 *
 * 示例：
	use builtin,request;

	headers = rqtGetHeaders();
	for(i=0; bltIterArray(headers,&i,&k,&v); )
		print k +": " + v + '<br/>';
		uppers[bltToUpper(k)] = bltToUpper(v);
	endfor

	print '=============================================<br/>uppers: <br/>';

	for(i=0; bltIterArray(uppers,&i,&k,&v); )
		print k +": " + v + '<br/>';
	endfor

	执行的结果类似如下：

	Host: 192.168.1.113:8083
	User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:81.0) Gecko/20100101 Firefox/81.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9
	Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
	Accept-Encoding: gzip, deflate
	Connection: keep-alive
	Upgrade-Insecure-Requests: 1
	Cache-Control: max-age=0
	=============================================
	uppers:
	HOST: 192.168.1.113:8083
	USER-AGENT: MOZILLA/5.0 (WINDOWS NT 10.0; WIN64; X64; RV:81.0) GECKO/20100101 FIREFOX/81.0
	ACCEPT: TEXT/HTML,APPLICATION/XHTML+XML,APPLICATION/XML;Q=0.9
	ACCEPT-LANGUAGE: ZH-CN,ZH;Q=0.8,ZH-TW;Q=0.7,ZH-HK;Q=0.5,EN-US;Q=0.3,EN;Q=0.2
	ACCEPT-ENCODING: GZIP, DEFLATE
	CONNECTION: KEEP-ALIVE
	UPGRADE-INSECURE-REQUESTS: 1
	CACHE-CONTROL: MAX-AGE=0

	可以看到经过bltToUpper转换后，所有的字符都转为了大写字符

	模块函数版本历史：
	 - v0.23.0版本新增此模块函数
 */
ZL_EXP_VOID module_builtin_to_upper(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	const char * func_name = "bltToUpper";
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: %s(str)", func_name);
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [str] of %s must be string", func_name);
	}
	char * str = (char *)arg.val.str;
	char * result = to_lower_upper(VM_ARG, str, ZL_EXP_FALSE);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, result, 0, 0);
	zenglApi_FreeMem(VM_ARG, result);
}

/**
 * bltVersionCompare模块函数，用于对版本号进行比较
 * 第一个参数version1必须是字符串类型，表示需要进行比较的第一个版本号
 * 第二个参数version2也必须是字符串类型，表示需要进行比较的第二个版本号
 * 	当返回值大于0时，表示version1大于version2
 * 	当返回值等于0时，表示version1等于version2
 * 	当返回值小于0时，表示version1小于version2
 *
 * 示例：
	use builtin;
	fun compare(v1, v2)
		c = bltVersionCompare(v1, v2);
		if(c > 0)
			print v1 + ' > ' + v2;
		elif(c < 0)
			print v1 + ' < ' + v2;
		else
			print v1 + ' == ' + v2;
		endif
	endfun

	fun compare2(v1, v2)
		if(bltVersionCompare(v1, v2) >= 0) // bltVersionCompare模块函数返回值大于或等于0，则说明v1版本号大于或等于v2版本号
			print v1 + ' >= ' + v2;
		else
			print v1 + ' < ' + v2;
		endif
	endfun

	compare('v0.1.0', 'v0.2.0');
	compare('v1.2.3', 'v1.2');
	compare('v2.2.3', 'v2.2.2');
	compare('2.3.0', 'v2.3');
	print '';

	compare2('3.2.1', '3.2');
	compare2('3.2.0', '3.2');
	compare2('3.2.0', '3.2.1');
	print '';

	执行结果如下：

	v0.1.0 < v0.2.0
	v1.2.3 > v1.2
	v2.2.3 > v2.2.2
	2.3.0 == v2.3

	3.2.1 >= 3.2
	3.2.0 >= 3.2
	3.2.0 < 3.2.1

	模块函数版本历史：
	 - v0.24.0版本新增此模块函数
 */
ZL_EXP_VOID module_builtin_version_compare(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	const char * func_name = "bltVersionCompare";
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: %s(version1, version2)", func_name);
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [version1] of %s must be string", func_name);
	}
	char * version1 = (char *)arg.val.str;
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [version2] of %s must be string", func_name);
	}
	char * version2 = (char *)arg.val.str;
	int retval = builtin_version_compare(version1, version2);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, retval, 0);
}

/**
 * bltSetTimeZone模块函数，设置当前脚本所在进程的时区
 * 第一个参数timezone必须是字符串类型，表示需要设置的时区，例如：America/New_York表示设置为纽约时区，Europe/London表示设置为伦敦时区等
 * 具体的时区格式，可以参考GNU官网的介绍：https://www.gnu.org/software/libc/manual/html_node/TZ-Variable.html
 * 返回值为1表示设置成功
 *
 * 示例：
	use builtin;

	print bltDate('%Y-%m-%d %H:%M:%S'); // 使用配置文件中timezone变量定义的时区来显示当前时间

	bltSetTimeZone("America/New_York"); // 切换到纽约时区

	print bltDate('%Y-%m-%d %H:%M:%S'); // 以纽约时区来显示当前时间

	bltSetTimeZone("Europe/London");    // 切换到伦敦时区

	print bltDate('%Y-%m-%d %H:%M:%S'); // 以伦敦时区来显示当前时间

	bltSetTimeZone("Asia/Shanghai");    // 切换到亚洲上海时区

	print bltDate('%Y-%m-%d %H:%M:%S'); // 以上海时区来显示当前时间

	bltSetTimeZone("");					// 切换到系统默认时区

	print bltDate('%Y-%m-%d %H:%M:%S'); // 使用默认时区来显示当前时间

	执行结果类似如下所示：
	2022-01-25 19:41:04
	2022-01-25 06:41:04
	2022-01-25 11:41:04
	2022-01-25 19:41:04
	2022-01-25 11:41:04

	模块函数版本历史：
	 - v0.25.0版本新增此模块函数
 */
ZL_EXP_VOID module_builtin_set_time_zone(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	const char * func_name = "bltSetTimeZone";
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: %s(timezone)", func_name);
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [timezone] of %s must be string", func_name);
	}
	char * timezone = (char *)arg.val.str;
	if(setenv("TZ", timezone, 1) == -1) {
		zenglApi_Exit("%s: failed to setenv TZ [%d] %s \n", (char *)func_name, errno, strerror(errno));
	}
	tzset();
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 1, 0);
}

/**
 * 內建模块的def宏值查询函数，该查询函数会根据查询名称返回对应的宏值
 * 例如：def TRUE ___BUILTIN_TRUE___; 这个语句，就会调用下面这个函数，并将___BUILTIN_TRUE___作为查询名称传递给该函数，
 * 函数在经过查询后，就会设置整数1作为TRUE的宏值，因此这个语句等效于 def TRUE 1;
 */
int module_builtin_def_lookup_handle(ZL_EXP_VOID * VM_ARG, ZL_EXP_CHAR * defValName)
{
	char tmpstr[20];
	int retval = 1;
	if(strcmp(defValName, "___BUILTIN_TRUE___") == 0) // 用于脚本中定义TRUE的宏值
	{
		retval = zenglApi_SetDefLookupResult(VM_ARG, ZL_EXP_FAT_INT, "1");
	}
	else if(strcmp(defValName, "___BUILTIN_FALSE___") == 0) // 用于脚本中定义FALSE的宏值
	{
		retval = zenglApi_SetDefLookupResult(VM_ARG, ZL_EXP_FAT_INT, "0");
	}
	else if(strcmp(defValName, "___BUILTIN_NULL___") == 0) // 用于脚本中定义NULL的宏值
	{
		retval = zenglApi_SetDefLookupResult(VM_ARG, ZL_EXP_FAT_INT, "0");
	}
	else if(strcmp(defValName, "___BUILTIN_WRITE_FILE_MODE_WRITE___") == 0) // 用于在脚本中定义bltWriteFile模块函数写入模式的宏值
	{
		snprintf(tmpstr, 20, "%d", WRITE_FILE_MODE_WRITE);
		retval = zenglApi_SetDefLookupResult(VM_ARG, ZL_EXP_FAT_INT, tmpstr);
	}
	else if(strcmp(defValName, "___BUILTIN_WRITE_FILE_MODE_APPEND___") == 0) // 用于在脚本中定义bltWriteFile模块函数追加模式的宏值
	{
		snprintf(tmpstr, 20, "%d", WRITE_FILE_MODE_APPEND);
		retval = zenglApi_SetDefLookupResult(VM_ARG, ZL_EXP_FAT_INT, tmpstr);
	}
	return !retval;
}

/**
 * builtin模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
 */
ZL_EXP_VOID module_builtin_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltArray",zenglApiBMF_array);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltUnset",zenglApiBMF_unset);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltIterArray",module_builtin_iterate_array);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltWriteFile",module_builtin_write_file);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltExit",module_builtin_exit);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltMustacheFileRender",module_builtin_mustache_file_render);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltJsonDecode",module_builtin_json_decode);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltJsonEncode",module_builtin_json_encode);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltMd5",module_builtin_md5);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltStr",module_builtin_str);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltInt",module_builtin_int);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltFloat",module_builtin_float);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltCount",module_builtin_count);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltGetZenglServerVersion",module_builtin_get_zengl_server_version);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltGetZenglVersion",module_builtin_get_zengl_version);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltHtmlEscape",module_builtin_html_escape);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltDate",module_builtin_date);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltMkdir",module_builtin_mkdir);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltUnlink",module_builtin_unlink);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltFileExists",module_builtin_file_exists);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltOutputBlob",module_builtin_output_blob);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltRandomStr",module_builtin_random_str);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltRand",module_builtin_rand);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltUtfStrLen",module_builtin_utf_str_len);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltStrLen",module_builtin_str_len);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltStrReplace",module_builtin_str_replace);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltIsNone",module_builtin_is_none);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltFree",module_builtin_free);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltReadFile",module_builtin_read_file);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltIsRunInCmd",module_builtin_is_run_in_cmd);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltSetImmediatePrint",module_builtin_set_immediate_print);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltSleep",module_builtin_sleep);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltDumpPtrData",module_builtin_dump_ptr_data);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltBase64Encode",module_builtin_base64_encode);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltBase64Decode",module_builtin_base64_decode);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltUrlEncode",module_builtin_url_encode);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltUrlDecode",module_builtin_url_decode);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltTrim",module_builtin_trim);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltFatalErrorCallback",module_builtin_fatal_error_callback);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltToLower",module_builtin_to_lower);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltToUpper",module_builtin_to_upper);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltVersionCompare",module_builtin_version_compare);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltSetTimeZone",module_builtin_set_time_zone);
}
