/*
 * module_builtin.h
 *
 *  Created on: 2017-7-16
 *      Author: zengl
 */

#ifndef MODULE_BUILTIN_H_
#define MODULE_BUILTIN_H_

#include "common_header.h"

#define BUILTIN_INFO_STRING_SIZE 1024 // 动态字符串初始化和动态扩容的大小

// 动态字符串的结构体定义
typedef struct _BUILTIN_INFO_STRING{
	char * str;   //字符串指针
	int size;  //字符串的动态大小
	int count; //存放的字符数
	int cur;   //当前游标
} BUILTIN_INFO_STRING;

typedef struct _builtin_mustache_context builtin_mustache_context;

struct _builtin_mustache_context {
	ZENGL_EXPORT_MOD_FUN_ARG ctx;
};

void builtin_module_terminus();

/**
 * 根据full_path文件路径来获取文件的内容
 */
char * builtin_get_file_content(ZL_EXP_VOID * VM_ARG, char * full_path, char * api_name, int * arg_file_size);

/**
 * 重置动态字符串的count字符数和cur当前游标，这样可以重新在该动态字符串中设置新的字符串
 */
void builtin_reset_info_string(ZL_EXP_VOID * VM_ARG, BUILTIN_INFO_STRING * infoStringPtr);

/**
 * 将格式化后的字符串追加到infoStringPtr动态字符串的末尾，动态字符串会根据格式化的字符串的大小进行动态扩容
 */
void builtin_make_info_string(ZL_EXP_VOID * VM_ARG, BUILTIN_INFO_STRING * infoStringPtr, const char * format, ...);

void st_detect_arg_is_address_type(ZL_EXP_VOID * VM_ARG,
		int arg_index, ZENGL_EXPORT_MOD_FUN_ARG * arg_ptr, const char * arg_desc, const char * module_func_name);

/**
 * builtin模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
 */
ZL_EXP_VOID module_builtin_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID);

#endif /* MODULE_BUILTIN_H_ */
