/*
 * fatal_error_callback.c
 *
 *  Created on: Sep 5, 2020
 *      Author: root
 */

#include "main.h"
#include "debug.h"
#include "fatal_error_callback.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 当脚本发生严重的运行时错误时，可以设置需要调用的脚本中的回调函数，脚本可以在该回调函数中获取到错误信息和函数栈追踪信息，
// 从而可以直接在脚本中处理错误信息(例如将这些信息写入到指定的日志文件中，或者输出到终端等)
static char * call_function_name = NULL;    // 回调函数名
static char * call_class_name = NULL;       // 如果回调函数属于某个类，即回调函数是某个类里的方法，则该变量会记录具体的类名
static char * st_fatal_error_string = NULL; // 该变量用于记录具体的运行时错误信息
// 在命令行模式下，是否需要执行默认动作，默认情况下，命令行模式会将错误信息输出到命令行，如果在脚本的回调函数里，已经将错误信息输出到了命令行的话，
// 可以将该变量设置为0，从而不会将错误信息再次输出到命令行
static int st_default_cmd_action = 1;

/**
 * 用于运行时错误回调函数名，类名和错误信息相关的字符串拷贝操作
 */
static char * fatal_error_copy_string(char * from, char * to)
{
	if(to != NULL) {
		free(to);
	}
	int from_len = strlen(from);
	if(from_len <= 0)
		return NULL;
	to = malloc(from_len + 1);
	memcpy(to, from, from_len);
	to[from_len] = '\0';
	return to;
}

/**
 * 设置运行时错误回调函数名
 */
void fatal_error_set_function_name(char * function_name)
{
	call_function_name = fatal_error_copy_string(function_name, call_function_name);
}

/**
 * 设置运行时错误回调相关的类名，如果回调函数属于某个类中定义的方法的话，就需要通过此函数来设置回调相关的类名
 */
void fatal_error_set_class_name(char * class_name)
{
	call_class_name = fatal_error_copy_string(class_name, call_class_name);
}

/**
 * 设置运行时错误发生时，需要传递给脚本回调函数的错误信息
 */
void fatal_error_set_error_string(char * error_string)
{
	st_fatal_error_string = fatal_error_copy_string(error_string, st_fatal_error_string);
}

/**
 * 将运行时错误信息以字符串的形式返回
 */
char * fatal_error_get_error_string()
{
	return st_fatal_error_string;
}

/**
 * 设置是否需要在命令模式下，执行默认动作，当为0时表示不需要执行默认动作，当不为0时则表示需要执行默认动作
 */
void fatal_error_set_default_cmd_action(int default_cmd_action)
{
	st_default_cmd_action = default_cmd_action;
}

/**
 * 判断是否需要执行默认动作，返回0表示不需要执行默认动作，否则表示需要执行默认动作
 */
int fatal_error_get_default_cmd_action()
{
	return st_default_cmd_action;
}

/**
 * 当脚本发生严重的运行时错误时，如果脚本中设置了运行时错误回调函数的话，就调用该回调函数来处理运行时错误，
 * 同时会将错误信息和函数栈追踪信息，通过参数传递给回调函数
 */
int fatal_error_callback_exec(ZL_EXP_VOID * VM, char * script_file, char * fatal_error)
{
	if(call_function_name == NULL) {
		return 0;
	}
	DEBUG_INFO debug_info;
	debug_init(&debug_info);
	debug_command_stack_backtrace(VM, &debug_info);
	zenglApi_ReUse(VM,0);
	zenglApi_Push(VM,ZL_EXP_FAT_STR,fatal_error,0,0);
	zenglApi_Push(VM,ZL_EXP_FAT_STR,debug_info.format_send_msg.str,0,0);
	debug_exit(VM, &debug_info);
	if(zenglApi_Call(VM, script_file, call_function_name, call_class_name) == -1) {
		return -1;
	}
	return 0;
}

/**
 * 将运行时错误回调函数名，类名和错误信息相关的字符串给释放掉，同时将回调函数名，类名，错误信息以及是否执行默认动作等重置为默认值
 */
void fata_error_free_all_ptrs()
{
	if(call_function_name != NULL) {
		free(call_function_name);
		call_function_name = NULL;
	}
	if(call_class_name != NULL) {
		free(call_class_name);
		call_class_name = NULL;
	}
	if(st_fatal_error_string != NULL) {
		free(st_fatal_error_string);
		st_fatal_error_string = NULL;
	}
	st_default_cmd_action = 1;
}
