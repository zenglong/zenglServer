/*
 * debug.h
 *
 *  Created on: 2018-2-9
 *      Author: zengl
 */

#ifndef DEBUG_H_
#define DEBUG_H_

#include "module_builtin.h"

// 调试相关的结构体
typedef struct _DEBUG_INFO{
	int socket; // 调试相关的连接套接字
	BUILTIN_INFO_STRING format_send_msg; // 动态字符串，包含需要发送给远程调试器的数据
} DEBUG_INFO;

void debug_command_stack_backtrace(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info);

/**
 * 初始化DEBUG_INFO即调试相关的结构体，该结构体中存储了调试相关的套接字，以及需要发送给远程调试器的动态字符串
 */
void debug_init(DEBUG_INFO * debug_info);

/**
 * 如果zenglServer开启了调试功能，那么，在zengl虚拟机关闭之前，需要调用此函数来关闭掉打开的调试套接字，以及释放掉分配过的动态字符串资源
 */
void debug_exit(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info);

/**
 * 中断回调函数，如果zenglServer开启了调试功能，那么当触发断点时，就会调用此回调函数
 * 在该回调函数中，可以接收远程调试器发来的各种调试命令，并将调试结果通过连接套接字反馈给远程调试器
 */
ZL_EXP_INT debug_break(ZL_EXP_VOID * VM_ARG,ZL_EXP_CHAR * cur_filename, ZL_EXP_INT cur_line,ZL_EXP_INT breakIndex,ZL_EXP_CHAR * log);

/**
 * 在设置条件断点时，如果设置的条件表达式有错误(例如语法错误等)，那么当条件表达式执行出错时，就会触发下面的回调函数
 * 在该回调函数中，会将出错信息反馈给远程调试器
 */
ZL_EXP_INT debug_conditionError(ZL_EXP_VOID * VM_ARG,ZL_EXP_CHAR * filename, ZL_EXP_INT line,ZL_EXP_INT breakIndex,ZL_EXP_CHAR * error);

#endif /* DEBUG_H_ */
