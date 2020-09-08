/*
 * debug.c
 *
 *  Created on: 2018-2-9
 *      Author: zengl
 */

#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#include "main.h"
#include "debug.h"
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <ctype.h>

#define DEBUG_RECV_SIZE 2000

/**
 * 根据当前执行脚本的目录路径，加上filename文件名，来生成可以被fopen等C库函数使用的路径，定义在module_builtin.c文件中
 */
void builtin_make_fullpath(char * full_path, char * filename, MAIN_DATA * my_data);

static void debug_free_socket(int * debug_arg_socket);

/**
 * 获取调试命令或者参数，第一次调用可以从str字符串中获取到调试命令
 * 第二次调用可以获取到命令的第一个参数，第三次调用可以获取到第二个参数，以此类推
 * 当无法获取到命令或者参数时，会返回0
 */
static ZL_EXP_CHAR * debug_get_arg(ZL_EXP_CHAR * str,ZL_EXP_INT * start,ZL_EXP_BOOL needNull)
{
	int i;
	char * ret;
	if((*start) < 0)
	{
		(*start) = -1;
		return ZL_EXP_NULL;
	}
	for(i=(*start);;i++)
	{
		if(str[i] == ' ' || str[i] == '\t')
			continue;
		else if(str[i] == '\0')
		{
			(*start) = -1;
			return ZL_EXP_NULL;
		}
		else
		{
			ret = str + i;
			while(++i)
			{
				if(str[i] == ' ' || str[i] == '\t')
				{
					if(needNull != ZL_EXP_FALSE)
						str[i] = '\0';
					(*start) = i+1;
					break;
				}
				else if(str[i] == '\0')
				{
					(*start) = -1;
					break;
				}
			}
			return ret;
		} //else
	}//for(i=(*start);;i++)
	(*start) = -1;
	return ZL_EXP_NULL;
}

/**
 * 判断str字符串是不是全部由数字构成
 */
static ZL_EXP_BOOL debug_is_number(ZL_EXP_CHAR * str)
{
	int len = strlen(str);
	int i;
	for(i=0;i<len;i++)
	{
		if(!isdigit(str[i]))
			return ZL_EXP_FALSE;
	}
	return ZL_EXP_TRUE;
}

/*将zengl数组转为字符串，并存储到debug_info->format_send_msg动态字符串中*/
ZL_EXP_VOID debug_make_array_str(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info, ZENGL_EXPORT_MEMBLOCK memblock,ZL_EXP_INT recur_count)
{
	ZL_EXP_INT size,i,j;
	ZL_EXP_CHAR * key;
	ZENGL_EXPORT_MOD_FUN_ARG mblk_val = {ZL_EXP_FAT_NONE,{0}};
	zenglApi_GetMemBlockInfo(VM_ARG,&memblock,&size,ZL_EXP_NULL);
	for(i=1;i<=size;i++)
	{
		mblk_val = zenglApi_GetMemBlock(VM_ARG,&memblock,i);
		zenglApi_GetMemBlockHashKey(VM_ARG,&memblock,i-1,&key);
		switch(mblk_val.type)
		{
		case ZL_EXP_FAT_INT:
		case ZL_EXP_FAT_FLOAT:
		case ZL_EXP_FAT_STR:
		case ZL_EXP_FAT_MEMBLOCK:
			for(j=0;j<recur_count;j++)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "  ");
			break;
		}
		switch(mblk_val.type)
		{
		case ZL_EXP_FAT_INT:
			if(key != ZL_EXP_NULL)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "[%d]{%s} %ld\n",i-1,key,mblk_val.val.integer);
			else
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "[%d] %ld\n",i-1,mblk_val.val.integer);
			break;
		case ZL_EXP_FAT_FLOAT:
			if(key != ZL_EXP_NULL)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "[%d]{%s} %.16g\n",i-1,key,mblk_val.val.floatnum);
			else
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "[%d] %.16g\n",i-1,mblk_val.val.floatnum);
			break;
		case ZL_EXP_FAT_STR:
			if(key != ZL_EXP_NULL)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "[%d]{%s} %s\n",i-1,key,mblk_val.val.str);
			else
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "[%d] %s\n",i-1,mblk_val.val.str);
			break;
		case ZL_EXP_FAT_MEMBLOCK:
			if(key != ZL_EXP_NULL)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "[%d]{%s} <array or class obj type> begin:\n",i-1,key);
			else
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "[%d] <array or class obj type> begin:\n",i-1);
			debug_make_array_str(VM_ARG, debug_info, mblk_val.val.memblock, recur_count+1);
			for(j=0;j<recur_count;j++)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "  "); // 递归调用返回后，输出前缀空格，以便于排版
			if(key != ZL_EXP_NULL)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "[%d]{%s} <array or class obj type> end\n",i-1,key);
			else
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "[%d] <array or class obj type> end\n",i-1);
			break;
		}
	}
}

/**
 * 将调试寄存器里的调试结果转为字符串形式，并存储到debug_info->format_send_msg动态字符串中
 */
ZL_EXP_VOID debug_make_value_str(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info, ZL_EXP_CHAR * debug_str)
{
	ZENGL_EXPORT_MOD_FUN_ARG reg_debug;
	ZL_EXP_INT debug_str_len = strlen(debug_str);
	ZL_EXP_BOOL hasSemi = ZL_EXP_FALSE;
	zenglApi_GetDebug(VM_ARG, &reg_debug);
	if(debug_str_len > 0 && debug_str[debug_str_len - 1] == ';')
	{
		hasSemi = ZL_EXP_TRUE;
		debug_str[debug_str_len - 1] = ' ';
	}
	builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "%s:",debug_str);
	switch(reg_debug.type)
	{
	case ZL_EXP_FAT_NONE:
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "none type , number equal %ld", reg_debug.val.integer);
		break;
	case ZL_EXP_FAT_INT:
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "integer:%ld",reg_debug.val.integer);
		break;
	case ZL_EXP_FAT_FLOAT:
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "float:%.16g",reg_debug.val.floatnum);
		break;
	case ZL_EXP_FAT_STR:
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "string:%s",reg_debug.val.str);
		break;
	case ZL_EXP_FAT_MEMBLOCK:
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "array or class obj:\n");
		debug_make_array_str(VM_ARG, debug_info, reg_debug.val.memblock, 0);
		break;
	case ZL_EXP_FAT_ADDR:
	case ZL_EXP_FAT_ADDR_LOC:
	case ZL_EXP_FAT_ADDR_MEMBLK:
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "addr type");
		break;
	case ZL_EXP_FAT_INVALID:
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "invalid type");
		break;
	}
	if(hasSemi == ZL_EXP_TRUE)
		debug_str[debug_str_len - 1] = ';';
	builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "\n");
}

// 执行一个非阻塞的连接(将套接字设置为非阻塞模式后，就可以利用select函数来控制连接的超时时间)
// 执行成功返回0，执行失败返回-1
// sa - 包含了需要连接的主机的IP地址和端口，由调用者填充
// sock - 需要用于连接的套接字
// timeout - 连接的超时时间(以秒为单位)
static int debug_connect_nonblock(struct sockaddr_in sa, int sock, int timeout)
{
	int flags = 0, error = 0, ret = 0;
	fd_set  rset, wset;
	socklen_t   len = sizeof(error);
	struct timeval  ts;

	ts.tv_sec = timeout;
	ts.tv_usec = 0;

	// 为select函数清理描述符集
	// 将套接字加入到描述集中
	FD_ZERO(&rset);
	FD_SET(sock, &rset);
	wset = rset;

	// 将套接字设置为非阻塞模式
	if( (flags = fcntl(sock, F_GETFL, 0)) < 0)
		return -1;

	if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
		return -1;

	// 初始化非阻塞连接
	if( (ret = connect(sock, (struct sockaddr *)&sa, 16)) < 0 )
		if (errno != EINPROGRESS)
			return -1;

	if(ret == 0)    // 此处连接成功，就不需要再调用select了
		goto done;

	// 通过select函数等待连接完成，timeout是超时时间
	if( (ret = select(sock + 1, &rset, &wset, NULL, (timeout) ? &ts : NULL)) < 0)
		return -1;
	if(ret == 0){   // select返回0表示连接超时，返回-1
		errno = ETIMEDOUT;
		return -1;
	}

	//  we had a positivite return so a descriptor is ready
	if (FD_ISSET(sock, &rset) || FD_ISSET(sock, &wset)){
		if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
			return -1;
	} else
		return -1;

	if(error) {  //check if we had a socket error
		errno = error;
		return -1;
	}

done:
	// 将套接字切回阻塞模式
	if(fcntl(sock, F_SETFL, flags) < 0)
		return -1;

	return 0;
}

/**
 * 如果没有创建过调试相关的连接套接字，就通过socket函数创建一个套接字
 * 并通过connect函数，根据调试器的IP地址和端口号连接远程调试器
 */
static int debug_get_socket(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info)
{
	if(debug_info->socket == -1)
	{
		debug_info->socket = socket(AF_INET , SOCK_STREAM , 0);
		if (debug_info->socket == -1)
		{
			write_to_server_log_pipe(WRITE_TO_PIPE, "zl debug error: Could not create socket [%d] %s\n", errno, strerror(errno));
			return -1;
		}
		write_to_server_log_pipe(WRITE_TO_PIPE, "zl debug info: Socket created [%d]\n", debug_info->socket);
		char * remote_debugger_ip;
		long remote_debugger_port;
		main_get_remote_debug_config(NULL, &remote_debugger_ip, &remote_debugger_port);
		struct sockaddr_in server;
		server.sin_addr.s_addr = inet_addr(remote_debugger_ip);
		server.sin_family = AF_INET;
		server.sin_port = htons( (uint16_t)remote_debugger_port );
		write_to_server_log_pipe(WRITE_TO_PIPE, "zl debug info: connecting to %s:%ld...", remote_debugger_ip, remote_debugger_port);
		//if (connect(debug_info->socket , (struct sockaddr *)&server , sizeof(server)) < 0)
		if(debug_connect_nonblock(server, debug_info->socket, 15) < 0) // 15秒超时
		{
			write_to_server_log_pipe(WRITE_TO_PIPE, " failed [%d] %s\n", errno, strerror(errno));
			debug_free_socket(&debug_info->socket);
			return -1;
		}
		write_to_server_log_pipe(WRITE_TO_PIPE, " connected\n");
	}
	return debug_info->socket;
}

/**
 * 通过调试套接字，将message字符串发送给远程调试器
 */
static int debug_socket_send(int sock, char * message, int message_length)
{
	int ret;
	if( ( ret = send(sock , message , message_length, 0) ) < 0)
	{
		write_to_server_log_pipe(WRITE_TO_PIPE, "zl debug error: send failed. [%d] %s\n", errno, strerror(errno));
		return -1;
	}
	return ret;
}

/**
 * p命令：执行p命令后面的第一个参数对应的表达式，并将表达式的结果，以字符串的形式存储到format_send_msg动态字符串中，稍后会将其发送给远程调试器
 */
static void debug_command_print(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info, char * str, int * start, int str_count, int str_size)
{
	char * arg = debug_get_arg(str, start, ZL_EXP_FALSE);
	int arglen = arg != ZL_EXP_NULL ? strlen(arg) : 0;
	if(arg != ZL_EXP_NULL && arglen > 0)
	{
		if(arg[arglen - 1] != ';' && str_count < str_size - 1)
		{
			arg[arglen] = ';';
			arg[arglen+1] = '\0';
		}
		if(zenglApi_Debug(VM_ARG,arg) == -1)
		{
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "p调试错误：%s\n", zenglApi_GetErrorString(VM_ARG));
			return;
		}
		debug_make_value_str(VM_ARG, debug_info, arg);
		return;
	}
	else {
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "p命令缺少参数\n");
		return;
	}
}

/**
 * b命令：设置断点
 * 例如：b test.zl 19 就是在test.zl脚本的第19行设置断点
 * 如果不提供脚本文件名，就是在当前执行脚本中设置断点，例如：b 19就是在当前执行脚本的第19行设置断点
 * 脚本文件名必须是相对于主执行脚本的相对路径
 * 假设主执行脚本是test.zl，并在test.zl中通过inc '../test2.zl'加载了test2.zl
 * 那么，要在test2.zl中设置断点的话，就需要使用b ../test2.zl 19这样的写法
 * 可以在b命令最后跟随一个断点次数，例如：b test.zl 19 1表示在test.zl的第19行设置断点，断点次数为1，也就是只能中断一次
 */
static int debug_command_set_breakpoint(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info, char * str, int * start,
		char * cur_filename, int * arg_count, MAIN_DATA * my_data)
{
	char full_path[FULL_PATH_SIZE];
	char * filename = ZL_EXP_NULL;
	int line = 0;
	int count = 0;
	char * arg = debug_get_arg(str, start, ZL_EXP_TRUE);
	if(arg != ZL_EXP_NULL && strlen(arg) > 0) {
		filename = arg;
	}
	else {
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "b命令缺少文件名或行号参数\n");
		return -1;
	}

	if(debug_is_number(filename)) {
		line = atoi(filename);
		filename = cur_filename;
	}
	else {
		arg = debug_get_arg(str, start, ZL_EXP_TRUE);
		if(arg != ZL_EXP_NULL && strlen(arg) > 0) {
			line = atoi(arg);
			builtin_make_fullpath(full_path, filename, my_data);
			filename = full_path;
		}
		else {
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "b命令缺少行号参数\n");
			return -1;
		}
	}

	if(arg_count != NULL) {
		count = (*arg_count);
	}
	else {
		arg = debug_get_arg(str, start, ZL_EXP_TRUE);
		if(arg != ZL_EXP_NULL && strlen(arg) > 0) {
			count = atoi(arg);
		}
	}

	if(zenglApi_DebugSetBreak(VM_ARG,filename,line,ZL_EXP_NULL,ZL_EXP_NULL,count,ZL_EXP_FALSE) == -1) {
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "b命令error:%s\n下断点的文件路径:%s\n",
				zenglApi_GetErrorString(VM_ARG), filename);
		return -1;
	}
	else if(arg_count == NULL) {
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "设置断点成功\n");
	}
	return 0;
}

/**
 * B命令：将设置过的断点都列举出来，并将列举出来的断点列表存到format_send_msg动态字符串中，稍后会将其发送给远程调试器
 */
static void debug_command_list_breakpoints(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info,
		ZL_EXP_INT breakIndex,
		ZL_EXP_CHAR * cur_filename,
		ZL_EXP_INT cur_line,
		char * str,
		int * start)
{
	int size;
	int totalcount;
	int i;
	char * filename = ZL_EXP_NULL;
	char * condition = ZL_EXP_NULL;
	char * log = ZL_EXP_NULL;
	int count;
	int line;
	ZL_EXP_BOOL disabled;
	if(breakIndex == -1) {
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "* %s:%d Single Break [current]\n", cur_filename, cur_line);
	}
	size = zenglApi_DebugGetBreak(VM_ARG,-1,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL,&totalcount,ZL_EXP_NULL,ZL_EXP_NULL);
	for(i=0;i<size;i++)
	{
		if(zenglApi_DebugGetBreak(VM_ARG,i,&filename,&line,&condition,&log,&count,&disabled,ZL_EXP_NULL) == -1)
			continue;
		else
		{
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "[%d] %s:%d",i,filename,line);
			// 如果设置过条件断点，就将condition条件表达式显示出来
			if(condition != ZL_EXP_NULL) {
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, " C:%s",condition);
			}
			// 如果设置过日志断点，就将日志表达式显示出来
			if(log != ZL_EXP_NULL) {
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, " L:%s",log);
			}
			// 显示出断点次数，也就是可以中断多少次
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, " N:%d", count);
			// 显示断点启用状态：enable表示启用，disable表示禁用
			if(disabled == ZL_EXP_FALSE)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, " D:enable");
			else
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, " D:disable");
			// 如果断点列表中的断点是当前触发的断点的话，就在后面显示[current]
			if(i == breakIndex)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, " [current]");
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "\n");
		}
	}
	builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "total:%d\n",totalcount);
}

/**
 * T命令：获取栈追踪信息，以显示代码执行情况
 * 例如：
 * zl debug >>> T
 * /home/zengl/zenglBlog/admin/../mysql.zl:17 Mysql:init
 * /home/zengl/zenglBlog/admin/login.zl:24
 * zl debug >>>
 * 上面通过T命令，可以看到，当前执行到了mysql.zl脚本的第17行，并且是通过login.zl的第24行调用Mysql类的init方法进入到mysql.zl脚本的
 */
void debug_command_stack_backtrace(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info)
{
	int arg = -1;
	int loc = -1;
	int pc = -1;
	int ret;
	int line = 0;
	char * fileName = ZL_EXP_NULL;
	char * className = ZL_EXP_NULL;
	char * funcName = ZL_EXP_NULL;
	while(ZL_EXP_TRUE)
	{
		ret = zenglApi_DebugGetTrace(VM_ARG,&arg,&loc,&pc,&fileName,&line,&className,&funcName);
		if(ret == 1)
		{
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, " %s:%d ",fileName,line);
			if(className != ZL_EXP_NULL)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "%s:",className);
			if(funcName != ZL_EXP_NULL)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "%s",funcName);
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "\n");
			continue;
		}
		else if(ret == 0)
		{
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, " %s:%d ",fileName,line);
			if(className != ZL_EXP_NULL)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "%s:",className);
			if(funcName != ZL_EXP_NULL)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "%s",funcName);
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "\n");
			break;
		}
		else if(ret == -1)
		{
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "%s",zenglApi_GetErrorString(VM_ARG));
			break;
		}
	}
}

/**
 * r命令：执行到返回
 * 如果当前位于某个脚本函数中，那么r命令会在脚本函数的调用位置的下一条指令位置处设置断点，并继续执行
 * 因此，使用r命令后，会马上执行完当前脚本函数，并在脚本函数返回时再触发断点，从而可以快速跳过某个函数的具体执行过程
 * 如果当前并不位于脚本函数中，就等效于c命令，也就是继续执行，直到遇到断点或者脚本结束
 * 例如：
 * zl debug >>> T
 * /home/zengl/zenglBlog/admin/../mysql.zl:17 Mysql:init
 * /home/zengl/zenglBlog/admin/login.zl:24
 * zl debug >>> r
 * file:/home/zengl/zenglBlog/admin/login.zl,line:25,breakIndex:0
 * zl debug >>> T
 * /home/zengl/zenglBlog/admin/login.zl:25
 * zl debug >>>
 * 上面当脚本位于Mysql类的init函数中时，通过r命令就可以一路执行完init函数，并在函数返回后的下一条指令位置处，也就是login.zl的第25行中断下来
 */
static void debug_command_run_to_return(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info, int * exit)
{
	int arg = -1;
	int loc = -1;
	int pc = -1;
	int tmpPC;
	int ret;
	int size,i;
	int line = 0;
	char * fileName = ZL_EXP_NULL;
	ZL_EXP_BOOL hasBreaked = ZL_EXP_FALSE;
	ret = zenglApi_DebugGetTrace(VM_ARG,&arg,&loc,&pc,&fileName,&line,ZL_EXP_NULL,ZL_EXP_NULL);
	if(ret == 1)
	{
		//zenglApi_DebugGetTrace(VM_ARG,&arg,&loc,&pc,&fileName,&line,ZL_EXP_NULL,ZL_EXP_NULL);
		pc++;
		size = zenglApi_DebugGetBreak(VM_ARG,-1,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL);
		for(i=0;i<size;i++)
		{
			if(zenglApi_DebugGetBreak(VM_ARG,i,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL,&tmpPC) == -1)
				continue;
			else if(pc == tmpPC)
			{
				hasBreaked = ZL_EXP_TRUE;
				break;
			}
		}
		if(!hasBreaked)
		{
			if(zenglApi_DebugSetBreakEx(VM_ARG,pc,ZL_EXP_NULL,ZL_EXP_NULL,1,ZL_EXP_FALSE) == -1)
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "%s",zenglApi_GetErrorString(VM_ARG));
			else
				(*exit) = 1;
		}
		else
			(*exit) = 1;
	}
	else if(ret == 0)
		(*exit) = 1;
	else if(ret == -1)
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "%s",zenglApi_GetErrorString(VM_ARG));
}

/**
 * d命令：删除某个断点
 * 每个断点都有一个索引，可以通过B命令查看到，需要删除某个断点时，只要在d命令后面使用该断点的索引作为参数即可
 * 例如：
 * zl debug >>> B
 * [0] /home/zengl/zenglBlog/admin/login.zl:25 N:1 D:enable [current]
 * [1] /home/zengl/zenglBlog/admin/../mysql.zl:17 N:0 D:enable
 * total:2
 * zl debug >>> d 1
 * 删除断点成功
 * zl debug >>> B
 * [0] /home/zengl/zenglBlog/admin/login.zl:25 N:1 D:enable [current]
 * total:1
 * zl debug >>>
 * 上面通过d 1命令将索引为1的断点给删除掉
 */
static void debug_command_delete_breakpoint(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info, char * str, int * start)
{
	int index;
	char * arg = debug_get_arg(str, start, ZL_EXP_TRUE);
	if(arg != ZL_EXP_NULL && strlen(arg) > 0 && debug_is_number(arg))
		index = atoi(arg);
	else
	{
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "d命令缺少断点索引参数\n");
		return;
	}
	if(zenglApi_DebugDelBreak(VM_ARG,index) == -1)
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "d命令error:无效的断点索引");
	else
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "删除断点成功");
	builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "\n");
}

/**
 * D命令：禁用某个断点
 * 通过在D命令后面使用断点索引作为参数，就可以禁用某个断点
 * 例如：
 * zl debug >>> B
 * [0] /home/zengl/zenglBlog/admin/login.zl:25 N:1 D:enable [current]
 * [1] /home/zengl/zenglBlog/admin/login.zl:28 N:0 D:enable
 * total:2
 * zl debug >>> D 1
 * D命令禁用断点成功
 * zl debug >>> B
 * [0] /home/zengl/zenglBlog/admin/login.zl:25 N:1 D:enable [current]
 * [1] /home/zengl/zenglBlog/admin/login.zl:28 N:0 D:disable
 * total:2
 * zl debug >>>
 * 上面示例中，通过D 1命令将索引为1的断点给禁用掉，命令执行后，通过B命令可以看到该断点已经disable被禁用了
 * 断点被禁用后，脚本执行到断点位置处时，就不会被中断下来
 */
static void debug_command_disable_breakpoint(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info, char * str, int * start)
{
	int index;
	char * filename = ZL_EXP_NULL;
	char * condition = ZL_EXP_NULL;
	char * log = ZL_EXP_NULL;
	int count;
	int line;
	ZL_EXP_BOOL disabled;
	char * arg = debug_get_arg(str, start, ZL_EXP_TRUE);
	if(arg != ZL_EXP_NULL && strlen(arg) > 0 && debug_is_number(arg))
		index = atoi(arg);
	else
	{
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "D命令缺少断点索引参数\n");
		return;
	}
	if(zenglApi_DebugGetBreak(VM_ARG,index,&filename,&line,&condition,&log,&count,&disabled,ZL_EXP_NULL) == -1)
	{
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "D命令error:无效的断点索引\n");
		return;
	}
	else
	{
		if(zenglApi_DebugSetBreak(VM_ARG,filename,line,condition,log,count,ZL_EXP_TRUE) == -1)
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "D命令禁用断点error:%s",zenglApi_GetErrorString(VM_ARG));
		else
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "D命令禁用断点成功");
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "\n");
	}
}

/**
 * C命令：设置条件断点
 * 通过在C命令后面跟随断点索引和条件表达式，就可以在执行到断点位置处时，当条件表达式的结果不为0时中断下来
 * 例如：
 * zl debug >>> b 19
 * 设置断点成功
 * zl debug >>> B
 * [0] my_webroot/v0_8_0/test.zl:1 N:1 D:enable [current]
 * [1] my_webroot/v0_8_0/test.zl:19 N:0 D:enable
 * total:2
 * zl debug >>> C 1 json!=''
 * C命令设置条件断点成功
 * zl debug >>> B
 * [0] my_webroot/v0_8_0/test.zl:1 N:1 D:enable [current]
 * [1] my_webroot/v0_8_0/test.zl:19 C:json!=''; N:0 D:enable
 * total:2
 * zl debug >>> c
 * file:my_webroot/v0_8_0/test.zl,line:19,breakIndex:1
 * zl debug >>>
 * 上面通过 C 1 json!='' 命令在索引为1的断点处设置了条件表达式，当执行到test.zl的第19行时，如果json不等于空字符串，就中断下来
 * 通过B命令，也可以看到设置的条件表达式
 */
static void debug_command_set_condition_breakpoint(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info,
					char * str, int * start, int str_count, int str_size)
{
	int index;
	char * newCondition;
	char * filename = ZL_EXP_NULL;
	char * condition = ZL_EXP_NULL;
	char * log = ZL_EXP_NULL;
	int count;
	int line;
	ZL_EXP_BOOL disabled;
	char * arg = debug_get_arg(str, start, ZL_EXP_TRUE);
	if(arg != ZL_EXP_NULL && strlen(arg) > 0 && debug_is_number(arg))
		index = atoi(arg);
	else
	{
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "C命令缺少断点索引参数\n");
		return;
	}
	arg = debug_get_arg(str, start, ZL_EXP_FALSE);
	int arglen = arg != ZL_EXP_NULL ? strlen(arg) : 0;
	if(arg != ZL_EXP_NULL && arglen > 0)
	{
		if(arg[arglen - 1] != ';' && str_count < str_size - 1)
		{
			arg[arglen] = ';';
			arg[arglen+1] = '\0';
		}
		newCondition = arg;
	}
	else
		newCondition = ZL_EXP_NULL;
	if(zenglApi_DebugGetBreak(VM_ARG,index,&filename,&line,&condition,&log,&count,&disabled,ZL_EXP_NULL) == -1)
	{
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "C命令error:无效的断点索引\n");
		return;
	}
	else
	{
		if(zenglApi_DebugSetBreak(VM_ARG,filename,line,newCondition,log,count,disabled) == -1)
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "C命令设置条件断点error:%s",zenglApi_GetErrorString(VM_ARG));
		else
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "C命令设置条件断点成功");
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "\n");
	}
}

/**
 * L命令：设置日志断点
 * 通过在L命令后面跟随断点索引和日志表达式，可以将某断点转为日志断点，当执行到断点位置处时，会执行日志表达式，并将表达式的执行结果显示出来
 * 例如：
 * listen connection...
 * 127.0.0.1 connected:
 * file:my_webroot/v0_8_0/test.zl,line:1,breakIndex:0
 * zl debug >>> b 19
 * 设置断点成功
 * zl debug >>> L 1 json
 * L命令设置日志断点成功
 * zl debug >>> B
 * [0] my_webroot/v0_8_0/test.zl:1 N:1 D:enable [current]
 * [1] my_webroot/v0_8_0/test.zl:19 L:json; N:0 D:enable
 * total:2
 * zl debug >>> c
 * json :string:{"hello": "world!!", "name": "zengl", "val": "programmer", "arr":[1,2,3]}
 * listen connection...
 * 上面通过L 1 json命令将索引为1的断点设置为了日志断点，通过B命令可以看到相关的日志表达式L:json;
 * 当执行到该断点位置处时，就会将表达式json;对应的值给显示出来
 */
static void debug_command_set_log_breakpoint(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info,
					char * str, int * start, int str_count, int str_size)
{
	int index;
	char * newLog;
	char * filename = ZL_EXP_NULL;
	char * condition = ZL_EXP_NULL;
	char * log = ZL_EXP_NULL;
	int count;
	int line;
	ZL_EXP_BOOL disabled;
	char * arg = debug_get_arg(str, start, ZL_EXP_TRUE);
	if(arg != ZL_EXP_NULL && strlen(arg) > 0 && debug_is_number(arg))
		index = atoi(arg);
	else
	{
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "L命令缺少断点索引参数\n");
		return;
	}
	arg = debug_get_arg(str, start, ZL_EXP_FALSE);
	int arglen = arg != ZL_EXP_NULL ? strlen(arg) : 0;
	if(arg != ZL_EXP_NULL && arglen > 0)
	{
		if(arg[arglen - 1] != ';' && str_count < str_size - 1)
		{
			arg[arglen] = ';';
			arg[arglen+1] = '\0';
		}
		newLog = arg;
	}
	else
		newLog = ZL_EXP_NULL;
	if(zenglApi_DebugGetBreak(VM_ARG,index,&filename,&line,&condition,&log,&count,&disabled,ZL_EXP_NULL) == -1)
	{
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "L命令error:无效的断点索引\n");
		return;
	}
	else
	{
		if(zenglApi_DebugSetBreak(VM_ARG,filename,line,condition,newLog,count,disabled) == -1)
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "L命令设置日志断点error:%s", zenglApi_GetErrorString(VM_ARG));
		else
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "L命令设置日志断点成功");
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "\n");
	}
}

/**
 * N命令：设置断点次数
 * 通过在N命令后面跟随断点索引和断点次数参数，就可以为某断点设置允许中断的次数，当中断次数达到允许的值时，就会删除掉该断点
 * 例如：
 * zl debug >>> N 1 2
 * N命令设置断点次数成功
 * zl debug >>> B
 * [0] my_webroot/v0_8_0/test.zl:1 N:1 D:enable [current]
 * [1] my_webroot/v0_8_0/test.zl:30 N:2 D:enable
 * total:2
 * zl debug >>> c
 * file:my_webroot/v0_8_0/test.zl,line:30,breakIndex:1
 * zl debug >>> c
 * file:my_webroot/v0_8_0/test.zl,line:30,breakIndex:1
 * zl debug >>> c
 * listen connection...
 * 上面通过N 1 2命令将索引为1的断点设置了断点次数为2后，该断点就只会最多中断两次
 */
static void debug_command_set_breakpoint_number(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info, char * str, int * start)
{
	int index;
	int newCount;
	char * filename = ZL_EXP_NULL;
	char * condition = ZL_EXP_NULL;
	char * log = ZL_EXP_NULL;
	int count;
	int line;
	ZL_EXP_BOOL disabled;
	char * arg = debug_get_arg(str, start, ZL_EXP_TRUE);
	if(arg != ZL_EXP_NULL && strlen(arg) > 0 && debug_is_number(arg))
		index = atoi(arg);
	else
	{
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "N命令缺少断点索引参数\n");
		return;
	}
	arg = debug_get_arg(str, start, ZL_EXP_TRUE);
	if(arg != ZL_EXP_NULL && strlen(arg) > 0 && debug_is_number(arg))
		newCount = atoi(arg);
	else
	{
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "N命令缺少断点次数参数\n");
		return;
	}
	if(zenglApi_DebugGetBreak(VM_ARG,index,&filename,&line,&condition,&log,&count,&disabled,ZL_EXP_NULL) == -1)
	{
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "N命令error:无效的断点索引\n");
		return;
	}
	else
	{
		if(zenglApi_DebugSetBreak(VM_ARG,filename,line,condition,log,newCount,disabled) == -1)
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "N命令设置断点次数error:%s",zenglApi_GetErrorString(VM_ARG));
		else
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "N命令设置断点次数成功");
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "\n");
	}
}

/**
 * h命令：显示帮助信息，帮助信息中可以看到各个命令的基本用法
 */
static void debug_command_help(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info)
{
	builtin_make_info_string(VM_ARG, &debug_info->format_send_msg,
			" p 调试变量信息 usage:p express\n"
			" b 设置断点 usage:b filename lineNumber[ count] | b lineNumber[ count]\n"
			" B 查看断点列表 usage:B\n"
			" T 查看脚本函数的堆栈调用信息 usage:T\n"
			" d 删除某断点 usage:d breakIndex\n"
			" D 禁用某断点 usage:D breakIndex\n"
			" C 设置条件断点 usage:C breakIndex condition-express\n"
			" L 设置日志断点 usage:L breakIndex log-express\n"
			" N 设置断点次数 usage:N breakIndex count\n"
			" s 单步步入 usage:s\n"
			" S 单步步过 usage:S\n"
			" r 执行到返回 usage:r\n"
			" c 继续执行 usage:c\n"
			" e 退出，停止执行 usage:e\n"
			" l 显示源码 usage:l filename [lineNumber[ offset]] | l [lineNumber[ offset]]\n"
			" u 执行到指定的行 usage:u filename lineNumber | u lineNumber\n"
			" h 显示帮助信息\n");
}

/**
 * l命令：查看源码
 * 例如：
 * zl debug >>> l
 * current run line:1 [my_webroot/v0_8_0/test.zl]
 * 1    use builtin;    <<<---[ current line] ***
 * 2
 * 3    def TRUE 1;
 * ............................
 *
 * zl debug >>> l 8 10
 * current run line:1 [my_webroot/v0_8_0/test.zl]
 * 1    use builtin;    <<<---[ current line] ***
 * 2
 * ............................
 * 16
 * 17    json = '{"hello": "world!!", "name": "zengl", "val": "programmer", "arr":[1,2,3]}';
 * 18
 *
 * zl debug >>> l test2.zl
 * 1    use builtin, request;
 * 2
 * 3    rqtSetResponseHeader("HTTP/1.1 302 Moved Temporarily");
 * 4    rqtSetResponseHeader("Location: test.zl");
 * 5    bltExit();
 *
 * zl debug >>> l test2.zl 5
 * ............................
 * zl debug >>> l test2.zl 5 10
 * ............................
 * 当l命令后面没有参数时，会将当前执行代码所在行附近的源码显示出来
 * 如果l命令后面只跟随了数字参数的话，那么分别表示需要显示的行号和偏移值
 * 例如上面的l 8 10表示将当前执行脚本的第8行附近的源码显示出来，10表示将第8行上下偏移10行的源码显示出来，因此会将1到18行的源码列举出来
 * 如果l命令后面跟随了脚本文件名的话，会将该脚本文件的源码显示出来，同样可以在脚本文件名后面跟随行号和偏移值
 * 和b命令类似，脚本文件名必须是相对于主执行脚本的相对路径
 * 假设主执行脚本是test.zl，并在test.zl中通过inc '../test2.zl'加载了test2.zl
 * 那么，要列举出test2.zl中的源码的话，就需要使用l ../test2.zl这样的写法
 *
 * zenglServer只会将脚本文件中的所有源码一次发给远程调试器，由远程调试器缓存源码，并根据行号等进行显示
 * 例如当在远程调试器中输入l test2.zl 5命令后，远程调试器只会将l test2.zl发送给zenglServer，zenglServer就会将test2.zl的所有内容一次读取出来
 * 并发送给远程调试器，远程调试器会将返回的源码缓存起来，然后从缓存的源码中，将第5行附近的代码列举出来，当下一次输入l test2.zl命令时
 * 远程调试器就只需要读取缓存即可，不需要再发送命令给zenglServer
 */
static int debug_command_list_file_content(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info,
		char * str, int * start, MAIN_DATA * my_data)
{
	char full_path[FULL_PATH_SIZE];
	char * filename = ZL_EXP_NULL;
	char * arg = debug_get_arg(str, start, ZL_EXP_TRUE);
	if(arg != ZL_EXP_NULL && strlen(arg) > 0) {
		filename = arg;
	}
	else {
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "l命令缺少文件名参数\n");
		return debug_socket_send(debug_info->socket, debug_info->format_send_msg.str, debug_info->format_send_msg.count);
	}
	builtin_make_fullpath(full_path, filename, my_data);
	const char * command_name = "l command";
	struct stat filestatus;
	if ( stat(full_path, &filestatus) != 0) {
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "%s stat file \"%s\" failed [%d] %s",
				command_name, full_path, errno, strerror(errno));
		return debug_socket_send(debug_info->socket, debug_info->format_send_msg.str, debug_info->format_send_msg.count);
	}
	int file_size = filestatus.st_size;
	FILE * fp = fopen(full_path, "rb");
	if (fp == NULL) {
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "%s open file \"%s\" failed [%d] %s",
				command_name, full_path, errno, strerror(errno));
		return debug_socket_send(debug_info->socket, debug_info->format_send_msg.str, debug_info->format_send_msg.count);
	}
	char * file_contents = (char *)zenglApi_AllocMem(VM_ARG, file_size + 1);
	int nread = fread(file_contents, file_size, 1, fp);
	if ( nread != 1 ) {
		fclose(fp);
		zenglApi_FreeMem(VM_ARG, file_contents);
		builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "%s error: Unable t read content of \"%s\"",
				command_name, full_path);
		return debug_socket_send(debug_info->socket, debug_info->format_send_msg.str, debug_info->format_send_msg.count);
	}
	fclose(fp);
	file_contents[file_size] = '\0';
	int ret = debug_socket_send(debug_info->socket, file_contents, file_size);
	zenglApi_FreeMem(VM_ARG, file_contents);
	return ret;
}

/**
 * u命令：执行到指定的行
 * u命令内部其实是先使用b命令在指定位置设置断点，并设置断点次数为1，然后继续执行，这样就可以快速的执行到指定位置，并在该位置中断下来
 * 例如：
 * zl debug >>> l 9 10
 * current run line:1 [my_webroot/v0_8_0/test.zl]
 * 1    use builtin;    <<<---[ current line] ***
 * 2
 * ........................................
 * 16
 * 17    json = '{"hello": "world!!", "name": "zengl", "val": "programmer", "arr":[1,2,3]}';
 * 18
 * 19    json = bltJsonDecode(json);
 *
 * zl debug >>> u 19
 * file:my_webroot/v0_8_0/test.zl,line:19,breakIndex:1
 * zl debug >>> p json
 * json :string:{"hello": "world!!", "name": "zengl", "val": "programmer", "arr":[1,2,3]}
 * zl debug >>>
 * 上面一开始当前执行代码位于第一行，通过u 19命令可以直接执行到第19行，并在19行中断下来
 */
static int debug_command_until(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info,
		char * str, int * start, char * cur_filename, MAIN_DATA * my_data)
{
	int count = 1; // 设置断点次数为1，也就是只中断一次
	return debug_command_set_breakpoint(VM_ARG, debug_info, str, start, cur_filename, &count, my_data);
}

/**
 * 如果输入了无效的命令，则直接返回字符串“无效的命令”给远程调试器
 */
static void debug_command_invalid(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info)
{
	builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "无效的命令\n");
}

/**
 * 如果创建过调试相关的套接字，就通过close将其关闭掉
 */
static void debug_free_socket(int * debug_arg_socket)
{
	int debug_socket = (*debug_arg_socket);
	if(debug_socket != -1) {
		shutdown(debug_socket, SHUT_RDWR);
		if(close(debug_socket) == -1) {
			write_to_server_log_pipe(WRITE_TO_PIPE, "zl debug warning: close socket [%d] failed [%d] %s\n",
							debug_socket, errno, strerror(errno));
		}
		write_to_server_log_pipe(WRITE_TO_PIPE, "zl debug info: close socket [%d]\n", debug_socket);
		(*debug_arg_socket) = -1;
	}
}

/**
 * 通过调试相关的套接字，接收从远程调试器发来的信息，例如用户在远程调试器中输入的调试命令等
 * 接收到的数据会存储到server_reply对应的缓存中
 */
static int debug_recv(int sock, char * server_reply)
{
	int recv_num;
	if((recv_num = recv(sock , server_reply , DEBUG_RECV_SIZE , 0)) < 0) {
		write_to_server_log_pipe(WRITE_TO_PIPE, "zl debug error: recv failed. [%d] %s\n", errno, strerror(errno));
		return -1;
	}
	// 如果在等待接收的过程中，远程调试器终止连接，那么接收到的数据会为空，此时，recv会返回0
	if(recv_num == 0) {
		write_to_server_log_pipe(WRITE_TO_PIPE, "zl debug warning: recv 0 byte. maybe remote connection is closed\n");
		return -1;
	}
	return recv_num;
}

/**
 * 初始化DEBUG_INFO即调试相关的结构体，该结构体中存储了调试相关的套接字，以及需要发送给远程调试器的动态字符串
 */
void debug_init(DEBUG_INFO * debug_info)
{
	memset(debug_info, 0, sizeof(DEBUG_INFO));
	debug_info->socket = -1;
}

/**
 * 如果zenglServer开启了调试功能，那么，在zengl虚拟机关闭之前，需要调用此函数来关闭掉打开的调试套接字，以及释放掉分配过的动态字符串资源
 */
void debug_exit(ZL_EXP_VOID * VM_ARG, DEBUG_INFO * debug_info)
{
	if(debug_info->socket != -1) {
		// 关闭调试相关的套接字
		debug_free_socket(&debug_info->socket);
	}
	// 如果分配过动态字符串，则释放掉动态字符串
	if(debug_info->format_send_msg.str != NULL) {
		zenglApi_FreeMem(VM_ARG, debug_info->format_send_msg.str);
	}
}

/**
 * 中断回调函数，如果zenglServer开启了调试功能，那么当触发断点时，就会调用此回调函数
 * 在该回调函数中，可以接收远程调试器发来的各种调试命令，并将调试结果通过连接套接字反馈给远程调试器
 */
ZL_EXP_INT debug_break(ZL_EXP_VOID * VM_ARG,ZL_EXP_CHAR * cur_filename,
		ZL_EXP_INT cur_line,ZL_EXP_INT breakIndex,ZL_EXP_CHAR * log)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	DEBUG_INFO * debug_info = my_data->debug_info;
	int sock = debug_get_socket(VM_ARG, debug_info);
	int recv_num = 0;
	char server_reply[DEBUG_RECV_SIZE];
	if(sock == -1)
		return -1;

	builtin_reset_info_string(VM_ARG, &debug_info->format_send_msg);
	// 如果当前触发的是日志断点，那么就执行log日志表达式，并将表达式的执行结果反馈给远程调试器，如果执行成功，在反馈完结果后，会直接返回以继续执行
	// 因此，日志断点只会反馈表达式的结果，而不会停下来去接受调试命令，除非表达式执行失败，才会停下来接受命令，因为执行失败很可能是因为日志表达式存在语法错误
	// 停下来接受命令，可以重新设置正确的日志表达式
	if(log != ZL_EXP_NULL)
	{
		if(zenglApi_Debug(VM_ARG,log) == -1) // 如果日志表达式执行出错，则将错误信息反馈给调试器
		{
			write_to_server_log_pipe(WRITE_TO_PIPE, "log日志断点错误：%s",zenglApi_GetErrorString(VM_ARG));
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "log日志断点错误：%s",zenglApi_GetErrorString(VM_ARG));
			if(debug_socket_send(debug_info->socket, debug_info->format_send_msg.str, debug_info->format_send_msg.count) < 0)
				return -1;
			// 远程调试器在接收到数据后，会反馈一个字符串(例如反馈字符串"ok"回来)表示接收到了数据
			recv_num = debug_recv(debug_info->socket, server_reply);
			if(recv_num < 0)
				return -1;
			builtin_reset_info_string(VM_ARG, &debug_info->format_send_msg);
		}
		else
		{
			// 将调试结果转为字符串，存储到format_send_msg动态字符串中，并将其发送给远程调试器
			debug_make_value_str(VM_ARG, debug_info, log);
			if(debug_socket_send(debug_info->socket, debug_info->format_send_msg.str, debug_info->format_send_msg.count) < 0)
				return -1;
			// 远程调试器在接收到数据后，会反馈一个字符串(例如反馈字符串"ok"回来)表示接收到了数据
			recv_num = debug_recv(debug_info->socket, server_reply);
			if(recv_num < 0)
				return -1;
			return 0;
		}
	}
	// 如果是非日志断点，就将当前断点所在的脚本文件名，行号，断点索引等信息反馈给远程调试器
	builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "{\"action\":\"debug\", "
					"\"filename\":\"%s\", \"line\":%d, \"breakIndex\":%d, \"main_script_filename\":\"%s\"}",
					cur_filename, cur_line, breakIndex, my_data->full_path);
	if(debug_socket_send(debug_info->socket, debug_info->format_send_msg.str, debug_info->format_send_msg.count) < 0)
		return -1;
	recv_num = 0;
	int exit = 0;
	const char * message = "";
	while(!exit)
	{
		// 接受用户输入的调试命令，如果没输入命令，会一直阻塞在这里，除非接收时发生错误，或者远程调试器关闭了连接
		recv_num = debug_recv(debug_info->socket, server_reply);
		if(recv_num < 0)
			return -1;
		server_reply[recv_num] = '\0';
		// 如果调试命令过长，则反馈警告信息
		if(recv_num >= DEBUG_RECV_SIZE - 10) {
			message = "zl debug warning: debugger command is too long\n";
			if(debug_socket_send(sock , (char *)message , strlen(message)) < 0)
				return -1;
			recv_num = debug_recv(debug_info->socket, server_reply);
			if(recv_num < 0)
				return -1;
			continue;
		}
		// 将接收到的调试命令记录到日志中
		write_to_server_log_pipe(WRITE_TO_PIPE, "zl debug info: debugger command: %s\n", server_reply);
		int start = 0;
		char * command;
		command = debug_get_arg(server_reply,&start,ZL_EXP_TRUE);
		if(command == ZL_EXP_NULL || strlen(command) != 1)
		{
			message = "命令必须是一个字符\n";
			if(debug_socket_send(sock , (char *)message , strlen(message)) < 0)
				return -1;
			recv_num = debug_recv(debug_info->socket, server_reply);
			if(recv_num < 0)
				return -1;
			continue;
		}
		builtin_reset_info_string(VM_ARG, &debug_info->format_send_msg);
		switch(command[0])
		{
		case 'p': // 执行表达式，并将表达式的结果反馈给远程调试器
			debug_command_print(VM_ARG, debug_info, server_reply, &start, recv_num, DEBUG_RECV_SIZE);
			break;
		case 'b': // 设置断点
			debug_command_set_breakpoint(VM_ARG, debug_info, server_reply, &start, cur_filename, NULL, my_data);
			break;
		case 'B': // 将设置过的断点都列举出来
			debug_command_list_breakpoints(VM_ARG, debug_info, breakIndex, cur_filename, cur_line, server_reply, &start);
			break;
		case 'T': // 获取栈追踪信息，以显示代码的执行情况
			debug_command_stack_backtrace(VM_ARG, debug_info);
			break;
		case 'r': // 执行到返回
			debug_command_run_to_return(VM_ARG, debug_info, &exit);
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "{\"exit\":%d}", exit);
			break;
		case 'd': // 删除某个断点
			debug_command_delete_breakpoint(VM_ARG, debug_info, server_reply, &start);
			break;
		case 'D': // 禁用某个断点
			debug_command_disable_breakpoint(VM_ARG, debug_info, server_reply, &start);
			break;
		case 'C': // 设置条件断点
			debug_command_set_condition_breakpoint(VM_ARG, debug_info, server_reply, &start, recv_num, DEBUG_RECV_SIZE);
			break;
		case 'L': // 设置日志断点
			debug_command_set_log_breakpoint(VM_ARG, debug_info, server_reply, &start, recv_num, DEBUG_RECV_SIZE);
			break;
		case 'N': // 设置断点次数
			debug_command_set_breakpoint_number(VM_ARG, debug_info, server_reply, &start);
			break;
		case 's': // 单步步入，如果遇到脚本函数，则进入脚本函数
			zenglApi_DebugSetSingleBreak(VM_ARG,ZL_EXP_TRUE);
			exit = 1;
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "{\"exit\":%d}", exit);
			break;
		case 'S': // 单步步过，如果遇到脚本函数，则直接执行完脚本函数，而不会进入脚本函数
			zenglApi_DebugSetSingleBreak(VM_ARG,ZL_EXP_FALSE);
			exit = 1;
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "{\"exit\":%d}", exit);
			break;
		case 'c': // 继续执行
			exit = 1;
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "{\"exit\":%d}", exit);
			break;
		case 'e': // 退出，停止执行
			zenglApi_Stop(VM_ARG);
			exit = 1;
			builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "{\"exit\":%d}", exit);
			break;
		case 'h': // 显示帮助信息
			debug_command_help(VM_ARG, debug_info);
			break;
		case 'l': // 查看源码
			if(debug_command_list_file_content(VM_ARG, debug_info, server_reply, &start, my_data) < 0) {
				return -1;
			}
			builtin_reset_info_string(VM_ARG, &debug_info->format_send_msg);
			recv_num = debug_recv(debug_info->socket, server_reply);
			if(recv_num < 0)
				return -1;
			break;
		case 'u': // 执行到指定的行
			exit = 1;
			if(debug_command_until(VM_ARG, debug_info, server_reply, &start, cur_filename, my_data) == 0) {
				builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "{\"exit\":%d}", exit);
			}
			else
				exit = 0;
			break;
		default: // 无效的命令
			debug_command_invalid(VM_ARG, debug_info);
			break;
		}
		if(debug_info->format_send_msg.count > 0) { // 如果在命令执行过程中设置了动态字符串的话，就将动态字符串发送给远程调试器
			if(debug_socket_send(debug_info->socket, debug_info->format_send_msg.str, debug_info->format_send_msg.count) < 0)
				return -1;
			// 远程调试器在接收到数据后，会反馈一个字符串(例如反馈字符串"ok"回来)表示接收到了数据
			recv_num = debug_recv(debug_info->socket, server_reply);
			if(recv_num < 0)
				return -1;
		}
	}
	return 0;
}

/**
 * 在设置条件断点时，如果设置的条件表达式有错误(例如语法错误等)，那么当条件表达式执行出错时，就会触发下面的回调函数
 * 在该回调函数中，会将出错信息反馈给远程调试器
 */
ZL_EXP_INT debug_conditionError(ZL_EXP_VOID * VM_ARG,ZL_EXP_CHAR * filename,
				ZL_EXP_INT line,ZL_EXP_INT breakIndex,ZL_EXP_CHAR * error)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	DEBUG_INFO * debug_info = my_data->debug_info;
	int sock = debug_get_socket(VM_ARG, debug_info);
	if(sock == -1)
		return -1;
	char * condition;
	zenglApi_DebugGetBreak(VM_ARG,breakIndex,ZL_EXP_NULL,ZL_EXP_NULL,&condition,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL,ZL_EXP_NULL);
	write_to_server_log_pipe(WRITE_TO_PIPE, "\nzl debug condition error:%s [%d] <%d %s> error:%s\n",filename,line,breakIndex,condition,error);
	builtin_reset_info_string(VM_ARG, &debug_info->format_send_msg);
	builtin_make_info_string(VM_ARG, &debug_info->format_send_msg, "\nzl debug condition error:%s [%d] <%d %s> error:%s\n",
					filename,line,breakIndex,condition,error);
	if(debug_socket_send(debug_info->socket, debug_info->format_send_msg.str, debug_info->format_send_msg.count) < 0) {
		return -1;
	}
	char server_reply[DEBUG_RECV_SIZE];
	int recv_num = debug_recv(debug_info->socket, server_reply);
	if(recv_num < 0)
		return -1;
	return 0;
}
