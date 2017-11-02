/*
 * main.h
 *
 *  Created on: 2017-6-15
 *      Author: zengl
 */

#ifndef MAIN_H_
#define MAIN_H_

#include "common_header.h"
#include "dynamic_string.h"
#include "resources.h"
#include "http_parser.h"
#include <stdio.h>

#define ZLSERVER_MAJOR_VERSION 0  // zenglServer 主版本号
#define ZLSERVER_MINOR_VERSION 3  // zenglServer 子版本号
#define ZLSERVER_REVISION 0       // zenglServer 修正版本号

#define URL_PATH_SIZE 120    // main.c中url_path可以容纳的字符数
#define FULL_PATH_SIZE 200   // main.c中full_path完整路径可以容纳的字符数

#define REQUEST_HEADER_STR_SIZE 200   // MY_PARSER_DATA结构体中request_header动态字符串初始化及动态扩容的大小
#define REQUEST_BODY_STR_SIZE 200     // MY_PARSER_DATA结构体中request_body动态字符串初始化及动态扩容的大小
#define REQUEST_URL_STR_SIZE 200      // MY_PARSER_DATA结构体中request_url动态字符串初始化及动态扩容的大小
#define RESPONSE_BODY_STR_SIZE 2000   // MAIN_DATA结构体中response_body动态字符串初始化及动态扩容的大小

#define REQUEST_HEADER_STR_MAX_SIZE 5000  // request_header动态字符串的最大允许长度
#define REQUEST_BODY_STR_MAX_SIZE 200000  // request_body动态字符串的最大允许长度
#define REQUEST_URL_STR_MAX_SIZE 1024     // request_url动态字符串的最大允许长度

#define WRITE_TO_PIPE 1
#define WRITE_TO_LOG 0

// 在解析请求头信息中的field和value时，会用到的枚举状态
typedef enum _ON_HEADER_STATUS{
	ON_HEADER_STATUS_ENUM_NONE,
	ON_HEADER_STATUS_ENUM_VALUE,
	ON_HEADER_STATUS_ENUM_FIELD,
} ON_HEADER_STATUS;

// http_parser_execute解析http协议时，会将该结构体作为自定义数据传递给http_parser，
// 这样在解析过程中，就可以设置一些自定义的值，例如：header_complete表示请求头是否解析完毕等等
typedef struct _MY_PARSER_DATA{
	int header_complete;   // 标识请求头是否解析完毕
	int message_complete;  // 标识请求主体数据是否解析完毕
	ON_HEADER_STATUS header_status;    // 解析请求头中的field和value时，要用到的枚举状态
	struct http_parser_url url_parser; // url资源路径和查询字符串的解析结果会存储在该字段对应的结构体中
	DYNAMIC_STRING request_url;     // 该动态字符串用于存储解析到的完整的url资源路径(包含查询字符串在内)
	DYNAMIC_STRING request_header;  // 该动态字符串用于存储所有的field和value字符串，field和value之间通过\0字符串终止符来进行分隔
	DYNAMIC_STRING request_body;    // 该动态字符串用于存储解析到的请求主体数据
	ZL_EXP_BOOL is_request_body_append_null; // 请求body主体数据对应的动态字符串是否追加了NULL终止字符(正常情况下都会追加)，追加了则动态字符串的字节数会比实际追加的请求主体数据的字节数多一个字节
} MY_PARSER_DATA;

// 该结构体用于在工作线程中，传递给zengl脚本作为额外数据用的
typedef struct _MAIN_DATA{
	int client_socket_fd; // 客户端套接字文件描述符，通过该套接字文件描述符，可以直接向客户端输出信息
	FILE * zl_debug_log;  // zengl调试日志，用于存储zengl脚本的虚拟汇编指令等调试信息
	ZENGL_EXPORT_MEMBLOCK headers_memblock; // 该内存块作为哈希数组，用于存储请求头中所有的field和value构成的名值对信息
	ZENGL_EXPORT_MEMBLOCK query_memblock;   // 该内存块作为哈希数组，用于存储查询字符串中所有的名值对信息
	ZENGL_EXPORT_MEMBLOCK body_memblock;    // 该内存块作为哈希数组，用于存储解析后的body名值对信息
	MY_PARSER_DATA * my_parser_data; // 需要依赖该结构里的解析结果来获取各种所需的数据，例如：里面的url_parser字段，可以用于获取查询字符串等
	DYNAMIC_STRING response_body;    // zengl脚本的输出内容会先追加到response_body动态字符串中，最后在脚本结束时，再将该动态字符串作为响应主体反馈给客户端
	RESOURCE_LIST resource_list; // 资源列表中存储了在脚本退出时，需要自动清理的资源，例如mysql数据库连接资源，mysql查询结果相关的资源等等
	char * full_path;
} MAIN_DATA;

char * main_get_webroot();
int main_full_path_append(char * full_path, int full_path_length, int full_path_size, char * append_path);
int write_to_server_log_pipe(ZL_EXP_BOOL write_to_pipe, const char * format, ...);
void routine_close_single_socket(int client_socket_fd);

#endif /* MAIN_H_ */
