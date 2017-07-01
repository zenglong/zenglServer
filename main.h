/*
 * main.h
 *
 *  Created on: 2017-6-15
 *      Author: zengl
 */

#ifndef MAIN_H_
#define MAIN_H_

#include "zengl/linux/zengl_exportfuns.h"
#include "dynamic_string.h"
#include "http_parser.h"
#include <stdio.h>

#define ZLSERVER_MAJOR_VERSION 0  // zenglServer 主版本号
#define ZLSERVER_MINOR_VERSION 1  // zenglServer 子版本号
#define ZLSERVER_REVISION 0       // zenglServer 修正版本号

#define URL_PATH_SIZE 120
#define FULL_PATH_SIZE 200

#define REQUEST_HEADER_STR_SIZE 200
#define REQUEST_BODY_STR_SIZE 200
#define REQUEST_URL_STR_SIZE 200
#define RESPONSE_BODY_STR_SIZE 2000

#define REQUEST_HEADER_STR_MAX_SIZE 5000
#define REQUEST_BODY_STR_MAX_SIZE 200000
#define REQUEST_URL_STR_MAX_SIZE 1024

typedef enum _ON_HEADER_STATUS{
	ON_HEADER_STATUS_ENUM_NONE,
	ON_HEADER_STATUS_ENUM_VALUE,
	ON_HEADER_STATUS_ENUM_FIELD,
} ON_HEADER_STATUS;

typedef struct _MY_PARSER_DATA{
	int header_complete;
	int message_complete;
	ON_HEADER_STATUS header_status;
	struct http_parser_url url_parser;
	DYNAMIC_STRING request_url;
	DYNAMIC_STRING request_header;
	DYNAMIC_STRING request_body;
} MY_PARSER_DATA;

typedef struct _MAIN_DATA{
	int client_socket_fd;
	FILE * zl_debug_log;
	ZENGL_EXPORT_MEMBLOCK headers_memblock;
	ZENGL_EXPORT_MEMBLOCK query_memblock;
	MY_PARSER_DATA * my_parser_data;
	DYNAMIC_STRING response_body;
} MAIN_DATA;

#endif /* MAIN_H_ */
