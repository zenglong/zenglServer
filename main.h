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

#define REQUEST_HEADER_STR_SIZE 200
#define REQUEST_BODY_STR_SIZE 200

#define REQUEST_HEADER_STR_MAX_SIZE 5000
#define REQUEST_BODY_STR_MAX_SIZE 200000

typedef enum _ON_HEADER_STATUS{
	ON_HEADER_STATUS_ENUM_NONE,
	ON_HEADER_STATUS_ENUM_VALUE,
	ON_HEADER_STATUS_ENUM_FIELD,
} ON_HEADER_STATUS;

typedef struct _MY_PARSER_DATA{
	char url[120];
	int header_complete;
	int message_complete;
	ON_HEADER_STATUS header_status;
	DYNAMIC_STRING request_header;
	DYNAMIC_STRING request_body;
} MY_PARSER_DATA;

typedef struct _MAIN_DATA{
	int client_socket_fd;
	ZENGL_EXPORT_MEMBLOCK headers_memblock;
	MY_PARSER_DATA * my_parser_data;
} MAIN_DATA;

#endif /* MAIN_H_ */
