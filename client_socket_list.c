/*
 * client_socket_list.c
 *
 *  Created on: 2017-10-24
 *      Author: zengl
 */

#include "client_socket_list.h"
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

void routine_close_client_socket(CLIENT_SOCKET_LIST * socket_list, int lst_idx);

static int on_info(http_parser* p);
static int on_headers_complete(http_parser* p);
static int on_message_complete(http_parser* p);
static int on_url(http_parser* p, const char *at, size_t length);
static int on_header_value(http_parser* p, const char *at, size_t length);
static int on_header_field(http_parser* p, const char *at, size_t length);
static int on_body(http_parser* p, const char *at, size_t length);
static int on_data(http_parser* p, const char *at, size_t length);

/**
 * 从套接字列表中查找某个套接字文件描述符，如果找到该描述符，将对应的列表索引值返回
 */
int client_socket_list_find(CLIENT_SOCKET_LIST * list, int client_socket_fd)
{
	int find_count = 0;
	if(list->count == 0)
		return -1;
	for(int i=0;i < list->size;i++){
		if(client_socket_fd == list->member[i].client_socket_fd) {
			return i;
		}
		if(list->member[i].used) {
			find_count++;
			if(find_count == list->count) {
				break;
			}
		}
	}
	return -1;
}

/**
 * 初始化套接字列表
 */
static int client_socket_list_init(CLIENT_SOCKET_LIST * list)
{
	if(list->member != NULL) {
		return -1;
	}
	list->size = CLIENT_SOCKET_LIST_INIT_SIZE;
	list->count = 0;
	list->member = (CLIENT_SOCKET_LIST_MEMBER *)malloc(list->size * sizeof(CLIENT_SOCKET_LIST_MEMBER));
	if(list->member == NULL) {
		return -2;
	}
	memset(list->member, 0, list->size * sizeof(CLIENT_SOCKET_LIST_MEMBER));
	return 0;
}

/**
 * 将套接字添加到套接字列表中，并返回相应的索引值
 */
static int client_socket_list_add(CLIENT_SOCKET_LIST * list, int client_socket_fd)
{
	if(list->member == NULL) {
		int ret_val = client_socket_list_init(list);
		if(ret_val < 0)
			return ret_val;
	}
	int idx;
	if(list->count == list->size) {
		list->size += CLIENT_SOCKET_LIST_INIT_SIZE;
		list->member = (CLIENT_SOCKET_LIST_MEMBER *)realloc(list->member, list->size * sizeof(CLIENT_SOCKET_LIST_MEMBER));
		memset(list->member + (list->size - CLIENT_SOCKET_LIST_INIT_SIZE), 0, CLIENT_SOCKET_LIST_INIT_SIZE * sizeof(CLIENT_SOCKET_LIST_MEMBER));
		idx = list->count;
		list->member[idx].client_socket_fd = client_socket_fd;
		list->member[idx].used = 1;
		list->member[idx].parser.data = (void *)&(list->member[idx].parser_data);
		http_parser_init(&(list->member[idx].parser), HTTP_REQUEST);
	}
	else {
		for(idx=0;idx < list->size;idx++) {
			if(list->member[idx].used == 0) {
				list->member[idx].parser.data = (void *)&(list->member[idx].parser_data);
				http_parser_init(&(list->member[idx].parser), HTTP_REQUEST);
				list->member[idx].client_socket_fd = client_socket_fd;
				list->member[idx].used = 1;
				break;
			}
		}
		if(idx == list->size)
			return -1;
	}
	list->count++;
	return idx;
}

/**
 * 将套接字列表中idx索引对应的成员释放掉，同时将成员中分配的动态字符串也释放掉
 */
void client_socket_list_free_by_idx(CLIENT_SOCKET_LIST * list, int idx)
{
	if(idx < 0 || idx >= list->size) {
		return;
	}
	dynamic_string_free(&(list->member[idx].parser_data.request_url));
	dynamic_string_free(&(list->member[idx].parser_data.request_header));
	dynamic_string_free(&(list->member[idx].parser_data.request_body));
	dynamic_string_free(&(list->member[idx].send_data));
	list->member[idx].send_data_cur = 0;
	list->member[idx].parser_data.header_complete = 0;
	list->member[idx].parser_data.message_complete = 0;
	list->member[idx].parser_data.header_status = ON_HEADER_STATUS_ENUM_NONE;
	list->member[idx].parser_data.is_request_body_append_null = ZL_EXP_FALSE;
	memset(&(list->member[idx].parser_data.url_parser), 0, sizeof(struct http_parser_url));
	memset(&(list->member[idx].parser), 0, sizeof(struct http_parser));
	list->member[idx].used = 0;
	close(list->member[idx].client_socket_fd);
	list->member[idx].client_socket_fd = 0;
	list->count--;
	if(list->count < 0)
		list->count = 0;
}

/**
 * 将客户端请求的处理结果(需要响应给客户端的数据)写入到套接字列表中idx成员对应的输出缓存(也是一个动态字符串)
 */
void client_socket_list_append_send_data(CLIENT_SOCKET_LIST * list, int idx, void * data, int data_len)
{
	dynamic_string_append(&(list->member[idx].send_data), (char *)data, data_len, CLIENT_SOCKET_LIST_SEND_DATA_STR_SIZE);
}

/**
 * 在日志中记录完整的响应头信息
 */
void client_socket_list_log_response_header(CLIENT_SOCKET_LIST * list, int idx)
{
	if(list->member[idx].send_data.count > 0) {
		char * data = list->member[idx].send_data.str;
		// 响应头是以\r\n\r\n结尾的，因此，先确定响应头的结束位置，接着就可以将完整的响应头写入到日志中了
		char * header_last_ptr = strstr(data, "\r\n\r\n");
		if(header_last_ptr != NULL) {
			char prev_char = header_last_ptr[2];
			header_last_ptr[2] = STR_NULL;
			write_to_server_log_pipe(WRITE_TO_PIPE, "response header: %s", data);
			header_last_ptr[2] = prev_char;
		}
	}
}

/**
 * 在调用http_parser_execute函数，解析http协议时，需要传递下面的settings作为参数，
 * 来设置解析时，需要调用的各个回调函数
 */
static http_parser_settings settings = {
  .on_message_begin = on_info,
  .on_headers_complete = on_headers_complete,
  .on_message_complete = on_message_complete,
  .on_header_field = on_header_field,
  .on_header_value = on_header_value,
  .on_url = on_url,
  .on_status = on_data,
  .on_body = on_body
};

/**
 * 处理EPOLLIN事件，下面函数中会先根据client_socket_fd套接字文件描述符，从套接字列表中
 * 搜索是否有该套接字，如果没有，则将其加入到套接字列表中，如果有，则将客户端请求的数据通过recv读取出来，
 * 并通过http_parser_execute进行请求数据的解析，在解析的过程中，会将请求数据的各部分写入到列表成员的不同的动态字符串中，
 * 以方便后续的各种操作，当recv返回EAGAIN或者EWOULDBLOCK错误时，就说明当前可读的数据都读完了，但是，
 * 客户端还有数据没传递过来(可能因为网络延迟等)，这时就直接返回，当下一次当前连接的后续数据到来时，会触发EPOLLIN事件，
 * 并再次进入该函数去处理，直到把所有请求的数据都读取和解析完为止。
 */
int client_socket_list_process_epollin(CLIENT_SOCKET_LIST * list, int client_socket_fd)
{
	int idx = client_socket_list_find(list, client_socket_fd);
	if(idx < 0) {
		idx = client_socket_list_add(list, client_socket_fd);
		if(idx < 0) {
			routine_close_single_socket(client_socket_fd);
			return idx;
		}
	}
	int data_length;
	int total_length = 0;
	size_t parsed;
	char buffer[1025];
	do {
		data_length = recv(client_socket_fd, buffer, (sizeof(buffer) - 1), 0);
		if(data_length > 0) {
			total_length += data_length;
		}
		if(data_length == -1) {
			if(errno == EAGAIN || errno == EWOULDBLOCK) {
				return CLIENT_EPOLL_EAGAIN_ERRNO;
			}
			else {
				write_to_server_log_pipe(WRITE_TO_PIPE, " **** error:[%d] %s\n", errno, strerror(errno));
				routine_close_client_socket(list, idx);
				return -1;
			}
		}
		else if(data_length == 0) {
			write_to_server_log_pipe(WRITE_TO_PIPE, " **** warning: 0 data length occured");
			write_to_server_log_pipe(WRITE_TO_PIPE, " %d[%d]\n", data_length, total_length);
			routine_close_client_socket(list, idx);
			return -1;
		}
		parsed = http_parser_execute(&(list->member[idx].parser), &settings, buffer, data_length);
		if(parsed != data_length) {
			write_to_server_log_pipe(WRITE_TO_PIPE, " **** parser error: parsed[%d] != data_length[%d]", (int)parsed, data_length);
			routine_close_client_socket(list, idx);
			return -1;
		}
		if(list->member[idx].parser_data.header_complete) {
			if(list->member[idx].parser.flags & (F_CHUNKED | F_CONTENTLENGTH)) {
				if(list->member[idx].parser_data.message_complete)
					break;
			}
			else
				break;
		}
	} while(1);
	return idx;
}

/**
 * 处理EPOLLOUT事件，list列表成员中的send_data动态字符串中包含了需要输出给客户端的响应数据，
 * 通过循环调用send将数据发送出去，如果输出数据比较大时，send可能会返回EAGAIN或者EWOULDBLOCK错误，
 * 表示当前客户端连接对应的发送缓存区已满了，就直接返回，并在下一次收到EPOLLOUT事件时再进入当前函数，
 * (表示发送缓存区的数据已发送到客户端，可以继续发送数据了)，
 * 在该函数中，继续send，直到将所有需要输出的数据都发送完为止。
 */
int client_socket_list_process_epollout(CLIENT_SOCKET_LIST * list, int idx)
{
	if(idx < 0 || idx >= list->size) {
		return -1;
	}
	int client_socket_fd = list->member[idx].client_socket_fd;
	char * buf = list->member[idx].send_data.str + list->member[idx].send_data_cur;
	size_t buf_len = list->member[idx].send_data.count - list->member[idx].send_data_cur;
	int data_length;
	int total_length = 0;
	do {
		data_length = send(client_socket_fd, buf, buf_len, 0);
		if(data_length > 0) {
			total_length += data_length;
		}
		else if(data_length == -1) {
			if(errno == EAGAIN || errno == EWOULDBLOCK) {
				return CLIENT_EPOLL_EAGAIN_ERRNO;
			}
			else {
				write_to_server_log_pipe(WRITE_TO_PIPE, " **** error:[%d] %s\n", errno, strerror(errno));
				routine_close_client_socket(list, idx);
				return -1;
			}
		}
		else {
			write_to_server_log_pipe(WRITE_TO_PIPE, " **** warning: 0 data length occured when send", errno, strerror(errno));
			write_to_server_log_pipe(WRITE_TO_PIPE, " %d[%d]\n", data_length, total_length);
			routine_close_client_socket(list, idx);
			return -1;
		}

		list->member[idx].send_data_cur += data_length;
		buf_len =  list->member[idx].send_data.count - list->member[idx].send_data_cur;
		if(buf_len == 0) {
			routine_close_client_socket(list, idx);
			return CLIENT_EPOLLOUT_FINISH;
		}
		else {
			buf = list->member[idx].send_data.str + list->member[idx].send_data_cur;
		}
	} while(1);
}

/**
 * 使用http_parser_execute解析http协议时，会调用的回调函数，该函数暂时啥也没做，直接返回
 */
static int on_info(http_parser* p) {
  return 0;
}

/**
 * 使用http_parser_execute解析http协议，当解析完请求头信息时，会调用的回调函数
 */
static int on_headers_complete(http_parser* p) {
	MY_PARSER_DATA * my_data = (MY_PARSER_DATA *)p->data;
	my_data->header_complete = 1;
	char str_null[1];
	str_null[0] = STR_NULL;
	dynamic_string_append(&my_data->request_header, str_null, 1, REQUEST_HEADER_STR_SIZE);
	dynamic_string_append(&my_data->request_url, str_null, 1, REQUEST_URL_STR_SIZE);
  return 0;
}

/**
 * 使用http_parser_execute解析http协议，当解析完body即请求的主体数据时，会调用的回调函数
 */
static int on_message_complete(http_parser* p) {
	MY_PARSER_DATA * my_data = (MY_PARSER_DATA *)p->data;
	my_data->message_complete = 1;
	char str_null[1];
	str_null[0] = STR_NULL;
	dynamic_string_append(&my_data->request_body, str_null, 1, REQUEST_BODY_STR_SIZE);
	my_data->is_request_body_append_null = ZL_EXP_TRUE;
	return 0;
}

/**
 * 使用http_parser_execute解析http协议，当解析url资源路径(包括查询字符串)时，会调用的回调函数，
 * 当url资源路径比较长时，可能会调用多次，每次解析一部分路径信息出来，at指向路径字符串的起始字符位置，
 * length表示路径信息的长度，通过p参数可以传递一些自定义的数据，例如下面就通过p->data里的request_url字段，
 * 将路径信息追加到request_url动态字符串中
 */
static int on_url(http_parser* p, const char *at, size_t length) {
	MY_PARSER_DATA * my_data = (MY_PARSER_DATA *)p->data;
	if((my_data->request_url.count + (int)length) > REQUEST_URL_STR_MAX_SIZE) {
		length = REQUEST_URL_STR_MAX_SIZE - my_data->request_url.count;
		if(length <= 0)
			return 0;
	}
	dynamic_string_append(&my_data->request_url, (char *)at, (int)length, REQUEST_URL_STR_SIZE);
	return 0;
}

/**
 * on_header_value和下面的on_header_field都是http_parser_execute解析http协议时，会调用的回调函数，
 * 这两个回调函数，主要用于解析http头信息中的名值对信息，例如：
 * User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0
 * 那么User-Agent会通过on_header_field解析为字段名，而Mozilla/5.0 ...则会被on_header_value解析为对应的值，
 * 由于http_parser_execute可能会因为头部信息比较长被执行多次，因此，on_header_field与
 * on_header_value都有可能被执行多次，以获取到完整的field: value信息，
 * 例如，第一次执行on_header_value时，可能得到Mozilla/5.0 (Windows NT 的字符串，
 * 第二次执行on_header_value时，可能得到后半部分：6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0
 * 两次执行的结果合在一块，得到完整的value，on_header_field也是同理，
 * 无论是field(字段名)也好，还是对应的value(字段值)也好，都会被追加到request_header动态字符串中，
 * 在zengl脚本里使用request模块中的rqtGetHeaders模块函数获取头部信息时，就会使用到该动态字符串来分解出名值对信息
 */
static int on_header_value(http_parser* p, const char *at, size_t length) {
	MY_PARSER_DATA * my_data = (MY_PARSER_DATA *)p->data;
	if((my_data->request_header.count + (int)length) >= REQUEST_HEADER_STR_MAX_SIZE) {
		return 0;
	}
	if(my_data->header_status == ON_HEADER_STATUS_ENUM_FIELD) {
		char str_null[1];
		str_null[0] = STR_NULL;
		dynamic_string_append(&my_data->request_header, str_null, 1, REQUEST_HEADER_STR_SIZE);
		my_data->header_status = ON_HEADER_STATUS_ENUM_VALUE;
	}
	dynamic_string_append(&my_data->request_header, (char *)at, (int)length, REQUEST_HEADER_STR_SIZE);
	return 0;
}

/**
 * 解释同上面的on_header_value，
 * 通过p参数可以获取到一些额外的数据，例如：request_header动态字符串，
 * 通过at参数获取当前field的起始字符位置，
 * length参数为at字符串的有效长度
 */
static int on_header_field(http_parser* p, const char *at, size_t length) {
	MY_PARSER_DATA * my_data = (MY_PARSER_DATA *)p->data;
	if((my_data->request_header.count + (int)length) >= REQUEST_HEADER_STR_MAX_SIZE){
		return 0;
	}
	if(my_data->header_status == ON_HEADER_STATUS_ENUM_VALUE) {
		char str_null[1];
		str_null[0] = STR_NULL;
		dynamic_string_append(&my_data->request_header, str_null, 1, REQUEST_HEADER_STR_SIZE);
		my_data->header_status = ON_HEADER_STATUS_ENUM_FIELD;
	}
	else if(my_data->header_status == ON_HEADER_STATUS_ENUM_NONE) {
		my_data->header_status = ON_HEADER_STATUS_ENUM_FIELD;
	}
	dynamic_string_append(&my_data->request_header, (char *)at, (int)length, REQUEST_HEADER_STR_SIZE);
	return 0;
}

/**
 * 使用http_parser_execute解析http协议的请求body(主体数据)部分时，会调用的回调函数
 */
static int on_body(http_parser* p, const char *at, size_t length) {
	MY_PARSER_DATA * my_data = (MY_PARSER_DATA *)p->data;
	if((my_data->request_body.count + (int)length) >= REQUEST_BODY_STR_MAX_SIZE) {
		return 0;
	}
	dynamic_string_append(&my_data->request_body, (char *)at, (int)length, REQUEST_BODY_STR_SIZE);
	return 0;
}

/**
 * 使用http_parser_execute解析http协议时，可能会调用的回调函数，暂时没做任何处理
 */
static int on_data(http_parser* p, const char *at, size_t length) {
  return 0;
}
