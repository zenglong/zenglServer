/*
 * client_socket_list.h
 *
 *  Created on: 2017-10-24
 *      Author: zengl
 */

#ifndef CLIENT_SOCKET_LIST_H_
#define CLIENT_SOCKET_LIST_H_

#include "main.h"

#define CLIENT_SOCKET_LIST_INIT_SIZE 10 // 套接字列表初始化和动态扩容的大小
#define CLIENT_SOCKET_LIST_SEND_DATA_STR_SIZE 5000 // 客户端连接的发送缓存(动态字符串)的初始化及动态扩容的大小
#define CLIENT_EPOLL_EAGAIN_ERRNO -10100 // 自定义的错误码
#define CLIENT_EPOLLOUT_FINISH 0 // 处理EPOLLOUT事件时，如果所有需要输出的数据都发送给了客户端时，就返回0，表示响应数据都发送完

// 采用epoll事件驱动方式时，套接字列表中每个成员的结构定义
typedef struct _CLIENT_SOCKET_LIST_MEMBER {
	int client_socket_fd; // 需要处理的套接字文件描述符
	unsigned short int used; // 当前成员是否正在使用中
	struct http_parser parser; // http_parser解析http协议时，需要用到的结构体
	MY_PARSER_DATA parser_data; // 在解析http协议时，可以传递给回调函数的自定义数据
	int send_data_cur; // 下面的send_data中，下一次需要发送给客户端的数据的起始偏移值
	DYNAMIC_STRING send_data; // 需要发送给客户端的缓存数据(动态字符串)
} CLIENT_SOCKET_LIST_MEMBER;

// 客户端套接字列表的结构体的定义
typedef struct _CLIENT_SOCKET_LIST {
	int count; // 列表中实际正在使用的成员数，也可以表示有多少个客户端请求正在处理中(不包括那些没有请求数据的空的连接请求)
	int size;  // 列表当前可以容纳的成员数，当count等于size时，就需要对列表进行动态扩容
	CLIENT_SOCKET_LIST_MEMBER * member; // 该指针指向包含了列表成员的动态数组
} CLIENT_SOCKET_LIST;

int client_socket_list_find(CLIENT_SOCKET_LIST * list, int client_socket_fd);
void client_socket_list_free_by_idx(CLIENT_SOCKET_LIST * list, int idx);
int client_socket_list_process_epollin(CLIENT_SOCKET_LIST * list, int client_socket_fd);
int client_socket_list_process_epollout(CLIENT_SOCKET_LIST * list, int idx);
void client_socket_list_append_send_data(CLIENT_SOCKET_LIST * list, int idx, void * data, int data_len);
void client_socket_list_log_response_header(CLIENT_SOCKET_LIST * list, int idx);

#endif /* CLIENT_SOCKET_LIST_H_ */
