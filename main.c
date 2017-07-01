#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#include "main.h"
#include "dynamic_string.h"
#include "http_parser.h"
#include "module_request.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
//#include <sys/ipc.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <semaphore.h>
#include <pthread.h>

void *routine(void *arg);

ZL_EXP_INT main_config_run_print(ZL_EXP_CHAR * infoStrPtr, ZL_EXP_INT infoStrCount,ZL_EXP_VOID * VM_ARG);

typedef struct _MY_THREAD_LOCK{
	sem_t * accept_sem;
	pthread_mutex_t lock;
} MY_THREAD_LOCK;

#define PROCESS_NUM 3
#define THREAD_NUM_PER_PROCESS 3
#define THREAD_NUM_MAX 3
#define WEB_ROOT_DEFAULT "webroot"
#define DEFAULT_CONFIG_FILE "config.zl"

MY_THREAD_LOCK my_thread_lock = {0};
int server_socket_fd;
long config_debug_mode = 0;
char config_web_root[150];
char config_zl_debug_log[120];
char * webroot;
char * zl_debug_log;

int main(int argc, char * argv[])
{
	int o;
	char * config_file = NULL;
	while (-1 != (o = getopt(argc, argv, "vhc:"))) {
		switch(o){
		case 'v':
			printf("version: v%d.%d.%d\n", ZLSERVER_MAJOR_VERSION,
					ZLSERVER_MINOR_VERSION,
					ZLSERVER_REVISION);
			return 0;
		case 'c':
			printf("use config: %s\n", optarg);
			config_file = optarg;
			break;
		case 'h':
			printf("usage: ./zenglServer [options]\n" \
					"-v                  show version\n" \
					"-c <config file>    set config file\n" \
					"-h                  show this help\n");
			return 0;
		}
	}
	if(config_file == NULL) {
		printf("use default config: " DEFAULT_CONFIG_FILE "\n");
		config_file = DEFAULT_CONFIG_FILE;
	}

	long port;
	long process_num;
	long thread_num_per_process;
	ZL_EXP_VOID * VM;
	VM = zenglApi_Open();
	zenglApi_SetFlags(VM,(ZENGL_EXPORT_VM_MAIN_ARG_FLAGS)(ZL_EXP_CP_AF_IN_DEBUG_MODE | ZL_EXP_CP_AF_OUTPUT_DEBUG_INFO));
	zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_PRINT,main_config_run_print);
	if(zenglApi_Run(VM, config_file) == -1) //编译执行zengl脚本
	{
		printf("错误：编译执行<%s>失败：%s\n", config_file, zenglApi_GetErrorString(VM));
		zenglApi_Close(VM);
		exit(-1);
	}
	if(zenglApi_GetValueAsInt(VM, "debug_mode", &config_debug_mode) < 0)
		config_debug_mode = 0;
	if(zenglApi_GetValueAsInt(VM,"port", &port) < 0)
		port = 8888;
	if(zenglApi_GetValueAsInt(VM,"process_num", &process_num) < 0)
		process_num = PROCESS_NUM;
	if(zenglApi_GetValueAsInt(VM,"thread_num_per_process", &thread_num_per_process) < 0)
		thread_num_per_process = THREAD_NUM_PER_PROCESS;
	else if(thread_num_per_process > THREAD_NUM_MAX) {
		printf("warning: thread_num_per_process in %s too big, use default thread_num_per_process\n", config_file);
		thread_num_per_process = THREAD_NUM_PER_PROCESS;
	}
	if((webroot = zenglApi_GetValueAsString(VM,"webroot")) == NULL) {
		webroot = WEB_ROOT_DEFAULT;
	}
	else if(strlen(webroot) < sizeof(config_web_root)){
		strncpy(config_web_root, webroot, strlen(webroot));
		config_web_root[strlen(webroot) + 1] = '\0';
		webroot = config_web_root;
	}
	else {
		printf("warning: webroot in %s too long, use default webroot\n", config_file);
		webroot = WEB_ROOT_DEFAULT;
	}
	zl_debug_log = NULL;
	if((zl_debug_log = zenglApi_GetValueAsString(VM,"zl_debug_log")) != NULL) {
		int zl_debug_log_len = strlen(zl_debug_log);
		if(zl_debug_log_len >= sizeof(config_zl_debug_log))
			zl_debug_log_len = sizeof(config_zl_debug_log) - 1;
		strncpy(config_zl_debug_log, zl_debug_log, zl_debug_log_len);
		config_zl_debug_log[zl_debug_log_len] = '\0';
		zl_debug_log = config_zl_debug_log;
	}
	printf("run %s complete, config: \n", config_file);
	printf("port: %ld process_num: %ld thread_num_per_process: %ld\n", port, process_num, thread_num_per_process);
	printf("webroot: %s\n", webroot);
	if(zl_debug_log != NULL)
		printf("zl_debug_log: %s\n", zl_debug_log);
	zenglApi_Close(VM);

	int client_socket_fd;
	//int processNum = PROCESS_NUM;
	struct sockaddr_in server_addr, client_addr;
	server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(server_socket_fd == -1)
	{
		printf("failed to create server socket [%d] %s \n", errno, strerror(errno));
		exit(-1);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons((uint16_t)port);
	int enable = 1;
	if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
	    perror("setsockopt(SO_REUSEADDR) failed");
	    exit(-1);
	}
	if(bind(server_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		printf("failed to bind server socket [%d] %s \n", errno, strerror(errno));
		exit(-1);
	}
	printf("bind done\n");

	listen(server_socket_fd, 10);

	//sem_t * accept_sem;
	sem_unlink("accept_sem");
	my_thread_lock.accept_sem = sem_open("accept_sem", O_CREAT | O_EXCL, 0644, 1);
	if(my_thread_lock.accept_sem <= 0)
	{
		printf("accept sem init failed : [%d] %s \n", errno, strerror(errno));
		exit(-1);
	}
	printf("accept sem initialized.\n");

	int c_len = sizeof(client_addr);

	for(int i=0;i < process_num;i++)
	{
		pid_t childpid = fork();
		if(childpid == 0)
		{
			pthread_t tid[THREAD_NUM_MAX];

			if(pthread_mutex_init(&(my_thread_lock.lock), NULL) != 0)
			{
				printf("thread lock init failed : [%d] %s \n", errno, strerror(errno));
				exit(-1);
			}

			// create all threads
			for (int i = 0; i < thread_num_per_process; i++)
			{
			    pthread_create(&tid[i], NULL, routine, NULL);
			}

			// wait all threads by joining them
			for (int i = 0; i < thread_num_per_process; i++)
			{
			    pthread_join(tid[i], NULL);
			}

			pthread_mutex_destroy(&(my_thread_lock.lock));
			exit(0);
		}
	}

	pid_t childpid;
	int childstatus;
	while ((childpid = waitpid (-1, &childstatus, 0)) > 0)
	{
		//printf("child %d exited\n", pid);
		if (WIFEXITED(childstatus))
		{
			printf("child PID %d exited normally.  Exit number:  %d\n", childpid, WEXITSTATUS(childstatus));
		}
		else
		{
			if (WIFSTOPPED(childstatus))
			{
				printf("child PID %d was stopped by %d\n", childpid, WSTOPSIG(childstatus));
			}
			else
			{
				if (WIFSIGNALED(childstatus))
				{
					printf("child PID %d exited due to signal %d\n.", childpid, WTERMSIG(childstatus));
				}
				else
				{
					perror("child waitpid");
				}
			}
		}
	}

	sem_unlink("accept_sem");
	sem_close(my_thread_lock.accept_sem);
	printf("closed accept_sem\n");
	shutdown(server_socket_fd, SHUT_RDWR);
	printf("shutdowned server socket\n");
	close(server_socket_fd);
	printf("closed server socket\n");
	return 0;
}

ZL_EXP_INT main_config_run_print(ZL_EXP_CHAR * infoStrPtr, ZL_EXP_INT infoStrCount,ZL_EXP_VOID * VM_ARG)
{
	printf("%s\n",infoStrPtr);
	return 0;
}

ZL_EXP_INT main_userdef_run_print(ZL_EXP_CHAR * infoStrPtr, ZL_EXP_INT infoStrCount,ZL_EXP_VOID * VM_ARG)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	// write(my_data->client_socket_fd, infoStrPtr, infoStrCount);
	// write(my_data->client_socket_fd, "\n", 1);
	dynamic_string_append(&my_data->response_body, infoStrPtr, infoStrCount, RESPONSE_BODY_STR_SIZE);
	dynamic_string_append(&my_data->response_body, "\n", 1, RESPONSE_BODY_STR_SIZE);
	return 0;
}

ZL_EXP_INT main_userdef_run_info(ZL_EXP_CHAR * infoStrPtr, ZL_EXP_INT infoStrCount,ZL_EXP_VOID * VM_ARG)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	fprintf(my_data->zl_debug_log,"%s",infoStrPtr);
	return 0;
}

ZL_EXP_VOID main_userdef_module_init(ZL_EXP_VOID * VM_ARG)
{
	zenglApi_SetModInitHandle(VM_ARG,"request", module_request_init);
}

static int on_info(http_parser* p) {
  return 0;
}

static int on_headers_complete(http_parser* p) {
	MY_PARSER_DATA * my_data = (MY_PARSER_DATA *)p->data;
	my_data->header_complete = 1;
	char str_null[1];
	str_null[0] = STR_NULL;
	dynamic_string_append(&my_data->request_header, str_null, 1, REQUEST_HEADER_STR_SIZE);
	dynamic_string_append(&my_data->request_url, str_null, 1, REQUEST_URL_STR_SIZE);
  return 0;
}

static int on_message_complete(http_parser* p) {
	MY_PARSER_DATA * my_data = (MY_PARSER_DATA *)p->data;
	my_data->message_complete = 1;
	char str_null[1];
	str_null[0] = STR_NULL;
	dynamic_string_append(&my_data->request_body, str_null, 1, REQUEST_BODY_STR_SIZE);
	return 0;
}

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

static int on_body(http_parser* p, const char *at, size_t length) {
	MY_PARSER_DATA * my_data = (MY_PARSER_DATA *)p->data;
	if((my_data->request_body.count + (int)length) >= REQUEST_BODY_STR_MAX_SIZE) {
		return 0;
	}
	dynamic_string_append(&my_data->request_body, (char *)at, (int)length, REQUEST_BODY_STR_SIZE);
	return 0;
}

static int on_data(http_parser* p, const char *at, size_t length) {
  return 0;
}

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

void * routine(void *arg)
{
	struct sockaddr_in client_addr;
	int c_len = sizeof(client_addr);
	do
	{
		pthread_mutex_lock(&(my_thread_lock.lock));
		sem_wait(my_thread_lock.accept_sem);
		int client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&client_addr, (socklen_t *)&c_len);
		sem_post(my_thread_lock.accept_sem);
		pthread_mutex_unlock(&(my_thread_lock.lock));
		if(client_socket_fd < 0)
		{
			printf("accept failed\n");
			pthread_exit(NULL);
		}
		#ifdef SYS_gettid
			pid_t tid = syscall(SYS_gettid);
		#else
			#error "SYS_gettid unavailable on this system"
		#endif
		printf("Connection accepted, accept pid: %d tid: %d \n", getpid(), tid);

		struct timeval tv;
		tv.tv_sec = 0;  /* Secs Timeout */
		tv.tv_usec = 700000;  // Not init'ing this can cause strange errors
		setsockopt(client_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv,sizeof(struct timeval));

		int recv_fd = open("recv.log", O_APPEND | O_WRONLY | O_CREAT, 0644);
		struct http_parser parser;
		MY_PARSER_DATA parser_data;
		int data_length;
		int total_length = 0;
		size_t parsed;
		char buffer[51];
		parser_data.header_complete = 0;
		parser_data.message_complete = 0;
		parser_data.request_url.str = PTR_NULL;
		parser_data.request_url.count = parser_data.request_url.size = 0;
		parser_data.request_header.str = PTR_NULL;
		parser_data.request_header.count = parser_data.request_header.size = 0;
		parser_data.request_body.str = PTR_NULL;
		parser_data.request_body.count = parser_data.request_body.size = 0;
		parser_data.header_status = ON_HEADER_STATUS_ENUM_NONE;
		parser.data = (void *)&parser_data;
		http_parser_init(&parser, HTTP_REQUEST);

		time_t rawtime;
		struct tm * timeinfo;
		time ( &rawtime );
		timeinfo = localtime ( &rawtime );
		char * current_time = asctime (timeinfo);
		printf("-----------------------------------\n%srecv [client_socket_fd:%d]:", current_time, client_socket_fd);
		fflush(stdout);
		write(recv_fd, "\n", 1);
		write(recv_fd, current_time, strlen(current_time));
		write(recv_fd, "\n", 1);

		int retry_timeout = 0;
		do {
			data_length = recv(client_socket_fd, buffer, (sizeof(buffer) - 1), 0);
			total_length += data_length;
			if(data_length == -1) {
				if(errno == EAGAIN) { // time out
					if(total_length <= 0 || retry_timeout >= 3) {
						printf(" timeout...\n");
						close(recv_fd);
						goto end;
					}
					else {
						retry_timeout++;
						continue;
					}
				}
				else {
					printf(" **** error:[%d] %s\n", errno, strerror(errno));
					close(recv_fd);
					goto end;
				}
			}
			else if(data_length == 0) {
				printf(" **** warning: 0 data length occured");
				printf(" %d[%d]", data_length, total_length);
				if(total_length > 0) {
					break;
				}
				else {
					close(recv_fd);
					goto end;
				}
			}
			printf(" %d[%d]", data_length, total_length);
			fflush(stdout);
			write(recv_fd, buffer, data_length);
			parsed = http_parser_execute(&parser, &settings, buffer, data_length);
			if(parsed != data_length) {
				printf(" **** parser error: parsed[%d] != data_length[%d]", (int)parsed, data_length);
				close(recv_fd);
				goto end;
			}
			if(parser_data.header_complete) {
				if(parser.flags & (F_CHUNKED | F_CONTENTLENGTH)) {
					if(parser_data.message_complete)
						break;
				}
				else
					break;
			}
		} while(1);
		close(recv_fd);
		printf("\n\n");

		printf("url: %s\n", parser_data.request_url.str);
		if(http_parser_parse_url(parser_data.request_url.str, strlen(parser_data.request_url.str), 0, &parser_data.url_parser)) {
			printf("**** failed to parse URL %s ****\n", parser_data.request_url.str);
			goto end;
		}
		char url_path[URL_PATH_SIZE];
		int tmp_len;
		if((parser_data.url_parser.field_set & (1 << UF_PATH)) && (parser_data.url_parser.field_data[UF_PATH].len > 0)) {
			if(parser_data.url_parser.field_data[UF_PATH].len >= URL_PATH_SIZE)
				tmp_len = URL_PATH_SIZE - 1;
			else
				tmp_len = parser_data.url_parser.field_data[UF_PATH].len;
			strncpy(url_path, parser_data.request_url.str + parser_data.url_parser.field_data[UF_PATH].off, tmp_len);
			url_path[tmp_len] = STR_NULL;
		}
		else {
			url_path[0] = '/';
			url_path[1] = STR_NULL;
		}
		printf("url_path: %s\n", url_path);

		int doc_fd;
		char full_path[FULL_PATH_SIZE];
		int status_code = 200;
		if(strlen(url_path) == 1 && url_path[0] == '/') {
			tmp_len = strlen("/index.html");
			strncpy(full_path, webroot, strlen(webroot));
			strncpy(full_path + strlen(webroot), "/index.html", tmp_len);
			int full_length = strlen(webroot) + tmp_len;
			full_path[full_length] = '\0';
			doc_fd = open(full_path, O_RDONLY);
		}
		else {
			int webroot_length = strlen(webroot);
			if(webroot_length >= FULL_PATH_SIZE)
				webroot_length = FULL_PATH_SIZE - 1;
			if(webroot_length > 0)
				strncpy(full_path, webroot, webroot_length);
			int url_path_length = strlen(url_path);
			if(url_path_length >= (FULL_PATH_SIZE - webroot_length))
				url_path_length = FULL_PATH_SIZE - webroot_length - 1;
			if(url_path_length > 0)
				strncpy(full_path + webroot_length, url_path, url_path_length);
			int full_length = webroot_length + url_path_length;
			full_path[full_length] = '\0';

			if(full_length > 3 && strncmp(full_path + (full_length - 3), ".zl", 3) == 0) {
				MAIN_DATA my_data;
				my_data.client_socket_fd = client_socket_fd;
				my_data.zl_debug_log = NULL;
				my_data.headers_memblock.ptr = ZL_EXP_NULL;
				my_data.headers_memblock.index = 0;
				my_data.query_memblock.ptr = ZL_EXP_NULL;
				my_data.query_memblock.index = 0;
				my_data.my_parser_data = &parser_data;
				my_data.response_body.str = PTR_NULL;
				my_data.response_body.count = my_data.response_body.size = 0;
				ZL_EXP_VOID * VM;
				VM = zenglApi_Open();
				zenglApi_SetFlags(VM,(ZENGL_EXPORT_VM_MAIN_ARG_FLAGS)(ZL_EXP_CP_AF_IN_DEBUG_MODE | ZL_EXP_CP_AF_OUTPUT_DEBUG_INFO));
				if(config_debug_mode && (zl_debug_log != NULL)) {
					my_data.zl_debug_log = fopen(zl_debug_log,"w+");
					if(my_data.zl_debug_log != NULL)
						zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_INFO,main_userdef_run_info);
				}
				zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_PRINT,main_userdef_run_print);
				zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_MODULE_INIT,main_userdef_module_init);
				zenglApi_SetExtraData(VM, "my_data", &my_data);
				if(zenglApi_Run(VM, full_path) == -1) //编译执行zengl脚本
				{
					printf("错误：编译执行<%s>失败：%s\n",full_path, zenglApi_GetErrorString(VM));
					send(client_socket_fd, "HTTP/1.1 500 Internal Server Error\r\n", 36, 0);
					dynamic_string_append(&my_data.response_body, "500 Internal Server Error", 25, 200);
				}
				else {
					send(client_socket_fd, "HTTP/1.1 200 OK\r\n", 17, 0);
				}
				zenglApi_Close(VM);
				if(my_data.zl_debug_log != NULL) {
					fclose(my_data.zl_debug_log);
				}
				char response_content_length[20];
				sprintf(response_content_length, "%d", my_data.response_body.count);
				send(client_socket_fd, "Content-Length: ", 16, 0);
				send(client_socket_fd, response_content_length, strlen(response_content_length), 0);
				send(client_socket_fd, "\r\nConnection: Closed\r\nServer: zenglServer\r\n\r\n", 45, 0);
				send(client_socket_fd, my_data.response_body.str, my_data.response_body.count, 0);
				dynamic_string_free(&my_data.response_body);
				doc_fd = -1;
			}
			else {
				doc_fd = open(full_path, O_RDONLY);
				if(doc_fd == -1) {
					tmp_len = strlen("/404.html");
					strncpy(full_path, webroot, strlen(webroot));
					strncpy(full_path + strlen(webroot), "/404.html", tmp_len);
					full_length = strlen(webroot) + tmp_len;
					full_path[full_length] = '\0';
					doc_fd = open(full_path, O_RDONLY);
					status_code = 404;
				}
			}
		}

		if(doc_fd > 0) {
			send(client_socket_fd, "HTTP/1.1 ", 9, 0);
			switch(status_code){
			case 404:
				send(client_socket_fd, "404 Not Found\r\n", 15, 0);
				break;
			case 200:
				send(client_socket_fd, "200 OK\r\n", 8, 0);
				send(client_socket_fd, "Cache-Control: max-age=120\r\n", 28, 0);
				break;
			}
			char doc_fd_content_length[20];
			sprintf(doc_fd_content_length, "%d", (int)lseek(doc_fd, 0, SEEK_END));
			lseek(doc_fd, 0, SEEK_SET);
			send(client_socket_fd, "Content-Length: ", 16, 0);
			send(client_socket_fd, doc_fd_content_length, strlen(doc_fd_content_length), 0);
			send(client_socket_fd, "\r\nConnection: Closed\r\nServer: zenglServer\r\n\r\n", 45, 0);
			while((data_length = read(doc_fd, buffer, sizeof(buffer))) > 0){
				send(client_socket_fd, buffer, data_length, 0);
			}
			close(doc_fd);
		}
		else if(status_code == 404) {
			send(client_socket_fd, "HTTP/1.1 404 Not Found\r\n", 9, 0);
			send(client_socket_fd, "Connection: Closed\r\nServer: zenglServer\r\n\r\n", 43, 0);
		}

end:
		dynamic_string_free(&parser_data.request_url);
		dynamic_string_free(&parser_data.request_header);
		dynamic_string_free(&parser_data.request_body);
		printf("close client_socket_fd: %d\n===============================\n", client_socket_fd);
		shutdown(client_socket_fd, SHUT_RDWR);
		close(client_socket_fd);
	}
	while(1);
    return NULL;
}
