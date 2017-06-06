#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#include "http_parser.h"
#include "zengl/linux/zengl_exportfuns.h"
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

typedef struct _MY_PARSER_DATA{
	char url[120];
} MY_PARSER_DATA;

typedef struct _MY_DATA{
	int client_socket_fd;
} MY_DATA;

#define PROCESS_NUM 3
#define THREAD_NUM_PER_PROCESS 3
#define THREAD_NUM_MAX 3
#define WEB_ROOT_DEFAULT "webroot"

MY_THREAD_LOCK my_thread_lock = {0};
int server_socket_fd;
char config_web_root[150];
char * webroot;

int main(int argc, char * argv[])
{
	long port;
	long process_num;
	long thread_num_per_process;
	ZL_EXP_VOID * VM;
	VM = zenglApi_Open();
	zenglApi_SetFlags(VM,(ZENGL_EXPORT_VM_MAIN_ARG_FLAGS)(ZL_EXP_CP_AF_IN_DEBUG_MODE | ZL_EXP_CP_AF_OUTPUT_DEBUG_INFO));
	zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_PRINT,main_config_run_print);
	if(zenglApi_Run(VM, "config.zl") == -1) //编译执行zengl脚本
	{
		printf("错误：编译执行<%s>失败：%s\n", "config.zl", zenglApi_GetErrorString(VM));
		zenglApi_Close(VM);
		exit(-1);
	}
	if(zenglApi_GetValueAsInt(VM,"port", &port) < 0)
		port = 8888;
	if(zenglApi_GetValueAsInt(VM,"process_num", &process_num) < 0)
		process_num = PROCESS_NUM;
	if(zenglApi_GetValueAsInt(VM,"thread_num_per_process", &thread_num_per_process) < 0)
		thread_num_per_process = THREAD_NUM_PER_PROCESS;
	else if(thread_num_per_process > THREAD_NUM_MAX) {
		printf("warning: thread_num_per_process in config.zl too big, use default thread_num_per_process\n");
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
		printf("warning: webroot in config.zl too long, use default webroot\n");
		webroot = WEB_ROOT_DEFAULT;
	}
	printf("run config.zl complete, config: \n");
	printf("port: %ld process_num: %ld thread_num_per_process: %ld\n", port, process_num, thread_num_per_process);
	printf("webroot: %s\n", webroot);
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
	MY_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	write(my_data->client_socket_fd, infoStrPtr, infoStrCount);
	write(my_data->client_socket_fd, "\n", 1);
	return 0;
}

static int on_info(http_parser* p) {
  return 0;
}

static int on_url(http_parser* p, const char *at, size_t length) {
	MY_PARSER_DATA * my_data = (MY_PARSER_DATA *)p->data;
	strncpy(my_data->url, at, length);
	my_data->url[length] = '\0';
	return 0;
}

static int on_data(http_parser* p, const char *at, size_t length) {
  return 0;
}

static http_parser_settings settings = {
  .on_message_begin = on_info,
  .on_headers_complete = on_info,
  .on_message_complete = on_info,
  .on_header_field = on_data,
  .on_header_value = on_data,
  .on_url = on_url,
  .on_status = on_data,
  .on_body = on_data
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

		int recv_fd = open("recv.txt", O_WRONLY | O_CREAT, 0644);
		int data_length;
		char buffer[1024];
		data_length = recv(client_socket_fd, buffer, sizeof(buffer), 0);
		write(recv_fd, buffer, data_length);
		close(recv_fd);

		struct http_parser parser;
		MY_PARSER_DATA parser_data;
		parser.data = (void *)&parser_data;
		http_parser_init(&parser, HTTP_REQUEST);
		size_t parsed = http_parser_execute(&parser, &settings, buffer, data_length);

		printf("url: %s\n", parser_data.url);
		int doc_fd;
		char full_path[200];
		int tmp_len;
		if(strlen(parser_data.url) == 1 && parser_data.url[0] == '/') {
			tmp_len = strlen("/index.html");
			strncpy(full_path, webroot, strlen(webroot));
			strncpy(full_path + strlen(webroot), "/index.html", tmp_len);
			int full_length = strlen(webroot) + tmp_len;
			full_path[full_length] = '\0';
			doc_fd = open(full_path, O_RDONLY);
		}
		else {
			strncpy(full_path, webroot, strlen(webroot));
			strncpy(full_path + strlen(webroot), parser_data.url, strlen(parser_data.url));
			int full_length = strlen(webroot) + strlen(parser_data.url);
			full_path[full_length] = '\0';

			if(full_length > 3 && strncmp(full_path + (full_length - 3), ".zl", 3) == 0) {
				MY_DATA my_data;
				my_data.client_socket_fd = client_socket_fd;
				ZL_EXP_VOID * VM;
				VM = zenglApi_Open();
				zenglApi_SetFlags(VM,(ZENGL_EXPORT_VM_MAIN_ARG_FLAGS)(ZL_EXP_CP_AF_IN_DEBUG_MODE | ZL_EXP_CP_AF_OUTPUT_DEBUG_INFO));
				zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_PRINT,main_userdef_run_print);
				zenglApi_SetExtraData(VM, "my_data", &my_data);
				send(client_socket_fd, "HTTP/1.1 200 OK\n\n", 17, 0);
				if(zenglApi_Run(VM, full_path) == -1) //编译执行zengl脚本
				{
					printf("错误：编译执行<%s>失败：%s\n",full_path, zenglApi_GetErrorString(VM));
				}
				zenglApi_Close(VM);
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
				}
			}
		}

		if(doc_fd > 0) {
			send(client_socket_fd, "HTTP/1.1 200 OK\n\n", 17, 0);
			while((data_length = read(doc_fd, buffer, sizeof(buffer))) > 0){
				write(client_socket_fd, buffer, data_length);
			}
			close(doc_fd);
		}

		printf("close client_socket_fd: %d\n", client_socket_fd);
		close(client_socket_fd);
	}
	while(1);
    return NULL;
}
