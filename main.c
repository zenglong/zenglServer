#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#include "main.h"
#include "dynamic_string.h"
/**
 * zenglServer主要是依靠 http_parser 这个第三方的解析程式来解析http协议的，
 * 该程式的项目地址：https://github.com/nodejs/http-parser
 */
#include "http_parser.h"
#include "module_request.h"
#include "module_builtin.h"
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

// 每个创建的线程会执行的例程
void *routine(void *arg);

// 由于配置文件是使用zengl脚本语法编写的，当在配置文件中使用print指令时，就会调用下面的回调函数，去执行具体的打印操作
ZL_EXP_INT main_config_run_print(ZL_EXP_CHAR * infoStrPtr, ZL_EXP_INT infoStrCount,ZL_EXP_VOID * VM_ARG);

typedef struct _MY_THREAD_LOCK{
	sem_t * accept_sem;    // 进程锁(通过信号量执行加锁操作)
	pthread_mutex_t lock;  // 线程锁
} MY_THREAD_LOCK;

#define PROCESS_NUM 3 // 如果在配置文件中没有设置process_num时，就使用该宏的值作为需要创建的进程数
#define THREAD_NUM_PER_PROCESS 3 // 如果在配置文件中没有设置thread_num_per_process时，就使用该宏的值作为每个进程中需要创建的线程数
#define THREAD_NUM_MAX 3 // 如果配置文件中设置的thread_num_per_process的值超过该宏定义的允许的最大值时，就会使用上面THREAD_NUM_PER_PROCESS宏定义的值来作为需要创建的线程数
#define WEB_ROOT_DEFAULT "webroot" // 如果配置文件中没有设置webroot时，就使用该宏对应的目录名作为web的根目录的目录名
#define DEFAULT_CONFIG_FILE "config.zl" // 当启动zenglServer时，如果没有使用-c命令行参数来指定配置文件名时，就会使用该宏对应的值来作为默认的配置文件名

MY_THREAD_LOCK my_thread_lock = {0}; // 全局锁变量，包含了进程锁和线程锁
int server_socket_fd; // zenglServer的服务端套接字对应的文件描述符
long config_debug_mode = 0; // 该全局变量用于存储配置文件中的debug_mode的值，用于判断当前的配置是否处于调试模式
char config_web_root[150];  // 该全局变量用于存储配置文件中的webroot对应的字符串值，也就是web根目录对应的目录名
char config_zl_debug_log[120]; // 该全局变量用于存储配置文件中的zl_debug_log的值，也就是zengl脚本的调试日志文件，里面存储了脚本对应的虚拟汇编指令，仅用于调试zengl脚本库的BUG时才需要用到
char * webroot; // 该字符串指针指向最终会使用的web根目录名，当配置文件中配置了webroot时，该指针就会指向上面的config_web_root，否则就指向WEB_ROOT_DEFAULT即默认的web根目录名
char * zl_debug_log; // 该字符串指针指向最终会使用的zl_debug_log的值，当配置文件中设置了zl_debug_log时，就指向上面的config_zl_debug_log，否则就设置为NULL(空指针)

/**
 * zenglServer启动时会执行的入口函数
 */
int main(int argc, char * argv[])
{
	int o;
	char * config_file = NULL;
	// 通过getopt的C库函数来获取用户在命令行中输入的参数，并根据这些参数去执行不同的操作
	while (-1 != (o = getopt(argc, argv, "vhc:"))) {
		switch(o){
		// 当使用-v参数时，会将zenglServer的版本号信息和所使用的zengl脚本语言的版本号信息给显示出来，然后直接返回以退出程序，版本号中会显示主版本号，子版本号和修正版本号
		case 'v':
			printf("zenglServer version: v%d.%d.%d\nzengl language version: v%d.%d.%d\n", ZLSERVER_MAJOR_VERSION,
					ZLSERVER_MINOR_VERSION,
					ZLSERVER_REVISION,
					ZL_EXP_MAJOR_VERSION, ZL_EXP_MINOR_VERSION, ZL_EXP_REVISION);
			return 0;
		// 当使用-c参数时，会使用-c后面的配置文件名来作为启动时需要加载的配置文件
		case 'c':
			printf("use config: %s\n", optarg);
			config_file = optarg;
			break;
		// 当使用-h参数时，会显示出帮助信息，然后直接返回以退出程序
		case 'h':
			printf("usage: ./zenglServer [options]\n" \
					"-v                  show version\n" \
					"-c <config file>    set config file\n" \
					"-h                  show this help\n");
			return 0;
		}
	}
	// 当没有使用-c命令行参数指定配置文件名时，就使用默认的配置文件名
	if(config_file == NULL) {
		printf("use default config: " DEFAULT_CONFIG_FILE "\n");
		config_file = DEFAULT_CONFIG_FILE;
	}

	long port; // 服务端需要绑定的端口号
	long process_num; // 需要创建的进程数
	long thread_num_per_process; // 每个进程需要创建的线程数
	ZL_EXP_VOID * VM; // 由于配置文件是使用zengl脚本语法编写的，因此，需要使用zengl虚拟机来运行该脚本
	VM = zenglApi_Open(); // 打开一个zengl虚拟机
	zenglApi_SetFlags(VM,(ZENGL_EXPORT_VM_MAIN_ARG_FLAGS)(ZL_EXP_CP_AF_IN_DEBUG_MODE | ZL_EXP_CP_AF_OUTPUT_DEBUG_INFO)); // 设置一些调试标志
	zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_PRINT,main_config_run_print); // 设置zengl脚本中print指令会执行的回调函数
	if(zenglApi_Run(VM, config_file) == -1) //编译执行zengl脚本
	{
		printf("错误：编译执行<%s>失败：%s\n", config_file, zenglApi_GetErrorString(VM));
		zenglApi_Close(VM);
		exit(-1);
	}
	// 执行完配置文件对应的脚本后，获取配置文件中定义的debug_mode的值
	if(zenglApi_GetValueAsInt(VM, "debug_mode", &config_debug_mode) < 0)
		config_debug_mode = 0; // 如果没有定义debug_mode，则将config_debug_mode设置为0，表示当前配置处于非调试模式

	// 获取配置文件中定义的port的值，也就是需要绑定的端口号
	if(zenglApi_GetValueAsInt(VM,"port", &port) < 0)
		port = 8888; // 如果没有设置，则使用默认的8888作为端口号

	// 获取配置文件中定义的process_num的值，也就是需要创建的进程数
	if(zenglApi_GetValueAsInt(VM,"process_num", &process_num) < 0)
		process_num = PROCESS_NUM; // 如果没有设置，则使用PROCESS_NUM宏定义的值

	// 获取配置文件中定义的thread_num_per_process的值，也就是每个进程需要创建的线程数
	if(zenglApi_GetValueAsInt(VM,"thread_num_per_process", &thread_num_per_process) < 0)
		thread_num_per_process = THREAD_NUM_PER_PROCESS; // 如果没有设置，则使用THREAD_NUM_PER_PROCESS宏定义的值
	// 如果thread_num_per_process的值超过THREAD_NUM_MAX允许的最大值，则将其重置为THREAD_NUM_PER_PROCESS对应的值
	else if(thread_num_per_process > THREAD_NUM_MAX) {
		printf("warning: thread_num_per_process in %s too big, use default thread_num_per_process\n", config_file);
		thread_num_per_process = THREAD_NUM_PER_PROCESS;
	}

	// 获取配置文件中定义的webroot的值，也就是web根目录名
	if((webroot = zenglApi_GetValueAsString(VM,"webroot")) == NULL) {
		webroot = WEB_ROOT_DEFAULT; // 如果没有定义，则默认使用WEB_ROOT_DEFAULT宏定义的值
	}
	// 如果配置文件中定义的webroot对应的字符串能够存储到全局变量config_web_root中，则将其拷贝到config_web_root中，并将webroot指向config_web_root，
	// 因为当虚拟机被关闭时，会释放掉虚拟机分配过的所有字符串资源，所以需要将字符串保存到其他地方
	else if(strlen(webroot) < sizeof(config_web_root)){
		strncpy(config_web_root, webroot, strlen(webroot));
		config_web_root[strlen(webroot) + 1] = '\0';
		webroot = config_web_root;
	}
	// 否则抛出警告，并使用默认的web根目录名
	else {
		printf("warning: webroot in %s too long, use default webroot\n", config_file);
		webroot = WEB_ROOT_DEFAULT;
	}
	zl_debug_log = NULL;
	// 获取配置文件中设置的zl_debug_log的值，如果没有设置，则将zl_debug_log全局变量设置为NULL
	if((zl_debug_log = zenglApi_GetValueAsString(VM,"zl_debug_log")) != NULL) {
		int zl_debug_log_len = strlen(zl_debug_log);
		// 将配置文件中设置的zl_debug_log拷贝到全局变量config_zl_debug_log中，并确保其不会超出config_zl_debug_log可以容纳的字符数范围
		if(zl_debug_log_len >= sizeof(config_zl_debug_log))
			zl_debug_log_len = sizeof(config_zl_debug_log) - 1;
		strncpy(config_zl_debug_log, zl_debug_log, zl_debug_log_len);
		config_zl_debug_log[zl_debug_log_len] = '\0';
		zl_debug_log = config_zl_debug_log;
	}
	// 显示出配置文件中定义的配置信息，如果配置文件没有定义这些值，则显示出默认值
	printf("run %s complete, config: \n", config_file);
	printf("port: %ld process_num: %ld thread_num_per_process: %ld\n", port, process_num, thread_num_per_process);
	printf("webroot: %s\n", webroot);
	if(zl_debug_log != NULL)
		printf("zl_debug_log: %s\n", zl_debug_log);
	// 关闭虚拟机，并释放掉虚拟机所分配过的系统资源
	zenglApi_Close(VM);

	struct sockaddr_in server_addr;
	// 创建服务端套接字
	server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(server_socket_fd == -1)
	{
		printf("failed to create server socket [%d] %s \n", errno, strerror(errno));
		exit(-1);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY; // 将套接字绑定到任意IP，除了本机可以访问外，外部网络也可以通过IP加端口号来访问到zenglServer
	server_addr.sin_port = htons((uint16_t)port); // 将套接字绑定到指定的端口
	int enable = 1;
	// 开启套接字的REUSEADDR选项，这样，当zenglServer关闭后，可以马上启动并重新绑定到该端口(否则，就需要等待一段时间，可能需要等待好几分钟才能再次绑定到同一个端口)
	if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
	    perror("setsockopt(SO_REUSEADDR) failed");
	    exit(-1);
	}
	// 将服务端套接字绑定到server_addr所指定的IP和端口上
	if(bind(server_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		printf("failed to bind server socket [%d] %s \n", errno, strerror(errno));
		exit(-1);
	}
	printf("bind done\n");

	// 当绑定IP和端口成功后，就可以正式开启服务端套接字的监听模式了
	listen(server_socket_fd, 10);

	// 删除掉之前创建过的信号量
	sem_unlink("accept_sem");
	// 创建一个新的信号量，用于实现多个进程间的加锁操作，sem_open的最后一个参数为1，表示只允许一个进程获取信号量并执行相关操作
	my_thread_lock.accept_sem = sem_open("accept_sem", O_CREAT | O_EXCL, 0644, 1);
	if(my_thread_lock.accept_sem <= 0)
	{
		printf("accept sem init failed : [%d] %s \n", errno, strerror(errno));
		exit(-1);
	}
	printf("accept sem initialized.\n");

	// 根据process_num的值，创建多个子进程，如果是调试模式，一般就设置一个子进程，方便gdb调试
	for(int i=0;i < process_num;i++)
	{
		// 通过fork创建子进程
		pid_t childpid = fork();
		// 如果childpid等于0，说明当前进程是子进程，就循环创建工作线程
		if(childpid == 0)
		{
			pthread_t tid[THREAD_NUM_MAX];

			// 初始化线程互斥锁
			if(pthread_mutex_init(&(my_thread_lock.lock), NULL) != 0)
			{
				printf("thread lock init failed : [%d] %s \n", errno, strerror(errno));
				exit(-1);
			}

			// 根据thread_num_per_process的值，循环创建线程，并将线程的执行例程设置为routine函数
			for (int i = 0; i < thread_num_per_process; i++)
			{
			    pthread_create(&tid[i], NULL, routine, NULL);
			}

			// 通过join线程，来等待所有的线程结束
			for (int i = 0; i < thread_num_per_process; i++)
			{
			    pthread_join(tid[i], NULL);
			}

			// 如果所有的线程都结束的话，就销毁线程锁，并退出当前子进程，正常情况下，线程不会退出(因为routine中是一个无限循环)，除非是发生严重的系统异常
			pthread_mutex_destroy(&(my_thread_lock.lock));
			exit(0);
		}
	}

	pid_t childpid;
	int childstatus;
	// 循环等待所有子进程退出，并显示出这些子进程退出的原因，一般是发生严重异常时，才会导致子进程退出
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

	// 如果所有子进程都退出了，就释放相关资源，并返回以退出程序
	sem_unlink("accept_sem");
	sem_close(my_thread_lock.accept_sem);
	printf("closed accept_sem\n");
	shutdown(server_socket_fd, SHUT_RDWR);
	printf("shutdowned server socket\n");
	close(server_socket_fd);
	printf("closed server socket\n");
	return 0;
}

/**
 * 由于配置文件是使用zengl脚本语法编写的，当在配置文件中使用print指令时，就会调用下面的回调函数，去执行具体的打印操作，
 * 该函数将信息直接通过printf显示出来
 */
ZL_EXP_INT main_config_run_print(ZL_EXP_CHAR * infoStrPtr, ZL_EXP_INT infoStrCount,ZL_EXP_VOID * VM_ARG)
{
	printf("%s\n",infoStrPtr);
	return 0;
}

/**
 * 在工作线程中，当在zengl脚本里使用print指令时，会调用下面的回调函数，将字符串信息追加到response_body动态字符串中，
 * 在脚本结束后，会将该动态字符串作为响应body，反馈给客户端
 */
ZL_EXP_INT main_userdef_run_print(ZL_EXP_CHAR * infoStrPtr, ZL_EXP_INT infoStrCount,ZL_EXP_VOID * VM_ARG)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	// write(my_data->client_socket_fd, infoStrPtr, infoStrCount);
	// write(my_data->client_socket_fd, "\n", 1);
	dynamic_string_append(&my_data->response_body, infoStrPtr, infoStrCount, RESPONSE_BODY_STR_SIZE);
	dynamic_string_append(&my_data->response_body, "\n", 1, RESPONSE_BODY_STR_SIZE);
	return 0;
}

/**
 * 当在配置文件中，开启了调试模式后，又设置了zl_debug_log时，就会将zengl脚本的虚拟汇编指令等写入到zl_debug_log对应的调试日志文件中
 */
ZL_EXP_INT main_userdef_run_info(ZL_EXP_CHAR * infoStrPtr, ZL_EXP_INT infoStrCount,ZL_EXP_VOID * VM_ARG)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	fprintf(my_data->zl_debug_log,"%s",infoStrPtr);
	return 0;
}

/**
 * 设置工作线程中，zengl脚本会调用的模块的初始化函数
 */
ZL_EXP_VOID main_userdef_module_init(ZL_EXP_VOID * VM_ARG)
{
	// 设置builtin模块的初始化函数，和builtin模块相关的C函数代码位于module_builtin.c文件里
	zenglApi_SetModInitHandle(VM_ARG,"builtin", module_builtin_init);
	// 设置request模块的初始化函数，和request模块相关的C函数代码位于module_request.c文件里
	zenglApi_SetModInitHandle(VM_ARG,"request", module_request_init);
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
 * 工作线程会执行的例程
 */
void * routine(void *arg)
{
	struct sockaddr_in client_addr;
	int c_len = sizeof(client_addr);
	// 整个线程使用无限循环来循环处理客户端请求，除非发生异常，或者主体程序退出
	do
	{
		// 这里加了两把锁，第一个线程锁主要是针对同一个子进程中不同的线程的
		// 第二个信号量，是用于不同的进程间进行加锁操作的，通过两个锁，从而确保同一时间只有一个子进程中的一个线程能够执行accept操作
		// 当accept接收到客户端请求时，就解开这两把锁，并处理该客户端请求，
		// 当两把锁被解开时，会有另一个线程去执行accept操作(如果还有多余的线程的话)，该线程可以是和之前的线程位于同一个子进程中，
		// 也可以是不同子进程中的线程，但是不管是哪个子进程中的线程，同一时间都只会有一个线程能够执行accept操作
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
		// 通过gettid系统调用来获取到当前的线程ID
		#ifdef SYS_gettid
			pid_t tid = syscall(SYS_gettid);
		#else
			#error "SYS_gettid unavailable on this system"
		#endif
		// 当接收到客户端连接时，将处理该连接请求的进程ID和线程ID打印出来
		printf("Connection accepted, accept pid: %d tid: %d \n", getpid(), tid);

		// 设置客户端套接字的超时时间为：700ms
		struct timeval tv;
		tv.tv_sec = 0;  /* Secs Timeout */
		tv.tv_usec = 700000;  // Not init'ing this can cause strange errors
		setsockopt(client_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv,sizeof(struct timeval));

		// 通过open打开recv.log日志文件，该日志中记录了客户端的请求信息，例如，请求时间，请求头信息，请求主体信息等
		// 这里以追加的方式打开的文件，因此，如果记录的数据过多时，需要手动清理该文件的内容
		int recv_fd = open("recv.log", O_APPEND | O_WRONLY | O_CREAT, 0644);
		// http_parser在解析http协议时，需要传递一个struct http_parser类型的参数，
		// 可以在该参数中设置一些自定义的用户数据，例如下面的parser_data
		struct http_parser parser;
		MY_PARSER_DATA parser_data;
		// data_length用于记录后面的recv操作接收到的数据长度
		int data_length;
		// total_length用于记录接收到的数据的总长度
		int total_length = 0;
		// http_parser在执行具体的解析操作时，会返回一个解析的字节数(存储在parsed变量里)，
		// 如果解析的字节数和原数据的长度不一致时，就表示解析失败
		size_t parsed;
		// 每次recv接收到的数据会先存储在buffer中，然后交由http_parser去执行http协议的解析操作
		char buffer[51];

		// parser_data中定义了一些自定义的数据，例如：header_complete用于表示请求头信息是否解析完毕，
		// message_complete表示请求的主体数据是否解析完毕(如果包含请求body的话)
		// request_url，request_header以及request_body是三个动态字符串，
		// 分别用于存储url资源路径，请求的头部信息，以及请求的主体数据
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
		// 通过http_parser_init来初始化http_parser
		http_parser_init(&parser, HTTP_REQUEST);

		time_t rawtime;
		struct tm * timeinfo;
		time ( &rawtime );
		timeinfo = localtime ( &rawtime );
		char * current_time = asctime (timeinfo);
		// 将当前时间和客户端套接字对应的描述符给打印出来
		printf("-----------------------------------\n%srecv [client_socket_fd:%d]:", current_time, client_socket_fd);
		fflush(stdout);
		// 将当前时间写入recv.log日志
		write(recv_fd, "\n", 1);
		write(recv_fd, current_time, strlen(current_time));
		write(recv_fd, "\n", 1);

		// 记录接收超时的重试次数
		int retry_timeout = 0;
		do {
			data_length = recv(client_socket_fd, buffer, (sizeof(buffer) - 1), 0);
			total_length += data_length;
			if(data_length == -1) {
				if(errno == EAGAIN) { // time out
					// 当发生接收超时时，如果total_length等于0，则说明没接收到任何数据，就直接结束当前客户端连接，
					// 对于chrome浏览器，会产生一个backup tcp connection(后备连接)，该连接的目的是用于优化浏览器的性能，
					// 在10秒内，如果chrome有数据需要请求的话，就会直接通过该后备连接来传输数据到服务端，但是这样会造成服务端接收到空的连接(就是没有任何接收数据的连接)，
					// 如果recv没有设置超时的话，就会卡在那10秒左右，从而占用服务端的资源，因此，这里的超时主要用于断开chrome的后备空连接
					// 如果total_length不等于0，说明是网络延迟造成的，就尝试3次，累计超过3次也关闭连接
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
			// 使用http_parser_execute去解析接收到的buffer数据
			parsed = http_parser_execute(&parser, &settings, buffer, data_length);
			// 解析的字节数和原数据长度不相等，则说明解析失败，直接关闭连接
			if(parsed != data_length) {
				printf(" **** parser error: parsed[%d] != data_length[%d]", (int)parsed, data_length);
				close(recv_fd);
				goto end;
			}
			// 如果header_complete的值为1，说明请求的头部信息已经解析完毕，如果没有body(请求主体数据)，则break跳出循环，
			// 如果有请求主体数据，那么就等到主体数据也解析完毕后，再跳出循环
			if(parser_data.header_complete) {
				if(parser.flags & (F_CHUNKED | F_CONTENTLENGTH)) {
					if(parser_data.message_complete)
						break;
				}
				else
					break;
			}
		} while(1);
		// 关闭recv.log日志文件
		close(recv_fd);
		printf("\n\n");

		printf("url: %s\n", parser_data.request_url.str);
		// 通过http_parser_parse_url来解析url资源路径(包含查询字符串)，该函数会将路径信息和查询字符串信息给解析出来，并将解析结果存储到url_parser中
		if(http_parser_parse_url(parser_data.request_url.str, strlen(parser_data.request_url.str), 0, &parser_data.url_parser)) {
			printf("**** failed to parse URL %s ****\n", parser_data.request_url.str);
			goto end;
		}
		char url_path[URL_PATH_SIZE];
		int tmp_len;
		// 将解析出来的url路径存储到url_path中
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
		// full_path中存储了需要访问的目标文件的完整路径信息
		char full_path[FULL_PATH_SIZE];
		// status_code存储响应状态码，默认为200
		int status_code = 200;
		// 如果是访问根目录，则将webroot根目录中的index.html文件里的内容，作为结果反馈给客户端
		if(strlen(url_path) == 1 && url_path[0] == '/') {
			tmp_len = strlen("/index.html");
			strncpy(full_path, webroot, strlen(webroot));
			strncpy(full_path + strlen(webroot), "/index.html", tmp_len);
			int full_length = strlen(webroot) + tmp_len;
			full_path[full_length] = '\0';
			// 以只读方式打开文件
			doc_fd = open(full_path, O_RDONLY);
		}
		else {
			// 下面会根据webroot根目录，和url_path来构建full_path完整路径
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

			// 如果要访问的文件是以.zl结尾的，就将该文件当做zengl脚本来进行编译执行
			if(full_length > 3 && strncmp(full_path + (full_length - 3), ".zl", 3) == 0) {
				// my_data是传递给zengl脚本的额外数据，里面包含了客户端套接字等可能需要用到的信息
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
				// 只有在调试模式下，并且在配置文件中，设置了zl_debug_log时，才设置run_info处理函数，该函数会将zengl脚本的虚拟汇编指令写入到指定的日志文件
				if(config_debug_mode && (zl_debug_log != NULL)) {
					my_data.zl_debug_log = fopen(zl_debug_log,"w+");
					if(my_data.zl_debug_log != NULL)
						zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_INFO,main_userdef_run_info);
				}
				// 设置在zengl脚本中使用print指令时，会执行的回调函数
				zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_PRINT,main_userdef_run_print);
				// 设置zengl脚本的模块初始化函数
				zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_MODULE_INIT,main_userdef_module_init);
				// 设置my_data额外数据
				zenglApi_SetExtraData(VM, "my_data", &my_data);
				if(zenglApi_Run(VM, full_path) == -1) //编译执行zengl脚本
				{
					// 如果执行失败，则显示错误信息，并抛出500内部错误给客户端
					printf("错误：编译执行<%s>失败：%s\n",full_path, zenglApi_GetErrorString(VM));
					send(client_socket_fd, "HTTP/1.1 500 Internal Server Error\r\n", 36, 0);
					dynamic_string_append(&my_data.response_body, "500 Internal Server Error", 25, 200);
				}
				else {
					send(client_socket_fd, "HTTP/1.1 200 OK\r\n", 17, 0);
				}
				// 关闭zengl虚拟机及zl_debug_log日志文件
				zenglApi_Close(VM);
				if(my_data.zl_debug_log != NULL) {
					fclose(my_data.zl_debug_log);
				}
				// zengl脚本中的输出数据会写入到my_data里的response_body动态字符串中，
				// 因此，将response_body动态字符串的长度作为Content-Length，并将其作为响应内容，反馈给客户端
				char response_content_length[20];
				sprintf(response_content_length, "%d", my_data.response_body.count);
				send(client_socket_fd, "Content-Length: ", 16, 0);
				send(client_socket_fd, response_content_length, strlen(response_content_length), 0);
				send(client_socket_fd, "\r\nConnection: Closed\r\nServer: zenglServer\r\n\r\n", 45, 0);
				send(client_socket_fd, my_data.response_body.str, my_data.response_body.count, 0);
				// 释放response_body动态字符串
				dynamic_string_free(&my_data.response_body);
				doc_fd = -1; // 将其设置为-1，就可以跳过后面的静态内容输出过程，因为上面已经输出过动态脚本的内容了
			}
			else {
				// 如果不是zengl脚本，则直接打开full_path对应的文件，如果打不开，说明文件不存在，
				// 则打开web根目录中的404.html文件，并设置404状态码
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

		// 如果doc_fd大于0，则直接输出相关的静态文件的内容
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
		// 如果连404.html也不存在的话，则直接反馈404状态信息
		else if(status_code == 404) {
			send(client_socket_fd, "HTTP/1.1 404 Not Found\r\n", 9, 0);
			send(client_socket_fd, "Connection: Closed\r\nServer: zenglServer\r\n\r\n", 43, 0);
		}

end:
		// 释放request_url，request_header以及request_body这些动态字符串资源
		dynamic_string_free(&parser_data.request_url);
		dynamic_string_free(&parser_data.request_header);
		dynamic_string_free(&parser_data.request_body);
		// 关闭客户端套接字
		printf("close client_socket_fd: %d\n===============================\n", client_socket_fd);
		shutdown(client_socket_fd, SHUT_RDWR);
		close(client_socket_fd);
	}
	while(1);
    return NULL;
}
