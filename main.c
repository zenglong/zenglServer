#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#include "main.h"
#include "dynamic_string.h"
#include "client_socket_list.h"
/**
 * zenglServer主要是依靠 http_parser 这个第三方的解析程式来解析http协议的，
 * 该程式的项目地址：https://github.com/nodejs/http-parser
 */
#include "http_parser.h"
#include "module_request.h"
#include "module_builtin.h"
#ifdef USE_MYSQL
#include "module_mysql.h"
#endif
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
#include <sys/epoll.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <semaphore.h>
#include <pthread.h>
#include <stdarg.h>

void fork_child_process(int idx);
void register_signals();
int trap_signals(ZL_EXP_BOOL on);

void * routine_epoll_append_fd(void * arg);
// 每个创建的线程会执行的例程
void *routine(void *arg);
static int routine_process_client_socket(CLIENT_SOCKET_LIST * socket_list, int lst_idx);

// 由于配置文件是使用zengl脚本语法编写的，当在配置文件中使用print指令时，就会调用下面的回调函数，去执行具体的打印操作
ZL_EXP_INT main_config_run_print(ZL_EXP_CHAR * infoStrPtr, ZL_EXP_INT infoStrCount,ZL_EXP_VOID * VM_ARG);

typedef struct _MY_THREAD_LOCK{
	sem_t * accept_sem;    // 进程锁(通过信号量执行加锁操作)
	pthread_mutex_t lock;  // 线程锁
} MY_THREAD_LOCK;

// 写入日志时，会根据format格式，动态的构建需要写入的字符串
// 这里用MY_SERVER_LOG_STR结构体来处理这种情况
typedef struct _MY_SERVER_LOG_STR{
	char * str;  // 字符串的指针
	int size;    // str指针指向的字符串最多可以容纳的字符数，会根据实际情况调整size
} MY_SERVER_LOG_STR;

// 注册信号时，需要使用的结构体
typedef struct _MY_SIG_PAIR{
    int signal;  // 要处理的信号
    struct sigaction action; // 用于设置处理信号时，需要执行的动作(也就是设置相应的C函数)
} MY_SIG_PAIR;

#define PROCESS_NUM 3 // 如果在配置文件中没有设置process_num时，就使用该宏的值作为需要创建的进程数
#define THREAD_NUM_PER_PROCESS 1 // (暂不使用，epoll模式下，实际的工作线程数暂时由程序自己确定!)
#define THREAD_NUM_MAX 3 // (暂不使用，epoll模式下，实际的工作线程数暂时由程序自己确定!)
#define MAX_EPOLL_EVENTS 64 // 每次epoll_wait时，最多可以读取的事件数，如果事件数超过该数量，则剩下的事件将等到下一次epoll_wait时再取出来
#define WEB_ROOT_DEFAULT "webroot" // 如果配置文件中没有设置webroot时，就使用该宏对应的目录名作为web的根目录的目录名
#define DEFAULT_CONFIG_FILE "config.zl" // 当启动zenglServer时，如果没有使用-c命令行参数来指定配置文件名时，就会使用该宏对应的值来作为默认的配置文件名
#define SERVER_LOG_PIPE_STR_SIZE 1024 // 写入日志的动态字符串的初始化及动态扩容的大小
#define WRITE_TO_PIPE 1 // 子进程统一将日志写入管道中，再由主进程从管道中将日志读取出来并写入日志文件
#define WRITE_TO_LOG 0  // 主进程的日志信息，则可以直接写入日志文件

char * current_process_name; // 指向当前进程的名称，通过修改该指针指向的内容，就可以修改当前进程的名称(目前名称的最大长度为255个字符)
int server_log_fd = -1;   // 为守护进程打开的日志文件的文件描述符
int server_log_pipefd[2]; // 该数组用于存储管道的文件描述符，子进程会将日志写入管道的一端，主进程则从另一端将其读取出来
int server_sig_count = 0; // 需要注册的信号数
pid_t server_child_process[0xff]; // 存储子进程的进程ID，目前最多存储255个
MY_SIG_PAIR server_sig_pairs[0xff]; // 该数组，用于注册要处理的信号，以及设置处理信号的C函数
MY_SERVER_LOG_STR server_log_pipe_string = {0}; // 写入日志时，会根据format格式，动态的构建需要写入的字符串
MY_THREAD_LOCK my_thread_lock = {0}; // 全局锁变量，包含了进程锁和线程锁
int server_socket_fd; // zenglServer的服务端套接字对应的文件描述符
int process_epoll_fd; // 每个进程创建的epoll实例对应的文件描述符
int epoll_fd_add_count; // 用于统计添加到epoll实例中的需要监听的文件描述符的数量
int process_max_open_fd_num; // 用于存储进程最多能打开的文件描述符数
struct epoll_event * process_epoll_events; // epoll_wait接收到EPOLLIN之类的事件时，会将这些事件写入到该数组中
long config_debug_mode = 0; // 该全局变量用于存储配置文件中的debug_mode的值，用于判断当前的配置是否处于调试模式
long server_process_num; // 需要创建的子进程数
char config_web_root[150];  // 该全局变量用于存储配置文件中的webroot对应的字符串值，也就是web根目录对应的目录名
char config_zl_debug_log[120]; // 该全局变量用于存储配置文件中的zl_debug_log的值，也就是zengl脚本的调试日志文件，里面存储了脚本对应的虚拟汇编指令，仅用于调试zengl脚本库的BUG时才需要用到
char * webroot; // 该字符串指针指向最终会使用的web根目录名，当配置文件中配置了webroot时，该指针就会指向上面的config_web_root，否则就指向WEB_ROOT_DEFAULT即默认的web根目录名
char * zl_debug_log; // 该字符串指针指向最终会使用的zl_debug_log的值，当配置文件中设置了zl_debug_log时，就指向上面的config_zl_debug_log，否则就设置为NULL(空指针)

char * main_get_webroot()
{
	return webroot;
}

int main_full_path_append(char * full_path, int full_path_length, int full_path_size, char * append_path)
{
	int append_path_length = strlen(append_path);
	int max_length = full_path_size - full_path_length - 1;
	if(append_path_length > max_length)
		append_path_length = max_length;
	if(append_path_length > 0)
		strncpy((full_path + full_path_length), append_path, append_path_length);
	return append_path_length;
}

/**
 * 将logstr写入server_log_fd文件描述符对应的日志文件中
 */
int write_to_server_log(char * logstr)
{
	return write(server_log_fd, logstr, strlen(logstr));
}

/**
 * 子进程会将日志信息写入server_log_pipefd管道的一端
 * 主进程则会循环读取管道的另一端，并将读取到的日志信息，统一写入到日志文件中，
 * 通过这种方式，日志信息就可以交由主进程统一管理，由主进程来决定写入到哪个日志文件中
 * (虽然目前的版本还是写入到一个日志文件里，但是以后可能会根据日期将日志写入不同的日志文件中)
 */
int read_from_server_log_pipe()
{
	while(1)
	{
		char logstr[200];
		int chars_read;
		chars_read = read(server_log_pipefd[0], logstr, 195);
		logstr[chars_read] = STR_NULL;
		write_to_server_log(logstr);
	}
}

/**
 * 主进程和子进程都会通过这个函数来写入日志信息，
 * 当write_to_pipe参数为WRITE_TO_LOG(就是整数0)时，就直接将信息写入日志文件(一般是主进程使用WRITE_TO_LOG方式)
 * 当write_to_pipe参数为WRITE_TO_PIPE(整数1)时，就将日志写入管道(一般是子进程使用WRITE_TO_PIPE方式)
 * 写入日志时，可以提供format格式，下面会通过vsnprintf来根据format和arglist参数列表，来构建需要写入的字符串
 */
int write_to_server_log_pipe(ZL_EXP_BOOL write_to_pipe, const char * format, ...)
{
	if(server_log_pipe_string.str == NULL) {
		server_log_pipe_string.size = SERVER_LOG_PIPE_STR_SIZE;
		server_log_pipe_string.str = (char *)malloc(server_log_pipe_string.size * sizeof(char));
	}
	int retcount = 0;
	va_list arglist;
	va_start(arglist, format);
	while(1) {
		retcount = vsnprintf(server_log_pipe_string.str, server_log_pipe_string.size, format, arglist);
		if(retcount >=0 && retcount < server_log_pipe_string.size) {
			server_log_pipe_string.str[retcount] = STR_NULL;
			if(write_to_pipe) {
				write(server_log_pipefd[1], server_log_pipe_string.str, retcount);
			}
			else {
				write_to_server_log(server_log_pipe_string.str);
			}
			break;
		}
		server_log_pipe_string.size += SERVER_LOG_PIPE_STR_SIZE;
		server_log_pipe_string.str = (char *)realloc(server_log_pipe_string.str, server_log_pipe_string.size * sizeof(char));
	}
	va_end(arglist);
	return retcount;
}

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
			//printf("use config: %s\n", optarg);
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

	// 后面会切换到守护进程，所有信息都会写入到logfile日志文件中
	if ((server_log_fd = open("logfile", O_WRONLY|O_APPEND|O_CREAT, 0644)) < 0) {
		printf("open for server_log_fd failed [%d] %s \n", errno, strerror(errno));
		exit(errno);
	}

	// 将argv[0]赋值给current_process_name，通过current_process_name就可以修改当前进程的名称
	current_process_name = argv[0];
	//通过fork创建master主进程，该进程将在后台以守护进程的形式一直运行，并通过该进程来创建执行具体任务的child子进程
	pid_t master_pid = fork();
	if(master_pid < 0) {
		write_to_server_log_pipe(WRITE_TO_LOG, "failed to create master process [%d] %s \n", errno, strerror(errno));
		// 创建完master进程后，退出当前进程
		exit(-1);
	}
	else if(master_pid > 0) {
		// 记录master主进程的进程ID
		write_to_server_log_pipe(WRITE_TO_LOG, "create master process for daemon [pid:%d] \n", master_pid);
		return 0;
	}

	// 将umask设为0，让子进程给文件设置的读写执行权限不会被屏蔽掉
	umask(0);
	int logStdout;
	if ((logStdout = open("/dev/null", O_WRONLY|O_APPEND|O_CREAT, 0644)) < 0) {
		write_to_server_log_pipe(WRITE_TO_LOG, "open /dev/null failed [%d] %s \n", errno, strerror(errno));
		exit(errno);
	}
	// 将标准输入和输出重定向到/dev/null
	dup2(logStdout, STDIN_FILENO);
	dup2(logStdout, STDOUT_FILENO);
	dup2(logStdout, STDERR_FILENO);
	close(logStdout);

	// 设置新的会话，这样主进程和子进程就不会受到控制台信号的影响了
	if (setsid() < 0) {
		write_to_server_log_pipe(WRITE_TO_LOG, "setsid() failed [%d] %s \n", errno, strerror(errno));
		exit(errno);
	}

	// 创建日志用的管道，子进程中的日志信息会先写入管道，再由主进程统一从管道中读取出来，并写入日志文件中
	if (pipe(server_log_pipefd) == -1) {
		write_to_server_log_pipe(WRITE_TO_LOG, "pipe() failed [%d] %s \n", errno, strerror(errno));
		exit(errno);
	}

	// 当没有使用-c命令行参数指定配置文件名时，就使用默认的配置文件名
	if(config_file == NULL) {
		write_to_server_log_pipe(WRITE_TO_LOG, "use default config: " DEFAULT_CONFIG_FILE "\n");
		config_file = DEFAULT_CONFIG_FILE;
	}
	else {
		write_to_server_log_pipe(WRITE_TO_LOG, "use config: %s\n", config_file);
	}

	long port; // 服务端需要绑定的端口号
	long thread_num_per_process; // 每个进程需要创建的线程数(暂停使用!)
	ZL_EXP_VOID * VM; // 由于配置文件是使用zengl脚本语法编写的，因此，需要使用zengl虚拟机来运行该脚本
	VM = zenglApi_Open(); // 打开一个zengl虚拟机
	zenglApi_SetFlags(VM,(ZENGL_EXPORT_VM_MAIN_ARG_FLAGS)(ZL_EXP_CP_AF_IN_DEBUG_MODE | ZL_EXP_CP_AF_OUTPUT_DEBUG_INFO)); // 设置一些调试标志
	zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_PRINT,main_config_run_print); // 设置zengl脚本中print指令会执行的回调函数
	if(zenglApi_Run(VM, config_file) == -1) //编译执行zengl脚本
	{
		write_to_server_log_pipe(WRITE_TO_LOG, "错误：编译执行<%s>失败：%s\n", config_file, zenglApi_GetErrorString(VM));
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
	if(zenglApi_GetValueAsInt(VM,"process_num", &server_process_num) < 0)
		server_process_num = PROCESS_NUM; // 如果没有设置，则使用PROCESS_NUM宏定义的值

	// 获取配置文件中定义的thread_num_per_process的值，也就是每个进程需要创建的线程数 (该参数暂停使用!)
	if(zenglApi_GetValueAsInt(VM,"thread_num_per_process", &thread_num_per_process) < 0)
		thread_num_per_process = THREAD_NUM_PER_PROCESS; // 如果没有设置，则使用THREAD_NUM_PER_PROCESS宏定义的值
	// 如果thread_num_per_process的值超过THREAD_NUM_MAX允许的最大值，则将其重置为THREAD_NUM_PER_PROCESS对应的值
	else if(thread_num_per_process > THREAD_NUM_MAX || thread_num_per_process <= 0) {
		write_to_server_log_pipe(WRITE_TO_LOG, "warning: thread_num_per_process is not use now \n", config_file);
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
		write_to_server_log_pipe(WRITE_TO_LOG, "warning: webroot in %s too long, use default webroot\n", config_file);
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
	write_to_server_log_pipe(WRITE_TO_LOG, "run %s complete, config: \n", config_file);
	write_to_server_log_pipe(WRITE_TO_LOG, "port: %ld process_num: %ld\n", port, server_process_num);
	write_to_server_log_pipe(WRITE_TO_LOG, "webroot: %s\n", webroot);
	if(zl_debug_log != NULL)
		write_to_server_log_pipe(WRITE_TO_LOG, "zl_debug_log: %s\n", zl_debug_log);
	// 关闭虚拟机，并释放掉虚拟机所分配过的系统资源
	zenglApi_Close(VM);

	// 将主进程的名称设置为zenglServer: master，可以在ps aux命令的输出信息中查看到该名称
	strncpy(current_process_name, "zenglServer: master", 0xff);

	struct sockaddr_in server_addr;
	// 创建服务端套接字
	server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(server_socket_fd == -1)
	{
		write_to_server_log_pipe(WRITE_TO_LOG, "failed to create server socket [%d] %s \n", errno, strerror(errno));
		exit(-1);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY; // 将套接字绑定到任意IP，除了本机可以访问外，外部网络也可以通过IP加端口号来访问到zenglServer
	server_addr.sin_port = htons((uint16_t)port); // 将套接字绑定到指定的端口
	int enable = 1;
	// 开启套接字的REUSEADDR选项，这样，当zenglServer关闭后，可以马上启动并重新绑定到该端口(否则，就需要等待一段时间，可能需要等待好几分钟才能再次绑定到同一个端口)
	if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
		write_to_server_log_pipe(WRITE_TO_LOG, "setsockopt(SO_REUSEADDR) failed [%d] %s \n", errno, strerror(errno));
	    exit(-1);
	}
	// 将服务端套接字绑定到server_addr所指定的IP和端口上
	if(bind(server_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		write_to_server_log_pipe(WRITE_TO_LOG, "failed to bind server socket [%d] %s \n", errno, strerror(errno));
		exit(-1);
	}
	write_to_server_log_pipe(WRITE_TO_LOG, "bind done\n");

	// 当绑定IP和端口成功后，就可以正式开启服务端套接字的监听模式了
	listen(server_socket_fd, 10);

	// 删除掉之前创建过的信号量
	sem_unlink("accept_sem");
	// 创建一个新的信号量，用于实现多个进程间的加锁操作，sem_open的最后一个参数为1，表示只允许一个进程获取信号量并执行相关操作 (信号量暂停使用!)
	my_thread_lock.accept_sem = sem_open("accept_sem", O_CREAT | O_EXCL, 0644, 1);
	if(my_thread_lock.accept_sem <= 0)
	{
		write_to_server_log_pipe(WRITE_TO_LOG, "accept sem init failed : [%d] %s \n", errno, strerror(errno));
		exit(-1);
	}
	write_to_server_log_pipe(WRITE_TO_LOG, "accept sem initialized.\n");

	// 获取当前进程可以打开的文件描述符数量限制，用于控制epoll监听的文件描述符数
	struct rlimit limit;
	if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
		write_to_server_log_pipe(WRITE_TO_LOG, "getrlimit() failed with errno=%d %s\n", errno, strerror(errno));
		exit(1);
	}
	process_max_open_fd_num = limit.rlim_cur;
	write_to_server_log_pipe(WRITE_TO_LOG, "process_max_open_fd_num: %d \n", process_max_open_fd_num);

	// 根据process_num的值，创建多个子进程，如果是调试模式，一般就设置一个子进程，方便gdb调试
	for(int i=0;i < server_process_num;i++)
	{
		fork_child_process(i);
	}

	// 注册信号，主要是进程终止信号，子进程结束信号等
	register_signals();
	// trap_signals会通过sigaction系统调用，将register_signals中注册的信号应用到相关的处理函数上，当进程接收到信号时，就会调用相关的C函数去处理
	if (!trap_signals(ZL_EXP_TRUE)) {
		write_to_server_log_pipe(WRITE_TO_LOG, "trap_signals() failed!\n");
		exit(-1);
	}

	// 主进程循环读取管道，将子进程通过管道发送的日志信息统一写入到日志文件中
	read_from_server_log_pipe();
	return 0;
}

/**
 * 通过fork系统调用创建执行具体工作的子进程
 */
void fork_child_process(int idx)
{
	// 通过fork创建子进程
	pid_t childpid = fork();
	// 如果childpid等于0，说明当前进程是子进程，就创建工作线程
	if(childpid == 0)
	{
		pthread_t tid[THREAD_NUM_MAX];

		// 设置child子进程的进程名
		snprintf(current_process_name, 0xff, "zenglServer: child(%d)", idx);

		// 将子进程从父进程继承过来的信号处理函数取消掉
		if (!trap_signals(ZL_EXP_FALSE)) {
			fprintf(stderr, "Child %d: trap_signals() failed!\n", idx);
			exit(1);
		}

		// 将process_max_open_fd_num的7/8的值，定为max_size，即epoll可以添加的用于监听事件的文件描述符数
		int max_size = (process_max_open_fd_num / 8) * 7;
		if(max_size > 0) { // 从Linux 2.6.8开始, epoll_create的第一个size参数已经被忽略掉, 但是该参数还是必须大于0
			process_epoll_fd = epoll_create(max_size);
		}
		else {
			process_epoll_fd = epoll_create(100);
		}
		// epoll_create返回的是epoll实例对应的文件描述符，后面会通过该文件描述符，对epoll进行操作，例如往epoll中添加需要监听的套接字等
		if(process_epoll_fd == -1)
		{
			write_to_server_log_pipe(WRITE_TO_PIPE, "epoll_create failed : [%d] %s \n", errno, strerror(errno));
			exit(-1);
		}
		// 该全局变量用于统计添加到epoll中的文件描述符的数量
		epoll_fd_add_count = 0;

		// 每次epoll_wait操作时，一次最多可以提取出MAX_EPOLL_EVENTS个事件进行处理，每个事件都对应一个epoll_event结构体
		process_epoll_events = calloc(MAX_EPOLL_EVENTS, sizeof(struct epoll_event));

		// 初始化线程互斥锁
		if(pthread_mutex_init(&(my_thread_lock.lock), NULL) != 0)
		{
			write_to_server_log_pipe(WRITE_TO_PIPE, "thread lock init failed : [%d] %s \n", errno, strerror(errno));
			exit(-1);
		}

		// 依次创建两个线程，第一个线程的处理函数为routine_epoll_append_fd，该处理函数主要用于从服务端套接字中获取客户端套接字的文件描述符，并将其加入到epoll中
		// 第二个线程的处理函数为routine，该处理函数会通过epoll_wait从epoll实例中获取每个客户端套接字文件描述符的相关事件(例如某个客户端连接的可读或可写等事件)，并对这些事件进行处理
		pthread_create(&tid[0], NULL, routine_epoll_append_fd, (void *)&max_size);
		pthread_create(&tid[1], NULL, routine, NULL);

		// 通过join线程，来等待所有的线程结束
		//for (int i = 0; i < thread_num_per_process; i++)
		for (int i = 0; i < 2; i++)
		{
			pthread_join(tid[i], NULL);
		}

		// 如果所有的线程都结束的话，就销毁线程锁，释放相关资源，并退出当前子进程，正常情况下，线程不会退出(因为routine中是一个无限循环)，除非是发生严重的异常
		pthread_mutex_destroy(&(my_thread_lock.lock));
		free(process_epoll_events);
		close(process_epoll_fd);
		exit(0);
	}
	else if(childpid > 0) { // childpid大于0，表示当前是主进程，就向日志中输出创建的子进程的信息
		write_to_server_log_pipe(WRITE_TO_LOG, "Master: Spawning child(%d) [pid %d] \n", idx, childpid);
		server_child_process[idx] = childpid;
	}
}

/**
 * 子进程退出时，主进程会收到SIGCHLD信号，并触发下面这个sig_child_callback函数去处理该信号
 */
void sig_child_callback()
{
    int     i, status[0xff];    /* 数组中存储了每个子进程的退出码，暂时最多只处理255个子进程 */
    pid_t   pid;

    for (i = 0; i < server_process_num; ++i)
    {
        pid = waitpid(server_child_process[i], &status[i], WNOHANG); /* waitpid时采用WNOHANG非阻塞模式 */

        if(pid < 0) {
        	write_to_server_log_pipe(WRITE_TO_LOG, "waitpid error [%d] %s", errno, strerror(errno));
        }
        else if(!pid) {
        	/* waitpid返回0，表示该子进程正在运行中 */
        	continue;
        }
        else {
        	// pid大于0，说明对应的子进程已经退出，则根据status退出码，将子进程退出的原因写入到日志中
			if (WIFEXITED(status[i]))
				write_to_server_log_pipe(WRITE_TO_LOG, "child PID %d exited normally.  Exit number:  %d\n", pid, WEXITSTATUS(status[i]));
			else {
				if (WIFSTOPPED(status[i]))
					write_to_server_log_pipe(WRITE_TO_LOG, "child PID %d was stopped by %d\n", pid, WSTOPSIG(status[i]));
				else {
					if (WIFSIGNALED(status[i]))
						write_to_server_log_pipe(WRITE_TO_LOG, "child PID %d exited due to signal %d\n.", pid, WTERMSIG(status[i]));
					else
						write_to_server_log_pipe(WRITE_TO_LOG, "child PID %d exited, status: %d", pid, status[i]);
				}
			}
			// 通过fork_child_process函数重新创建一个新的子进程，继续工作
			fork_child_process(i);
        }
    }
}

/**
 * 当主进程接收到SIGINT或者SIGTERM终止信号时，会触发的信号处理函数
 */
void sig_terminate_master_callback()
{
    int     i, status;
    pid_t   pid;

    write_to_server_log_pipe(WRITE_TO_LOG, "Termination signal received! Killing children");

    /*
     * 在kill杀死子进程之前，需要先重置所有的信号处理函数，否则，当子进程被kill结束时，会给主进程发送SIGCHLD信号，并自动触发上面的sig_child_callback，
     * sig_child_callback又会通过fork_child_process重启子进程，就没办法结束掉子进程。因此需要先重置信号处理函数，
     * 通过将trap_signals的参数设置为ZL_EXP_FALSE(也就是整数0)，就可以进行重置
     */
    trap_signals(ZL_EXP_FALSE);

    // 循环向子进程发送SIGTERM(终止信号)，从而结束掉子进程
    for (i = 0; i < server_process_num; ++i)
        kill(server_child_process[i], SIGTERM);

    /* 循环等待所有子进程结束 */
    while ((pid = wait(&status)) != -1)
    	write_to_server_log_pipe(WRITE_TO_LOG, ".");

    write_to_server_log_pipe(WRITE_TO_LOG, "\nAll children reaped, shutting down.\n");

    // 如果所有子进程都退出了，就释放相关资源，并退出主进程，子进程和主进程都退出后，整个程序也就退出了
	sem_unlink("accept_sem");
	sem_close(my_thread_lock.accept_sem);
	write_to_server_log_pipe(WRITE_TO_LOG, "closed accept_sem\n");
	shutdown(server_socket_fd, SHUT_RDWR);
	write_to_server_log_pipe(WRITE_TO_LOG, "shutdowned server socket\n");
	close(server_socket_fd);
	write_to_server_log_pipe(WRITE_TO_LOG, "closed server socket\n===================================\n\n");
	free(server_log_pipe_string.str);
    exit(0);
}

/**
 * 注册信号，将要处理的信号和对应的处理函数写入到server_sig_pairs数组中
 * 后面的trap_signals函数，就会根据该数组进行实际的信号处理函数的绑定操作
 */
void register_signals()
{
    int i = 0;

    server_sig_pairs[i].signal            = SIGCHLD;
    server_sig_pairs[i].action.sa_handler = &sig_child_callback;
    /* Don't send SIGCHLD when a process has been frozen (e.g. Ctrl-Z) */
    server_sig_pairs[i].action.sa_flags   = SA_NOCLDSTOP;

    server_sig_pairs[++i].signal          = SIGINT;
    server_sig_pairs[i].action.sa_handler = &sig_terminate_master_callback;

    server_sig_pairs[++i].signal          = SIGTERM;
    server_sig_pairs[i].action.sa_handler = &sig_terminate_master_callback;

    /* setting sigcount now is easier than doing it dynamically */
    server_sig_count = ++i;
}

/**
 * 如果on参数是非0值，就将server_sig_pairs中注册的信号绑定到相应的自定义处理函数上
 * 这样当主进程接收到注册的信号时，就会自动调用自定义的处理函数去处理这些信号
 * 当该函数的on参数是0时，则将server_sig_pairs中注册的信号的处理handler恢复到默认的SIG_DFL
 * 相当于重置所有的信号处理函数
 */
int trap_signals(ZL_EXP_BOOL on)
{
    int i;
    struct sigaction dfl;       /* the handler object */

    dfl.sa_handler = SIG_DFL;   /* for resetting to default behavior */

    /* Loop through all registered signals and either set to the new handler
     * or reset them back to the default */
    for (i = 0; i < server_sig_count; ++i) {
        /* notice that the second parameter takes the address of the handler */
        if (sigaction(server_sig_pairs[i].signal, on ? &server_sig_pairs[i].action : &dfl, NULL) < 0)
            return ZL_EXP_FALSE;
    }

    return ZL_EXP_TRUE;
}

/**
 * 由于配置文件是使用zengl脚本语法编写的，当在配置文件中使用print指令时，就会调用下面的回调函数，去执行具体的打印操作，
 * 该函数将信息直接通过printf显示出来
 */
ZL_EXP_INT main_config_run_print(ZL_EXP_CHAR * infoStrPtr, ZL_EXP_INT infoStrCount,ZL_EXP_VOID * VM_ARG)
{
	write_to_server_log_pipe(WRITE_TO_LOG, "%s\n",infoStrPtr);
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
#ifdef USE_MYSQL
	// 设置mysql模块的初始化函数，和mysql模块相关的C函数代码位于module_mysql.c文件里
	zenglApi_SetModInitHandle(VM_ARG,"mysql", module_mysql_init);
#endif
}

/**
 * 将sfd对应的套接字设置为非阻塞模式，以配合epoll的事件驱动的工作方式
 */
static int make_socket_non_blocking (int sfd)
{
	int flags, s;

	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1)
	{
		write_to_server_log_pipe(WRITE_TO_PIPE, "fcntl failed [%d] %s \n", errno, strerror(errno));
		return -1;
	}

	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
	if (s == -1)
	{
		write_to_server_log_pipe(WRITE_TO_PIPE, "fcntl failed [%d] %s \n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

/**
 * 子进程的第一个工作线程的处理函数为routine_epoll_append_fd
 * 该处理函数会通过accept，从server_socket_fd服务端套接字中获取到client_socket_fd(客户端套接字)
 * 并将client_socket_fd设置为非阻塞模式，并加入到epoll实例中，这样当该套接字对应的客户端连接有输入数据时，就会触发EPOLLIN事件，
 * 另一个工作线程，就会对EPOLLIN事件进行处理，并对客户端连接传递过来的数据进行处理
 */
void * routine_epoll_append_fd(void * arg)
{
	struct sockaddr_in client_addr;
	int c_len = sizeof(client_addr);
	struct epoll_event event;
	int max_count = *((int *)arg);
	write_to_server_log_pipe(WRITE_TO_PIPE, "epoll max fd count : %d \n", max_count);
	do {
		//sem_wait(my_thread_lock.accept_sem);
		int client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&client_addr, (socklen_t *)&c_len);
		if(client_socket_fd < 0) {
			write_to_server_log_pipe(WRITE_TO_PIPE, "accept client_socket_fd less than 0, maybe your linux is too old, and have thundering herd problem \n", max_count);
			continue;
		}
		//sem_post(my_thread_lock.accept_sem);
		if(make_socket_non_blocking(client_socket_fd) == 0) {
			event.data.fd = client_socket_fd;
			event.events = EPOLLIN | EPOLLET | EPOLLERR | EPOLLHUP;
			// 每当向epoll实例中添加客户端套接字时，都将epoll_fd_add_count加一，用于统计添加了多少文件描述符
			// 为了不让添加操作受到另一个工作线程的影响，这里对添加操作进行了线程加锁
			pthread_mutex_lock(&(my_thread_lock.lock));
			epoll_ctl (process_epoll_fd, EPOLL_CTL_ADD, client_socket_fd, &event);
			epoll_fd_add_count++;
			pthread_mutex_unlock(&(my_thread_lock.lock));
			// 当添加到epoll中的文件描述符数超过了max_count时，就循环通过pthread_yield切换到其他工作线程，不再往epoll中添加更多的文件描述符了
			// 除非另一个工作线程消化完了这些客户端连接，并让epoll_fd_add_count小于max_count时，就可以跳出循环，再继续添加文件描述符了
			while(epoll_fd_add_count >= max_count) {
				pthread_yield();
			}
		}
	} while(1);
	return NULL;
}

/**
 * 获取当前的线程ID
 */
pid_t routine_get_tid()
{
	// 通过gettid系统调用来获取到当前的线程ID
	#ifdef SYS_gettid
		pid_t tid = syscall(SYS_gettid);
	#else
		#error "SYS_gettid unavailable on this system"
	#endif
	return tid;
}

/**
 * 关闭客户端套接字，并将套接字从socket_list列表中移除，同时将epoll_fd_add_count统计数减一
 */
void routine_close_client_socket(CLIENT_SOCKET_LIST * socket_list, int lst_idx)
{
	if(lst_idx >= 0 && lst_idx < socket_list->size) {
		pthread_mutex_lock(&(my_thread_lock.lock));
		client_socket_list_free_by_idx(socket_list, lst_idx);
		epoll_fd_add_count--;
		write_to_server_log_pipe(WRITE_TO_PIPE, "free socket_list[%d]/list_cnt:%d epoll_fd_add_count:%d pid:%d tid:%d\n", lst_idx,
				 socket_list->count, epoll_fd_add_count, getpid(), routine_get_tid());
		pthread_mutex_unlock(&(my_thread_lock.lock));
	}
}

/**
 * 对于未添加到socket_list列表中的套接字，当发生错误时，就直接close关闭掉它
 */
void routine_close_single_socket(int client_socket_fd)
{
	if(client_socket_fd > 0) {
		pthread_mutex_lock(&(my_thread_lock.lock));
		close(client_socket_fd);
		epoll_fd_add_count--;
		write_to_server_log_pipe(WRITE_TO_PIPE, "close single socket:%d pid:%d tid:%d\n", client_socket_fd, getpid(), routine_get_tid());
		pthread_mutex_unlock(&(my_thread_lock.lock));
	}
}

/**
 * 子进程的第二个工作线程的处理函数，该处理函数会循环通过epoll_wait来获取各个套接字的读写事件，
 * 当某个客户端连接有可读的数据时，就会触发EPOLLIN事件，线程收到该事件时，就会将客户端连接中
 * 可读的数据读取到该连接对应的缓存中，如果需要读取的数据比较多时，可能会触发多次EPOLLIN，线程就需要
 * 读取多次，并将数据写入到客户端连接对应的缓存中，这里建立了一个socket_list的套接字列表，每个列表
 * 成员中，包含了每个客户端连接对应的fd套接字文件描述符，以及相应的缓存等。这里还会处理EPOLLOUT事件，
 * 需要输出的数据也会先缓存起来，如果一次没传完的话，下次接收到EPOLLOUT时，再继续传数据，直到把所有需要
 * 输出的数据都传递给客户端为止。
 */
void * routine(void *arg)
{
	int n, i;
	int client_socket_fd;
	struct epoll_event event;
	CLIENT_SOCKET_LIST socket_list = {0};
	int lst_idx, epollout_ret;
	// 整个线程使用无限循环来循环处理客户端请求，除非发生异常，或者主体程序退出
	do
	{
		n = epoll_wait (process_epoll_fd, process_epoll_events, MAX_EPOLL_EVENTS, -1);
		for (i = 0; i < n; i++) {
			if ((process_epoll_events[i].events & EPOLLERR) ||
				  (process_epoll_events[i].events & EPOLLHUP) ||
				  (!(process_epoll_events[i].events & EPOLLIN) && !(process_epoll_events[i].events & EPOLLOUT)))
			{
				/* An error has occured on this fd, or the socket is not
				 ready for reading (why were we notified then?) */
				write_to_server_log_pipe(WRITE_TO_PIPE, "epoll error: 0x%x\n", process_epoll_events[i].events);
				client_socket_fd = process_epoll_events[i].data.fd;
				lst_idx = client_socket_list_find(&socket_list, client_socket_fd);
				if(lst_idx < 0)
					routine_close_single_socket(client_socket_fd);
				else
					routine_close_client_socket(&socket_list, lst_idx);
				continue;
			}
			else
			{
				if((process_epoll_events[i].events & EPOLLIN))
				{
					client_socket_fd = process_epoll_events[i].data.fd;
					lst_idx = client_socket_list_process_epollin(&socket_list, client_socket_fd);
					if(lst_idx < 0) {
						continue;
					}
					lst_idx = routine_process_client_socket(&socket_list, lst_idx);
					if(lst_idx < 0) {
						continue;
					}
					event.data.fd = client_socket_fd;
					event.events = EPOLLOUT | EPOLLET | EPOLLERR | EPOLLHUP;
					epoll_ctl (process_epoll_fd, EPOLL_CTL_MOD, client_socket_fd, &event);
					client_socket_list_process_epollout(&socket_list, lst_idx);
				}
				else if(process_epoll_events[i].events & EPOLLOUT) {
					client_socket_fd = process_epoll_events[i].data.fd;
					lst_idx = client_socket_list_find(&socket_list, client_socket_fd);
					if(lst_idx < 0) {
						write_to_server_log_pipe(WRITE_TO_PIPE, "client_socket_list_find return less than 0: %d\n", lst_idx);
						routine_close_single_socket(client_socket_fd);
						continue;
					}
					client_socket_list_process_epollout(&socket_list, lst_idx);
				}
			}
		}
	} while(1);
	return NULL;
}

/**
 * 当线程读取到客户端的完整的请求数据后，就会执行下面这个函数，去处理该请求，
 * 并将处理的结果写入到输出缓存，函数返回后，线程会将输出缓存里的数据传递给客户端，
 * 当输出缓存中的数据比较多时，线程就需要分多次进行传输(通过检测EPOLLOUT事件来实现多次传输，
 * 当收到EPOLLOUT事件时，就说明该事件对应的客户端连接可以继续发送数据了)
 */
static int routine_process_client_socket(CLIENT_SOCKET_LIST * socket_list, int lst_idx)
{
	time_t rawtime;
	struct tm * timeinfo;
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	char * current_time = asctime (timeinfo);
	// 将当前时间和客户端套接字对应的描述符给打印出来
	write_to_server_log_pipe(WRITE_TO_PIPE, "-----------------------------------\n%srecv [client_socket_fd:%d] [lst_idx:%d] [pid:%d] [tid:%d]:",
					current_time, socket_list->member[lst_idx].client_socket_fd, lst_idx, getpid(), routine_get_tid());
	write_to_server_log_pipe(WRITE_TO_PIPE, "\n\n");
	MY_PARSER_DATA * parser_data = &(socket_list->member[lst_idx].parser_data);
	write_to_server_log_pipe(WRITE_TO_PIPE, "request header: ");
	{
		char * tmp = parser_data->request_header.str;
		char * end = parser_data->request_header.str + parser_data->request_header.count;
		do{
			ZL_EXP_CHAR * field = tmp;
			ZL_EXP_CHAR * value = field + strlen(field) + 1;
			if(field >= end || value >= end) {
				break;
			}
			write_to_server_log_pipe(WRITE_TO_PIPE, "%s: %s | ", field, value);
			tmp = value + strlen(value) + 1;
		}while(1);
	}
	write_to_server_log_pipe(WRITE_TO_PIPE, "\n\n");
	write_to_server_log_pipe(WRITE_TO_PIPE, "url: %s\n", parser_data->request_url.str);
	// 通过http_parser_parse_url来解析url资源路径(包含查询字符串)，该函数会将路径信息和查询字符串信息给解析出来，并将解析结果存储到url_parser中
	if(http_parser_parse_url(parser_data->request_url.str,
			strlen(parser_data->request_url.str), 0,
			&(parser_data->url_parser))) {
		write_to_server_log_pipe(WRITE_TO_PIPE, "**** failed to parse URL %s ****\n",
				socket_list->member[lst_idx].parser_data.request_url.str);
		routine_close_client_socket(socket_list, lst_idx);
		return -1;
	}
	char url_path[URL_PATH_SIZE];
	int tmp_len;
	// 将解析出来的url路径存储到url_path中
	if((parser_data->url_parser.field_set & (1 << UF_PATH)) && (parser_data->url_parser.field_data[UF_PATH].len > 0)) {
		if(parser_data->url_parser.field_data[UF_PATH].len >= URL_PATH_SIZE)
			tmp_len = URL_PATH_SIZE - 1;
		else
			tmp_len = parser_data->url_parser.field_data[UF_PATH].len;
		strncpy(url_path, parser_data->request_url.str + parser_data->url_parser.field_data[UF_PATH].off, tmp_len);
		url_path[tmp_len] = STR_NULL;
	}
	else {
		url_path[0] = '/';
		url_path[1] = STR_NULL;
	}
	write_to_server_log_pipe(WRITE_TO_PIPE, "url_path: %s\n", url_path);
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
			my_data.full_path = full_path;
			my_data.client_socket_fd = socket_list->member[lst_idx].client_socket_fd;
			my_data.zl_debug_log = NULL;
			my_data.headers_memblock.ptr = ZL_EXP_NULL;
			my_data.headers_memblock.index = 0;
			my_data.query_memblock.ptr = ZL_EXP_NULL;
			my_data.query_memblock.index = 0;
			my_data.body_memblock.ptr = ZL_EXP_NULL;
			my_data.body_memblock.index = 0;
			my_data.my_parser_data = parser_data;
			my_data.response_body.str = PTR_NULL;
			my_data.response_body.count = my_data.response_body.size = 0;
			my_data.resource_list.list = PTR_NULL;
			my_data.resource_list.count = my_data.resource_list.size = 0;
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
			pthread_mutex_lock(&(my_thread_lock.lock));
			if(zenglApi_Run(VM, full_path) == -1) //编译执行zengl脚本
			{
				// 如果执行失败，则显示错误信息，并抛出500内部错误给客户端
				write_to_server_log_pipe(WRITE_TO_PIPE, "zengl run <%s> failed: %s\n",full_path, zenglApi_GetErrorString(VM));
				client_socket_list_append_send_data(socket_list, lst_idx, "HTTP/1.1 500 Internal Server Error\r\n", 36);
				dynamic_string_append(&my_data.response_body, "500 Internal Server Error", 25, 200);
			}
			else {
				client_socket_list_append_send_data(socket_list, lst_idx, "HTTP/1.1 200 OK\r\n", 17);
			}
			pthread_mutex_unlock(&(my_thread_lock.lock));
			resource_list_remove_all_resources(VM, &(my_data.resource_list));
			// 关闭zengl虚拟机及zl_debug_log日志文件
			zenglApi_Close(VM);
			if(my_data.zl_debug_log != NULL) {
				fclose(my_data.zl_debug_log);
			}
			// zengl脚本中的输出数据会写入到my_data里的response_body动态字符串中，
			// 因此，将response_body动态字符串的长度作为Content-Length，并将其作为响应内容，反馈给客户端
			char response_content_length[20];
			sprintf(response_content_length, "%d", my_data.response_body.count);
			client_socket_list_append_send_data(socket_list, lst_idx, "Content-Length: ", 16);
			client_socket_list_append_send_data(socket_list, lst_idx, response_content_length, strlen(response_content_length));
			client_socket_list_append_send_data(socket_list, lst_idx, "\r\nConnection: Closed\r\nServer: zenglServer\r\n\r\n", 45);
			client_socket_list_append_send_data(socket_list, lst_idx, my_data.response_body.str, my_data.response_body.count);
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
		client_socket_list_append_send_data(socket_list, lst_idx, "HTTP/1.1 ", 9);
		switch(status_code){
		case 404:
			client_socket_list_append_send_data(socket_list, lst_idx, "404 Not Found\r\n", 15);
			break;
		case 200:
			client_socket_list_append_send_data(socket_list, lst_idx, "200 OK\r\n", 8);
			client_socket_list_append_send_data(socket_list, lst_idx, "Cache-Control: max-age=120\r\n", 28);
			break;
		}
		char doc_fd_content_length[20];
		sprintf(doc_fd_content_length, "%d", (int)lseek(doc_fd, 0, SEEK_END));
		lseek(doc_fd, 0, SEEK_SET);
		client_socket_list_append_send_data(socket_list, lst_idx, "Content-Length: ", 16);
		client_socket_list_append_send_data(socket_list, lst_idx, doc_fd_content_length, strlen(doc_fd_content_length));
		client_socket_list_append_send_data(socket_list, lst_idx, "\r\nConnection: Closed\r\nServer: zenglServer\r\n\r\n", 45);
		char buffer[1025];
		int data_length;
		while((data_length = read(doc_fd, buffer, sizeof(buffer))) > 0){
			client_socket_list_append_send_data(socket_list, lst_idx, buffer, data_length);
		}
		close(doc_fd);
	}
	// 如果连404.html也不存在的话，则直接反馈404状态信息
	else if(status_code == 404) {
		client_socket_list_append_send_data(socket_list, lst_idx, "HTTP/1.1 404 Not Found\r\n", 9);
		client_socket_list_append_send_data(socket_list, lst_idx, "Connection: Closed\r\nServer: zenglServer\r\n\r\n", 43);
	}
	return lst_idx;
}
