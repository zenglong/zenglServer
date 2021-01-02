#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif
#ifndef _XOPEN_SOURCE
	#define _XOPEN_SOURCE
#endif

#include "main.h"
#include "dynamic_string.h"
#include "client_socket_list.h"
#include "zlsrv_setproctitle.h"
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
#include "module_session.h"
#ifdef USE_MAGICK
#include "module_magick.h"
#endif
#ifdef USE_PCRE
#include "module_pcre.h"
#endif
#ifdef USE_CURL
#include "module_curl.h"
#endif
#ifdef USE_REDIS
#include "module_redis.h"
#endif
#ifdef USE_OPENSSL
#include "module_openssl.h"
#endif
#include "debug.h" // debug.h头文件中包含远程调试相关的结构体和函数的定义
#include "md5.h"
#include "fatal_error_callback.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <semaphore.h>
#include <pthread.h>
#include <stdarg.h>
#include <dirent.h>
#include <execinfo.h>

// 当web根目录中没有定义404.html时，就会将下面这个宏定义的字符串，作为404错误的默认输出内容返回给客户端
#define DEFAULT_OUTPUT_HTML_404 "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center></body></html>"
// 当发生403错误时，会将下面这个宏定义的字符串作为结果返回给客户端
#define DEFAULT_OUTPUT_HTML_403 "<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center></body></html>"

void fork_child_process(int idx);
void fork_cleaner_process();
void register_signals();
int trap_signals(ZL_EXP_BOOL on);

void * routine_epoll_append_fd(void * arg);
// 每个创建的线程会执行的例程
void *routine(void *arg);
static int routine_process_client_socket(CLIENT_SOCKET_LIST * socket_list, int lst_idx);

// 以命令行的方式执行脚本
static int main_run_cmd(char * run_cmd);

/**
 * 当zenglServer的命令行模式下的主进程或web模式下的工作子进程因为严重的段错误导致进程挂掉时，
 * 会通过下面这个C函数将段错误相关的函数栈追踪信息记录到日志中，从而可以分析出段错误发生的原因
 */
static void dump_process_segv_fault();

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

/**
 * 根据文件名后缀检测内容类型的结构体
 */
typedef struct _SERVER_CONTENT_TYPE{
	const char * suffix; // 文件名后缀
	int suffix_length;   // 后缀长度
	const char * content_type; // 内容类型
} SERVER_CONTENT_TYPE;

#define PROCESS_NUM 3 // 如果在配置文件中没有设置process_num时，就使用该宏的值作为需要创建的进程数
#define THREAD_NUM_PER_PROCESS 1 // (暂不使用，epoll模式下，实际的工作线程数暂时由程序自己确定!)
#define THREAD_NUM_MAX 3 // (暂不使用，epoll模式下，实际的工作线程数暂时由程序自己确定!)
#define MAX_EPOLL_EVENTS 64 // 每次epoll_wait时，最多可以读取的事件数，如果事件数超过该数量，则剩下的事件将等到下一次epoll_wait时再取出来
#define WEB_ROOT_DEFAULT "webroot" // 如果配置文件中没有设置webroot时，就使用该宏对应的目录名作为web的根目录的目录名
#define SESSION_DIR_DEFAULT "sessions" // 如果配置文件中没有设置session_dir时，就使用该宏对应的目录名作为会话文件的存储目录
#define SESSION_EXPIRE 1440 // 如果配置文件中没有设置session_expire时，就使用该宏的值作为session会话的超时时间(以秒为单位)
#define SESSION_CLEANER_INTERVAL 3600 // 如果配置文件中没有设置session_cleaner_interval时，就使用该宏的值作为会话文件清理进程的清理时间间隔(以秒为单位)
#define REMOTE_DEBUGGER_IP_DEFAULT "127.0.0.1" // 远程调试器默认的IP地址
#define REMOTE_DEBUGGER_PORT 9999 // 远程调试器默认的端口号
#define DEFAULT_CONFIG_FILE "config.zl" // 当启动zenglServer时，如果没有使用-c命令行参数来指定配置文件名时，就会使用该宏对应的值来作为默认的配置文件名
#define SERVER_LOG_PIPE_STR_SIZE 1024 // 写入日志的动态字符串的初始化及动态扩容的大小
#define SHM_MIN_SIZE (300 * 1024) // 如果配置文件中没有设置shm_min_size时，就使用该宏的值作为需要放进共享内存的缓存的最小大小(以字节为单位)

// 启动过程中，在没有重定向输出之前，如果发生错误或警告，除了写入日志，还会显示在命令行终端，方便启动时不用通过查看日志就可以发现错误等
#define WRITE_LOG_WITH_PRINTF(format, ...) write_to_server_log_pipe(WRITE_TO_LOG, format, __VA_ARGS__); \
	printf(format, __VA_ARGS__);
#define WRITE_LOG_WITH_PRINTF_NOARG(format) write_to_server_log_pipe(WRITE_TO_LOG, format); \
	printf(format);

int server_log_fd = -1;   // 为守护进程打开的日志文件的文件描述符
int server_log_pipefd[2]; // 该数组用于存储管道的文件描述符，子进程会将日志写入管道的一端，主进程则从另一端将其读取出来
int server_sig_count = 0; // 需要注册的信号数
pid_t server_child_process[0xff]; // 存储子进程的进程ID，目前最多存储255个
pid_t server_cleaner_process; // 存储cleaner进程的进程ID
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
char config_web_root[FULL_PATH_SIZE];  // 该全局变量用于存储配置文件中的webroot对应的字符串值，也就是web根目录对应的目录名
char config_zl_debug_log[FULL_PATH_SIZE]; // 该全局变量用于存储配置文件中的zl_debug_log的值，也就是zengl脚本的调试日志文件，里面存储了脚本对应的虚拟汇编指令，仅用于调试zengl脚本库的BUG时才需要用到
char * webroot; // 该字符串指针指向最终会使用的web根目录名，当配置文件中配置了webroot时，该指针就会指向上面的config_web_root，否则就指向WEB_ROOT_DEFAULT即默认的web根目录名
char * zl_debug_log; // 该字符串指针指向最终会使用的zl_debug_log的值，当配置文件中设置了zl_debug_log时，就指向上面的config_zl_debug_log，否则就设置为NULL(空指针)

char ** zlsrv_main_argv = NULL; // 将main函数的argv参数指针保存为全局变量，以供zlsrv_setproctitle.c文件使用

static char * server_logfile = NULL; // 将日志文件名保存到server_logfile，方便在SIGUSR1信号处理中，通过文件名重新打开日志文件

static ZL_EXP_BOOL is_run_in_cmd = ZL_EXP_FALSE; // 通过该变量来判断，当前是否是以命令行的方式在运行脚本
static ZL_EXP_BOOL is_immediate_print = ZL_EXP_FALSE; // 是否使用立即打印模式，当使用立即打印模式时，脚本在命令行下运行，使用print指令输出信息时，会立刻显示到终端上

static char config_session_dir[FULL_PATH_SIZE]; // session会话目录
static long config_session_expire; // session会话默认超时时间(以秒为单位)
static long config_session_cleaner_interval; // session会话文件清理进程的清理时间间隔(以秒为单位)

static long config_remote_debug_enable; // 是否开启远程调试
static char config_remote_debugger_ip[30]; // 远程调试器的ip地址
static long config_remote_debugger_port; //远程调试器的端口号

static long config_zengl_cache_enable; // 是否开启zengl脚本的编译缓存

static long config_shm_enable; // 是否将zengl脚本的编译缓存放入共享内存
static long config_shm_min_size; // 需要放进共享内存的缓存的最小大小，只有超过这个大小的缓存才放入共享内存中，以字节为单位

// 是否使用详细的日志记录模式，在详细模式下，会将每个请求的请求头和响应头等都记录到日志中，默认就是详细模式
// 如果将配置文件中的verbose设置为FALSE，就是精简模式，该模式下，只会记录请求的路径信息，而不会记录具体的请求头和响应头等
static long config_verbose = ZL_EXP_TRUE;

// 存储配置文件中的request_body_max_size的配置值，该配置用于设置每个请求的主体数据所允许的最大字节值
// 当需要上传较大的文件时，就需要调整该配置值，例如，假设配置值是200K，但是上传文件的大小是300K，那么上传就会失败，
// 因为上传文件的请求对应的主体数据的字节大小大于设置的200K，此时，就需要将此配置根据情况调大，例如调到400K等，这样就可以上传较大的文件了
long config_request_body_max_size;
// 存储配置文件中的request_header_max_size的配置值，该配置用于设置请求头所允许的最大字节值，当请求中可能包含较大的请求头时，
// 就需要调整该配置的值，例如，当请求头中包含很多Cookie信息时，就会导致请求头比较大，此时就可以适当的调大该配置的值，
// 这样，服务端就能记录到完整的请求头信息了
long config_request_header_max_size;
// 存储配置文件中的request_url_max_size的配置值，该配置用于设置url资源路径(包括请求参数在内)所允许的最大字符数
long config_request_url_max_size;

// 存储配置文件中的pidfile的配置值，该配置用于设置记录主进程的进程ID的文件名(该文件名可以是相对于当前工作目录的路径)
static char config_pidfile[FULL_PATH_SIZE];

// server_content_types数组中存储了文件名后缀与内容类型之间的对应关系
static SERVER_CONTENT_TYPE server_content_types[] = {
	{".html", 5, "text/html"},
	{".css", 4, "text/css"},
	{".js", 3, "application/javascript"},
	{".png", 4, "image/png"},
	{".jpg", 4, "image/jpeg"},
	{".jpeg", 5, "image/jpeg"},
	{".gif", 4, "image/gif"},
	{".ico", 4, "image/x-icon"}
};

// server_content_types数组的成员个数
static int server_content_types_number = 8;

/**
 * 通过检测文件名后缀，在响应头中输出相应的Content-Type内容类型(IE高版本浏览器，css样式文件如果没有Content-Type，会报Mime类型不匹配而被忽略的警告信息，从而导致样式不生效)
 */
static int main_output_content_type(char * full_path, CLIENT_SOCKET_LIST * socket_list, int lst_idx)
{
	int full_length = strlen(full_path);
	for(int i=0; i < server_content_types_number; i++) {
		SERVER_CONTENT_TYPE * sct = &server_content_types[i];
		if(full_length > sct->suffix_length &&
			(full_path[full_length -1] == sct->suffix[sct->suffix_length - 1])) {
			if(strncmp(full_path + (full_length - sct->suffix_length), sct->suffix, sct->suffix_length) == 0) {
				client_socket_list_append_send_data(socket_list, lst_idx, "Content-Type: ", 14);
				client_socket_list_append_send_data(socket_list, lst_idx, (char *)sct->content_type, strlen(sct->content_type));
				client_socket_list_append_send_data(socket_list, lst_idx, "\r\n", 2);
				return 1;
			}
		}
	}
	return 0;
}

/**
 * 将buffer字符串解析成相应的时间结构
 */
static void main_parse_date(const char *buffer, struct tm *date) {
	int len;
	char firstElement[20];
	sscanf(buffer, "%s", firstElement);
	len = strlen(firstElement);

	switch (len) {
	/* RFC 822, updated by RFC 1123; firstElement "[wkday]," */
	case 4:
		strptime(buffer, "%a, %d %b %Y %T GMT", date);
		break;
		/*  ANSI C's asctime() format; firstElement "[wkday]" */
	case 3:
		strptime(buffer, "%a %b %d %T %Y", date);
		break;
		/* RFC 850, obsoleted by RFC 1036; firstElement "[weekdey],
		 * " */
	default:
		strptime(buffer, "%A, %d-%b-%y %T GMT", date);
	}
}

/**
 * 比较两个时间结构，判断他们是否相等
 */
static int main_compare_dates(const struct tm *date1, const struct tm *date2) {
	time_t sec1;
	time_t sec2;

	sec1 = mktime((struct tm*) date1);
	sec2 = mktime((struct tm*) date2);

	return (sec2 - sec1);
}

/**
 * 根据静态文件的修改时间，生成Last-Modified响应头
 */
static void main_output_last_modified(struct stat * filestatus, CLIENT_SOCKET_LIST * socket_list, int lst_idx)
{
	char dateLine[60];
	struct tm * tempDate;
	tempDate = gmtime(&filestatus->st_mtim.tv_sec);
	strftime(dateLine, 60, "Last-Modified: %a, %d %b %Y %T GMT\r\n", tempDate);
	client_socket_list_append_send_data(socket_list, lst_idx, dateLine, strlen(dateLine));
}

/**
 * 如果客户的的请求头中包含了If-Modified-Since字段的话，就将该字段的时间值，与所访问的静态文件的修改时间进行比较
 * 如果两个时间相同，则返回304状态码
 */
static void main_process_if_modified_since(char * request_header, int request_header_count,
		struct stat * filestatus, CLIENT_SOCKET_LIST * socket_list, int lst_idx, int * status_code)
{
	const char * if_modified_since = "If-Modified-Since";
	int if_modified_since_length = strlen(if_modified_since);
	char * tmp = request_header;
	char * end = request_header + request_header_count;
	do{
		ZL_EXP_CHAR * field = tmp;
		ZL_EXP_CHAR * value = field + strlen(field) + 1;
		if(field >= end || value >= end) {
			break;
		}
		int field_len = strlen(field);
		if(field_len == if_modified_since_length) {
			if(!strcasecmp(field, if_modified_since)) {
				struct tm reqestedDate;
				main_parse_date(value, &reqestedDate);
				struct tm * fileModDate = gmtime(&(filestatus->st_mtime));
				if(!main_compare_dates(&reqestedDate, fileModDate)) {
					if((*status_code) == 200) {
						(*status_code) = 304;
					}
					return;
				}
			}
		}
		tmp = value + strlen(value) + 1;
	} while(1);
}

/**
 * 计算str字符串的md5值，并将md5值写入到buf缓存，isLowerCase参数表示是否生成小写，is32表示是否生成32位的md5
 */
static void main_compute_md5(char * buf, char * str, ZL_EXP_BOOL isLowerCase, ZL_EXP_BOOL is32)
{
	MD5_CTX md5;
	MD5Init(&md5);
	unsigned char * encrypt = (unsigned char *)str;
	unsigned char decrypt[16];
	MD5Update(&md5,encrypt,strlen((char *)encrypt));
	MD5Final(&md5,decrypt);
	char * p = buf;
	int start_idx = is32 ? 0 : 4;
	int end_idx = is32 ? 16 : 12;
	const char * format = isLowerCase ? "%02x" : "%02X";
	for(int i = start_idx; i < end_idx; i++) {
		sprintf(p, format, decrypt[i]);
		p += 2;
	}
	(*p) = '\0';
}

/**
 * 根据full_path脚本路径，得到最终要生成的缓存文件的路径信息
 */
static void main_get_zengl_cache_path(char * cache_path, int cache_path_size, char * full_path)
{
	char fullpath_md5[33];
	char cache_prefix[20] = {0};
	const char * cache_path_prefix = "zengl/caches/"; // 缓存文件都放在zengl/caches目录中
	int append_length;
	main_compute_md5(fullpath_md5, full_path, ZL_EXP_TRUE, ZL_EXP_TRUE); // 将full_path进行md5编码
	// 在缓存路径前面加上zengl版本号和指针长度，不同的zengl版本生成的缓存有可能会不一样，另外，32位和64位环境下生成的内存缓存数据也是不一样的
	// 32位系统中生成的缓存数据放到64位中运行，或者反过来，都会报内存相关的错误
	sprintf(cache_prefix, "%d_%d_%d_%ld_", ZL_EXP_MAJOR_VERSION, ZL_EXP_MINOR_VERSION, ZL_EXP_REVISION, sizeof(char *));
	append_length = main_full_path_append(cache_path, 0, cache_path_size, (char *)cache_path_prefix);
	append_length += main_full_path_append(cache_path, append_length, cache_path_size, cache_prefix);
	append_length += main_full_path_append(cache_path, append_length, cache_path_size, fullpath_md5);
	cache_path[append_length] = '\0';
}

/**
 * 尝试重利用full_path脚本文件对应的缓存数据，cache_path表示缓存数据所在的文件路径
 * 如果缓存文件不存在，则会重新生成缓存文件，如果full_path脚本文件内容发生了改变或者其加载的脚本文件内容发生了改变，也会重新生成缓存
 * 外部调用者通过is_reuse_cache变量的值来判断是否需要生成缓存文件，如果is_reuse_cache为ZL_EXP_FALSE，就表示没有重利用缓存，则需要生成缓存文件
 * 如果is_reuse_cache为ZL_EXP_TRUE，则说明重利用了缓存，不需要再生成缓存文件了
 */
static void main_try_to_reuse_zengl_cache(ZL_EXP_VOID * VM, char * cache_path, char * full_path, ZL_EXP_BOOL * is_reuse_cache)
{
	FILE * ptr_fp;
	ZL_EXP_VOID * cachePoint = NULL;
	ZENGL_EXPORT_API_CACHE_TYPE * api_cache;
	ZL_EXP_LONG offset, cache_mtime, file_mtime;
	ZL_EXP_BYTE * mempoolPtr;
	ZL_EXP_CHAR ** filenames, * filename;
	ZL_EXP_INT cacheSize, i;
	struct stat stat_result;
	(* is_reuse_cache) = ZL_EXP_FALSE;
	if(stat(cache_path, &stat_result)==0) { // 获取缓存文件的修改时间
		cache_mtime = (ZL_EXP_LONG)stat_result.st_mtime;
	}
	else { // 获取文件的状态信息失败，可能缓存文件不存在，需要重新编译生成缓存，直接返回
		write_to_server_log_pipe(WRITE_TO_PIPE, "can not stat cache file: \"%s\", maybe no such cache file [recompile]\n", cache_path);
		return ;
	}
	if(stat(full_path, &stat_result)==0) { // 获取主执行脚本的修改时间
		file_mtime = (ZL_EXP_LONG)stat_result.st_mtime;
		if(file_mtime >= cache_mtime) { // 如果主执行脚本的修改时间大于等于缓存数据的修改时间，则说明主执行脚本的内容发生了改变，需要重新编译生成新的缓存
			write_to_server_log_pipe(WRITE_TO_PIPE, "\"%s\" mtime:%ld [changed] [recompile]\n", full_path, file_mtime);
			return;
		}
	}
	else { // 主执行脚本不存在，直接返回
		write_to_server_log_pipe(WRITE_TO_PIPE, "warning stat script file: \"%s\" failed, maybe no such file! [recompile]\n", full_path);
		return ;
	}
	// 打开缓存文件
	if((ptr_fp = fopen(cache_path, "rb")) == NULL) {
		write_to_server_log_pipe(WRITE_TO_PIPE, "no cache file: \"%s\" [recompile]\n", cache_path);
		return ;
	}
	flock(ptr_fp->_fileno, LOCK_SH); // 加文件共享锁，如果有进程在修改缓存内容的话，所有读缓存的进程都会等待写入完成，再执行读操作
	fstat(ptr_fp->_fileno, &stat_result);
	cacheSize = stat_result.st_size;
	ZL_EXP_BYTE is_create = ZL_EXP_FALSE; // 判断是否是新创建的共享内存，如果是新建的，则需要将缓存数据读取到共享内存中，如果共享内存已经存在，则无需再读取
	// is_use_shm用于判断是否使用共享内存，如果配置中启用了共享内存，同时编译缓存的大小超过了配置文件中shm_min_size的值，则表示当前编译缓存需要放到共享内存中
	ZL_EXP_BYTE is_use_shm = config_shm_enable ? ((cacheSize > config_shm_min_size) ? ZL_EXP_TRUE : ZL_EXP_FALSE) : ZL_EXP_FALSE;
	int shm_id = -1;
	key_t share_mem_key;
	if(is_use_shm) { // 如果使用共享内存，则先将缓存路径转为共享内存key，再通过该key来获取已存在的共享内存，如果共享内存不存在时，则新建一个共享内存
		share_mem_key = ftok(cache_path, 1);
		shm_id = shmget(share_mem_key, cacheSize, 0666);
		if(shm_id == -1) {
			if(errno == ENOENT) { // 不存在，则新建一个共享内存
				shm_id = shmget(share_mem_key, cacheSize, IPC_CREAT | 0666);
				is_create = ZL_EXP_TRUE;
			}
			else { // 获取共享内存失败，则将is_use_shm设为FALSE，表示使用普通的文件缓存方式
				write_to_server_log_pipe(WRITE_TO_PIPE, "shmget <key: 0x%x size: %d cache_path: %s> failed [%d] %s [read from cache file]\n",
						share_mem_key, cacheSize, cache_path, errno, strerror(errno));
				is_use_shm = ZL_EXP_FALSE;
			}
		}
	}
	if(is_use_shm) { // 如果使用共享内存，则通过shmat库函数，将共享内存映射到当前进程的线性地址空间，从而得到当前进程可以访问的内存地址
		cachePoint = shmat(shm_id, NULL, 0);
		if(cachePoint == ((ZL_EXP_VOID *)-1)) { // 映射失败，记录错误，并使用原始的文件缓存方式
			write_to_server_log_pipe(WRITE_TO_PIPE, "shmat <id: %d cache_path: %s> failed [%d] %s [read from cache file]\n",
						shm_id, cache_path, errno, strerror(errno));
			is_use_shm = ZL_EXP_FALSE;
		}
	}
	if(!is_use_shm || is_create) {
		if(!is_use_shm) { // 如果不使用共享内存，则在根据缓存大小，新建一个堆内存空间，编译缓存会读取到该堆内存中
			cachePoint = malloc(cacheSize);
		}
		if(fread(cachePoint, cacheSize, 1, ptr_fp) != 1) { // 读取编译缓存数据到堆内存(普通文件缓存方式)，或者读取到新创建的共享内存中
			write_to_server_log_pipe(WRITE_TO_PIPE, "read cache file \"%s\" failed [recompile]\n", cache_path);
			goto end;
		}
	}
	api_cache = (ZENGL_EXPORT_API_CACHE_TYPE *)cachePoint;
	if(api_cache->signer != ZL_EXP_API_CACHE_SIGNER) { // 根据缓存签名判断是否是有效的缓存数据
		write_to_server_log_pipe(WRITE_TO_PIPE, "invalid cache file \"%s\" [recompile]\n", cache_path);
		goto end;
	}
	mempoolPtr = ((ZL_EXP_BYTE *)cachePoint + api_cache->mempoolOffset);
	offset = (ZL_EXP_LONG)api_cache->filenames;
	filenames = (ZL_EXP_CHAR **)(mempoolPtr + offset - 1);
	if(api_cache->filenames_count > 0) {
		// 循环判断加载的脚本文件的内容是否发生了改变，如果改变了，则需要重新编译生成新的缓存
		for(i=0; i < api_cache->filenames_count; i++) {
			offset = (ZL_EXP_LONG)(filenames[i]);
			filename = (ZL_EXP_CHAR *)(mempoolPtr + offset - 1);
			if(stat(filename, &stat_result)==0) {
				file_mtime = (ZL_EXP_LONG)stat_result.st_mtime;
				if(file_mtime >= cache_mtime){
					write_to_server_log_pipe(WRITE_TO_PIPE, "\"%s\" mtime:%ld [changed] [recompile]\n", filename, file_mtime);
					goto end;
				}
			}
			else {
				write_to_server_log_pipe(WRITE_TO_PIPE, " stat \"%s\" failed [recompile]\n", filename);
				goto end;
			}
		}
	}
	// 通过zenglApi_ReUseCacheMemData接口函数，将编译好的缓存数据加载到编译器和解释器中，这样就可以跳过编译过程，直接运行
	if(zenglApi_ReUseCacheMemData(VM, cachePoint, cacheSize) == -1) {
		if(is_use_shm)
			write_to_server_log_pipe(WRITE_TO_PIPE, "[shm:0x%x] reuse cache file \"%s\" failed: %s [recompile]\n", share_mem_key, cache_path, zenglApi_GetErrorString(VM));
		else
			write_to_server_log_pipe(WRITE_TO_PIPE, "reuse cache file \"%s\" failed: %s [recompile]\n", cache_path, zenglApi_GetErrorString(VM));
		goto end;
	}
	(* is_reuse_cache) = ZL_EXP_TRUE;
	if(is_use_shm)
		write_to_server_log_pipe(WRITE_TO_PIPE, "[shm:0x%x] reuse cache file: \"%s\" mtime:%ld\n", share_mem_key, cache_path, cache_mtime);
	else
		write_to_server_log_pipe(WRITE_TO_PIPE, "reuse cache file: \"%s\" mtime:%ld\n", cache_path, cache_mtime);
end:
	fclose(ptr_fp);
	flock(ptr_fp->_fileno, LOCK_UN); // 解锁
	if(cachePoint != NULL) {
		if(is_use_shm) // 如果使用了共享内存，则通过shmdt来解除映射
			shmdt(cachePoint);
		else // 如果是普通的文件缓存方式，则将之前创建的堆内存释放掉
			free(cachePoint);
	}
}

/**
 * 在编译执行结束后，生成缓存数据并写入缓存文件
 */
static void main_write_zengl_cache_to_file(ZL_EXP_VOID * VM, char * cache_path)
{
	FILE * ptr_fp;
	ZL_EXP_VOID * cachePoint;
	ZL_EXP_INT cacheSize;
	// 通过zenglApi_CacheMemData接口函数，将编译器和解释器中的主要的内存数据缓存到cachePoint对应的内存中
	if(zenglApi_CacheMemData(VM, &cachePoint, &cacheSize) == -1) {
		write_to_server_log_pipe(WRITE_TO_PIPE, "write zengl cache to file \"%s\" failed: %s\n", cache_path,zenglApi_GetErrorString(VM));
		return;
	}

	// 打开cache_path对应的缓存文件
	if((ptr_fp = fopen(cache_path, "wb")) == NULL) {
		write_to_server_log_pipe(WRITE_TO_PIPE, "write zengl cache to file \"%s\" failed: open failed\n", cache_path);
		return;
	}
	flock(ptr_fp->_fileno, LOCK_EX); // 写入缓存数据之前，先加入互斥锁，让所有读进程等待写入完成
	struct stat stat_result;
	fstat(ptr_fp->_fileno, &stat_result);
	ZL_EXP_INT cachefileSize = stat_result.st_size;
	key_t share_mem_key = ftok(cache_path, 1);
	int shm_id = shmget(share_mem_key, cachefileSize, 0666);
	if(shm_id != -1) { // 由于生成了新的编译缓存数据，因此，如果存在对应的共享内存，则将共享内存移除掉，下次读缓存时，就会创建一个新的共享内存，并将新的缓存数据写入共享内存
		shmctl(shm_id, IPC_RMID, NULL);
		write_to_server_log_pipe(WRITE_TO_PIPE, "remove shm key: 0x%x, shm id: %d, ", share_mem_key, shm_id);
	}
	// 将缓存数据写入缓存文件
	if( fwrite(cachePoint, cacheSize, 1, ptr_fp) != 1)
		write_to_server_log_pipe(WRITE_TO_PIPE, "write zengl cache to file \"%s\" failed: write failed\n", cache_path);
	else
		write_to_server_log_pipe(WRITE_TO_PIPE, "write zengl cache to file \"%s\" success \n", cache_path);
	fclose(ptr_fp);
	flock(ptr_fp->_fileno, LOCK_UN); // 解锁
}

/**
 * 获取webroot网站根目录
 */
char * main_get_webroot()
{
	return webroot;
}

/**
 * 将append_path路径追加到full_path中，如果追加路径后，full_path长度会超出full_path_size时，路径将会被截断
 */
int main_full_path_append(char * full_path, int full_path_length, int full_path_size, char * append_path)
{
	int append_path_length = strlen(append_path);
	int max_length = full_path_size - full_path_length - 1;
	if(append_path_length > max_length)
		append_path_length = max_length;
	if(append_path_length > 0) {
		strncpy((full_path + full_path_length), append_path, append_path_length);
		return append_path_length;
	}
	else {
		return 0;
	}
}

/**
 * 模块函数中，可以通过此函数来获取配置文件设置过的会话目录，会话超时时间，以及cleaner进程的清理时间间隔
 */
void main_get_session_config(char ** session_dir, long * session_expire, long * session_cleaner_interval)
{
	if(session_dir != NULL)
		(*session_dir) = config_session_dir;
	if(session_expire != NULL)
		(*session_expire) = config_session_expire;
	if(session_cleaner_interval != NULL)
		(*session_cleaner_interval) = config_session_cleaner_interval;
}

/**
 * bltIsRunInCmd模块函数会通过此函数来判断当前是否处于命令行模式
 */
void main_check_is_run_in_cmd(ZL_EXP_BOOL * arg_is_run_in_cmd)
{
	if(arg_is_run_in_cmd != NULL)
		(*arg_is_run_in_cmd) = is_run_in_cmd;
}

/**
 * bltSetImmediatePrint模块函数会通过此函数，来设置当前是否启用立即打印模式
 * 在立即打印模式中，命令行下运行的脚本在使用print指令输出信息时，会立即输出到命令行终端
 */
void main_set_is_immediate_print(ZL_EXP_BOOL arg_is_immediate_print)
{
	is_immediate_print = arg_is_immediate_print;
}

/**
 * 在进行远程调试时，可以通过此函数来获取配置文件中和远程调试相关的配置信息
 * 例如 remote_debug_enable：是否开启了远程调试，remote_debugger_ip：远程调试器的ip地址，remote_debugger_port：远程调试器的端口号
 */
void main_get_remote_debug_config(long * remote_debug_enable, char ** remote_debugger_ip, long * remote_debugger_port)
{
	if(remote_debug_enable != NULL)
		(*remote_debug_enable) = config_remote_debug_enable;
	if(remote_debugger_ip != NULL)
		(*remote_debugger_ip) = config_remote_debugger_ip;
	if(remote_debugger_port != NULL)
		(*remote_debugger_port) = config_remote_debugger_port;
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
	// 当配置文件中的verbose值为FALSE时(即开启精简日志模式时)，就不在日志中记录WRITE_TO_PIPE的信息，这些信息大部分是方便调试开发的信息
	if(config_verbose == ZL_EXP_FALSE) {
		if(write_to_pipe == WRITE_TO_PIPE)
			return 0;
	}
	// 命令行模式下，只有一个进程，所以这种情况下，直接写入日志文件即可
	if(is_run_in_cmd == ZL_EXP_TRUE) {
		write_to_pipe = WRITE_TO_LOG;
	}
	if(server_log_pipe_string.str == NULL) {
		server_log_pipe_string.size = SERVER_LOG_PIPE_STR_SIZE;
		server_log_pipe_string.str = (char *)malloc(server_log_pipe_string.size * sizeof(char));
	}
	int retcount = 0;
	va_list arglist;
	while(1) {
		va_start(arglist, format);
		retcount = vsnprintf(server_log_pipe_string.str, server_log_pipe_string.size, format, arglist);
		va_end(arglist);
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
		else if(retcount < 0 && errno !=0) { // 记录写入日志时，可能会发生的错误
			retcount = snprintf(server_log_pipe_string.str, server_log_pipe_string.size, "write log errno:%d, errstr:%s \n", errno, strerror(errno));
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
	return retcount;
}

/**
 * zenglServer启动时会执行的入口函数
 */
int main(int argc, char * argv[])
{
	int o;
	char * config_file = NULL;
	char * logfile = NULL;
	char * run_cmd = NULL; // 需要在命令行中执行的脚本的相对路径(包括需要传递给脚本的参数)
	zlsrv_main_argv = argv;
	// 通过getopt的C库函数来获取用户在命令行中输入的参数，并根据这些参数去执行不同的操作
	while (-1 != (o = getopt(argc, argv, "vhc:l:r:"))) {
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
		case 'l':
			logfile = optarg;
			break;
		// 当使用-r选项时，可以直接在命令行中运行脚本，-r后面需要跟随脚本的url路径和参数信息，例如: ./zenglServer -r "/v0_1_1/test.zl?a=12&b=456"
		case 'r':
			run_cmd = optarg;
			is_run_in_cmd = ZL_EXP_TRUE; // 将is_run_in_cmd设置为TRUE，表示当前在命令行中运行
			if(strlen(run_cmd) == 0) {
				printf("please set script url for -r option\n");
				exit(-1);
			}
			break;
		// 当使用-h参数时，会显示出帮助信息，然后直接返回以退出程序
		case 'h':
			printf("usage: ./zenglServer [options]\n" \
					"-v                  show version\n" \
					"-c <config file>    set config file\n" \
					"-l <logfile>        set logfile\n" \
					"-r <script_url>     set script url(include query params) for cmd\n" \
					"-h                  show this help\n");
			return 0;
		default:
			exit(-1);
			break;
		}
	}

	if(logfile == NULL) {
		logfile = "logfile";
	}

	// 后面会切换到守护进程，所有信息都会写入到logfile日志文件中
	if ((server_log_fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT, 0644)) < 0) {
		printf("open %s for server_log_fd failed [%d] %s \n", logfile, errno, strerror(errno));
		exit(errno);
	}

	// 将日志文件名保存到server_logfile变量所指向的字符串中
	server_logfile = malloc(strlen(logfile) + 1);
	strncpy(server_logfile, logfile, strlen(logfile));
	server_logfile[strlen(logfile)] = '\0';

	//通过fork创建master主进程，该进程将在后台以守护进程的形式一直运行，并通过该进程来创建执行具体任务的child子进程
	if(run_cmd == NULL) {
		pid_t master_pid = fork();
		if(master_pid < 0) {
			WRITE_LOG_WITH_PRINTF("failed to create master process [%d] %s \n", errno, strerror(errno));
			// 创建master进程失败，直接退出
			exit(-1);
		}
		else if(master_pid > 0) {
			// 记录master主进程的进程ID
			write_to_server_log_pipe(WRITE_TO_LOG, "create master process for daemon [pid:%d] \n", master_pid);
			// 创建完master进程后，直接返回以退出当前进程
			return 0;
		}
	}
	else { // 命令行模式下，只需要一个进程，就不需要再创建子进程了
		write_to_server_log_pipe(WRITE_TO_LOG, "**--------- cmd begin ---------***\ncreate master process for cmd [pid:%d] \n", getpid());
	}

	// 创建日志用的管道，子进程中的日志信息会先写入管道，再由主进程统一从管道中读取出来，并写入日志文件中
	if (pipe(server_log_pipefd) == -1) {
		WRITE_LOG_WITH_PRINTF("pipe() failed [%d] %s \n", errno, strerror(errno));
		exit(errno);
	}

	// 当通过make命令设置自定义的URL_PATH_SIZE时，如果设置的值小于等于30，或者大于4096时，就提示需要重新设置，并退出程序
	if(URL_PATH_SIZE <= 30) {
		WRITE_LOG_WITH_PRINTF("the URL_PATH_SIZE: %d is too small, please redefine it.\n", URL_PATH_SIZE);
		exit(-1);
	}
	else if(URL_PATH_SIZE > 4096) {
		WRITE_LOG_WITH_PRINTF("the URL_PATH_SIZE: %d is too big, please redefine it.\n", URL_PATH_SIZE);
		exit(-1);
	}

	// 当通过make命令设置自定义的FULL_PATH_SIZE时，如果设置的值小于等于30，或者大于4096时，就提示需要重新设置，并退出程序
	if(FULL_PATH_SIZE <= 30) {
		WRITE_LOG_WITH_PRINTF("the FULL_PATH_SIZE: %d is too small, please redefine it.\n", FULL_PATH_SIZE);
		exit(-1);
	}
	else if(FULL_PATH_SIZE > 4096) {
		WRITE_LOG_WITH_PRINTF("the FULL_PATH_SIZE: %d is too big, please redefine it.\n", FULL_PATH_SIZE);
		exit(-1);
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
		WRITE_LOG_WITH_PRINTF("错误：编译执行<%s>失败：%s\n", config_file, zenglApi_GetErrorString(VM));
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
		WRITE_LOG_WITH_PRINTF_NOARG("warning: thread_num_per_process is not use now \n");
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
		config_web_root[strlen(webroot)] = '\0';
		webroot = config_web_root;
	}
	// 否则抛出警告，并使用默认的web根目录名
	else {
		WRITE_LOG_WITH_PRINTF("warning: webroot in %s too long, use default webroot\n", config_file);
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

	char * session_dir;
	// 获取配置文件中设置的session_dir会话目录，如果没有定义，则默认使用SESSION_DIR_DEFAULT宏定义的值
	if((session_dir = zenglApi_GetValueAsString(VM,"session_dir")) == NULL)
		session_dir = SESSION_DIR_DEFAULT;
	else if(strlen(session_dir) >= sizeof(config_session_dir)) {
		WRITE_LOG_WITH_PRINTF("warning: session_dir in %s is too long, use default session_dir\n", config_file);
		session_dir = SESSION_DIR_DEFAULT;
	}
	strncpy(config_session_dir, session_dir, strlen(session_dir));
	config_session_dir[strlen(session_dir)] = '\0';

	// 获取配置文件中设置的session_expire会话文件的过期时间，如果没有定义，则默认使用SESSION_EXPIRE宏定义的值
	if(zenglApi_GetValueAsInt(VM,"session_expire", &config_session_expire) < 0)
		config_session_expire = SESSION_EXPIRE;

	// 获取配置文件中设置的session_cleaner_interval清理进程的清理时间间隔，如果没有定义，则默认使用SESSION_CLEANER_INTERVAL宏定义的值
	if(zenglApi_GetValueAsInt(VM,"session_cleaner_interval", &config_session_cleaner_interval) < 0)
		config_session_cleaner_interval = SESSION_CLEANER_INTERVAL;

	// 获取配置文件中设置的remote_debug_enable即是否开启远程调试
	if(zenglApi_GetValueAsInt(VM,"remote_debug_enable", &config_remote_debug_enable) < 0)
		config_remote_debug_enable = ZL_EXP_FALSE;

	char * remote_debugger_ip;
	// 获取配置文件中设置的remote_debugger_ip即远程调试器的IP地址，如果没有设置过
	// 或者设置的ip地址的长度超出了config_remote_debugger_ip可以容纳的字符范围，则使用REMOTE_DEBUGGER_IP_DEFAULT宏定义的默认的IP地址
	if((remote_debugger_ip = zenglApi_GetValueAsString(VM,"remote_debugger_ip")) == NULL)
		remote_debugger_ip = REMOTE_DEBUGGER_IP_DEFAULT;
	else if(strlen(remote_debugger_ip) >= sizeof(config_remote_debugger_ip)) {
		WRITE_LOG_WITH_PRINTF("warning: remote_debugger_ip in %s is too long, use default ip\n", config_file);
		remote_debugger_ip = REMOTE_DEBUGGER_IP_DEFAULT;
	}
	strncpy(config_remote_debugger_ip, remote_debugger_ip, strlen(remote_debugger_ip));
	config_remote_debugger_ip[strlen(remote_debugger_ip)] = '\0';

	// 获取配置文件中设置的remote_debugger_port即远程调试器的端口号
	if(zenglApi_GetValueAsInt(VM,"remote_debugger_port", &config_remote_debugger_port) < 0)
		config_remote_debugger_port = REMOTE_DEBUGGER_PORT;

	// 获取配置文件中设置的zengl_cache_enable即是否开启zengl脚本的编译缓存
	if(zenglApi_GetValueAsInt(VM,"zengl_cache_enable", &config_zengl_cache_enable) < 0)
		config_zengl_cache_enable = ZL_EXP_FALSE;

	// 获取配置文件中设置的shm_enable即是否开启共享内存来存储编译缓存
	if(zenglApi_GetValueAsInt(VM,"shm_enable", &config_shm_enable) < 0)
		config_shm_enable = ZL_EXP_FALSE;

	// 获取配置文件中设置的shm_min_size的值，也就是开启共享内存的情况下，需要放进共享内存的缓存的最小大小，只有超过这个大小的缓存才放入共享内存中，以字节为单位
	if(zenglApi_GetValueAsInt(VM,"shm_min_size", &config_shm_min_size) < 0)
		config_shm_min_size = SHM_MIN_SIZE;

	// 获取配置文件中设置的verbose的值，该配置表示是使用详细日志模式，还是精简日志模式，默认是TRUE即详细日志模式，
	// 设置为FALSE可以切换到精简日志模式，在详细日志模式中，会将每个请求的请求头和响应头都记录到日志中
	if(zenglApi_GetValueAsInt(VM,"verbose", &config_verbose) < 0)
		config_verbose = ZL_EXP_TRUE;

	// 获取配置文件中设置的request_body_max_size的值，用于设置每个请求的主体数据所允许的最大字节值
	if(zenglApi_GetValueAsInt(VM,"request_body_max_size", &config_request_body_max_size) < 0)
		config_request_body_max_size = REQUEST_BODY_STR_MAX_SIZE;

	// 获取配置文件中设置的request_header_max_size的值，用于设置每个请求头所允许的最大字节值
	if(zenglApi_GetValueAsInt(VM,"request_header_max_size", &config_request_header_max_size) < 0)
		config_request_header_max_size = REQUEST_HEADER_STR_MAX_SIZE;

	// 获取配置文件中设置的request_url_max_size的值，用于设置url资源路径(包括请求参数在内)所允许的最大字符数
	if(zenglApi_GetValueAsInt(VM,"request_url_max_size", &config_request_url_max_size) < 0)
		config_request_url_max_size = REQUEST_URL_STR_MAX_SIZE;

	char * pidfile;
	config_pidfile[0] = '\0';
	// 获取配置文件中设置的pidfile的值，用于设置记录主进程的进程ID的文件名(该文件名可以是相对于当前工作目录的路径)
	if((pidfile = zenglApi_GetValueAsString(VM,"pidfile")) != NULL) {
		if((strlen(pidfile) + 1) <= sizeof(config_pidfile)) {
			strncpy(config_pidfile, pidfile, strlen(pidfile));
			config_pidfile[strlen(pidfile)] = '\0';
		}
		else {
			WRITE_LOG_WITH_PRINTF("warning: pidfile in %s is too long, so no pidfile use\n", config_file);
		}
	}

	// 显示出配置文件中定义的配置信息，如果配置文件没有定义这些值，则显示出默认值
	write_to_server_log_pipe(WRITE_TO_LOG, "run %s complete, config: \n", config_file);
	write_to_server_log_pipe(WRITE_TO_LOG, "port: %ld process_num: %ld\n", port, server_process_num);
	write_to_server_log_pipe(WRITE_TO_LOG, "webroot: %s\n", webroot);
	if(zl_debug_log != NULL) {
		write_to_server_log_pipe(WRITE_TO_LOG, "zl_debug_log: %s\n", zl_debug_log);
	}
	write_to_server_log_pipe(WRITE_TO_LOG, "session_dir: %s session_expire: %ld cleaner_interval: %ld\n", config_session_dir,
			config_session_expire,
			config_session_cleaner_interval);
	// 将远程调试相关的配置，以及是否开启zengl脚本的编译缓存等配置，记录到日志中
	write_to_server_log_pipe(WRITE_TO_LOG, "remote_debug_enable: %s remote_debugger_ip: %s remote_debugger_port: %ld"
			" zengl_cache_enable: %s shm_enable: %s shm_min_size: %ld\n"
			"verbose: %s request_body_max_size: %ld, request_header_max_size: %ld request_url_max_size: %ld\n"
			"URL_PATH_SIZE: %d FULL_PATH_SIZE: %d\n",
			config_remote_debug_enable ? "True" : "False",
			config_remote_debugger_ip,
			config_remote_debugger_port,
			config_zengl_cache_enable ? "True" : "False",
			config_shm_enable ? "True" : "False",
			config_shm_min_size,
			config_verbose ? "True" : "False",
			config_request_body_max_size,
			config_request_header_max_size,
			config_request_url_max_size,
			URL_PATH_SIZE, FULL_PATH_SIZE);

	// 如果设置了pidfile文件，则将主进程的进程ID记录到pidfile所指定的文件中(只有在非命令行模式下，才需要执行这步操作)
	if(run_cmd == NULL) {
		if(strlen(config_pidfile) > 0) {
			write_to_server_log_pipe(WRITE_TO_LOG, "pidfile: %s\n", config_pidfile);
			char master_pid_str[30];
			snprintf(master_pid_str, 30, "%d", getpid());
			int pidfile_fd = open(config_pidfile, O_WRONLY|O_TRUNC|O_CREAT, 0644); // TODO
			if(pidfile_fd < 0) {
				WRITE_LOG_WITH_PRINTF("open %s for pidfile failed [%d] %s \n", config_pidfile, errno, strerror(errno));
			}
			else {
				write(pidfile_fd, master_pid_str, strlen(master_pid_str));
				close(pidfile_fd);
			}
		}
		else {
			write_to_server_log_pipe(WRITE_TO_LOG, "no pidfile.\n");
		}
	}

	// 关闭虚拟机，并释放掉虚拟机所分配过的系统资源
	zenglApi_Close(VM);

	// 如果是命令行模式，则通过main_run_cmd函数在命令行中直接运行脚本
	if(run_cmd != NULL)
	{
		// 设置当命令行主进程发生段错误时(系统会产生SIGSEGV信号)，会执行的SIGSEGV信号处理函数
		if (signal(SIGSEGV, dump_process_segv_fault) == SIG_ERR) {
			write_to_server_log_pipe(WRITE_TO_LOG, "main process: can't catch SIGSEGV\n");
			exit(-1);
		}
		int cmd_ret = main_run_cmd(run_cmd);
		write_to_server_log_pipe(WRITE_TO_LOG, "**--------- cmd end return:%d ---------***\n\n", cmd_ret);
		return cmd_ret;
	}
	else
	{
		char master_process_name[255] = {0};
		size_t cmd_max_size = 4096;
		char * cwd = (char *)malloc(cmd_max_size);
		memset(cwd, 0, cmd_max_size);
		// 获取当前的工作目录，并将工作目录设置到主进程的名称中
		if(getcwd(cwd, cmd_max_size) == NULL) {
			WRITE_LOG_WITH_PRINTF("failed to get cwd  [%d] %s \n", errno, strerror(errno));
			exit(-1);
		}
		snprintf(master_process_name, 0xff, "zenglServer: master[%ld] cwd:%s -c %s -l %s",
				port, cwd, config_file, logfile);
		free(cwd);
		char * errorstr = NULL;
		if(zlsrv_init_setproctitle(&errorstr) < 0) {
			WRITE_LOG_WITH_PRINTF("%s \n", errorstr);
			exit(-1);
		}
		// 将主进程的名称设置为zenglServer: master，可以在ps aux命令的输出信息中查看到该名称
		zlsrv_setproctitle(master_process_name);
	}

	struct sockaddr_in server_addr;
	// 创建服务端套接字
	server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(server_socket_fd == -1)
	{
		WRITE_LOG_WITH_PRINTF("failed to create server socket [%d] %s \n", errno, strerror(errno));
		exit(-1);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY; // 将套接字绑定到任意IP，除了本机可以访问外，外部网络也可以通过IP加端口号来访问到zenglServer
	server_addr.sin_port = htons((uint16_t)port); // 将套接字绑定到指定的端口
	int enable = 1;
	// 开启套接字的REUSEADDR选项，这样，当zenglServer关闭后，可以马上启动并重新绑定到该端口(否则，就需要等待一段时间，可能需要等待好几分钟才能再次绑定到同一个端口)
	if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
		WRITE_LOG_WITH_PRINTF("setsockopt(SO_REUSEADDR) failed [%d] %s \n", errno, strerror(errno));
		exit(-1);
	}
	// 将服务端套接字绑定到server_addr所指定的IP和端口上
	if(bind(server_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		WRITE_LOG_WITH_PRINTF("failed to bind server socket [%d] %s \n", errno, strerror(errno));
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
		WRITE_LOG_WITH_PRINTF("accept sem init failed : [%d] %s \n", errno, strerror(errno));
		exit(-1);
	}
	write_to_server_log_pipe(WRITE_TO_LOG, "accept sem initialized.\n");

	// 获取当前进程可以打开的文件描述符数量限制，用于控制epoll监听的文件描述符数
	struct rlimit limit;
	if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
		WRITE_LOG_WITH_PRINTF("getrlimit() failed with errno=%d %s\n", errno, strerror(errno));
		exit(1);
	}
	process_max_open_fd_num = limit.rlim_cur;
	write_to_server_log_pipe(WRITE_TO_LOG, "process_max_open_fd_num: %d \n", process_max_open_fd_num);

	// 将umask设为0，让子进程给文件设置的读写执行权限不会被屏蔽掉
	umask(0);
	int logStdout;
	if ((logStdout = open("/dev/null", O_WRONLY|O_APPEND|O_CREAT, 0644)) < 0) {
		WRITE_LOG_WITH_PRINTF("open /dev/null failed [%d] %s \n", errno, strerror(errno));
		exit(errno);
	}
	// 设置新的会话，这样主进程和子进程就不会受到控制台信号的影响了
	if (setsid() < 0) {
		WRITE_LOG_WITH_PRINTF("setsid() failed [%d] %s \n", errno, strerror(errno));
		exit(errno);
	}
	// 将标准输入和输出重定向到/dev/null
	dup2(logStdout, STDIN_FILENO);
	dup2(logStdout, STDOUT_FILENO);
	dup2(logStdout, STDERR_FILENO);
	close(logStdout);

	// 根据process_num的值，创建多个子进程，如果是调试模式，一般就设置一个子进程，方便gdb调试
	for(int i=0;i < server_process_num;i++)
	{
		fork_child_process(i);
	}

	// 创建cleaner清理进程，该进程会定期清理过期的会话文件
	fork_cleaner_process();

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
 * 当zenglServer的命令行模式下的主进程或web模式下的工作子进程因为严重的段错误导致进程挂掉时，
 * 会通过下面这个C函数将段错误相关的函数栈追踪信息记录到日志中，从而可以分析出段错误发生的原因，
 * 由于记录在日志中的函数栈追踪信息里的地址是十六进制格式的地址，所以，还需要通过addr2line命令将这些地址转为具体的函数名(包括这些函数所在的C文件路径及行号信息)
 * 例如：addr2line 0x46a161 -e zenglServer -f 假设该命令中的0x46a161是日志中记录的函数地址的十六进制格式，那么得到的结果类似如下所示：
 * zenglrun_RunInsts (函数名)
 * /root/zenglServerTest/zengl/linux/zenglrun_main.c:1245 (函数所在的C文件路径及行号信息)
 */
static void dump_process_segv_fault()
{
	void *buffer[100] = {0};
	size_t size;
	char **strings = NULL;
	size_t i = 0;

	size = backtrace(buffer, 100);
	write_to_server_log_pipe(WRITE_TO_PIPE_, "segv fault backtrace() returned %d addresses \n", size);
	strings = backtrace_symbols(buffer, size);
	if (strings == NULL) {
		write_to_server_log_pipe(WRITE_TO_PIPE_, "error: backtrace_symbols return NULL");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < size; i++)
	{
		write_to_server_log_pipe(WRITE_TO_PIPE_, "%s\n", strings[i]);
	}

	free(strings);
	strings = NULL;
	exit(0);
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

		{
			// 设置child子进程的进程名
			char child_process_name[80];
			snprintf(child_process_name, sizeof(child_process_name), "zenglServer: child(%d) ppid:%d", idx, getppid());
			zlsrv_setproctitle(child_process_name);
		}

		// 将子进程从父进程继承过来的信号处理函数取消掉
		if (!trap_signals(ZL_EXP_FALSE)) {
			fprintf(stderr, "Child %d: trap_signals() failed!\n", idx);
			exit(1);
		}

		// 设置当子进程发生段错误时(系统会产生SIGSEGV信号)，会执行的SIGSEGV信号处理函数
		if (signal(SIGSEGV, dump_process_segv_fault) == SIG_ERR) {
			fprintf(stderr, "Child %d: can't catch SIGSEGV", idx);
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
 * 创建cleaner清理进程，该进程会定期清理过期的会话文件
 */
void fork_cleaner_process()
{
	pid_t childpid = fork();

	if(childpid == 0) {

		{
			char cleaner_process_name[80];
			snprintf(cleaner_process_name, sizeof(cleaner_process_name), "zenglServer: cleaner  ppid:%d", getppid());
			// 设置cleaner进程的进程名
			zlsrv_setproctitle(cleaner_process_name);
		}

		// 将cleaner进程从父进程继承过来的信号处理函数取消掉
		if (!trap_signals(ZL_EXP_FALSE)) {
			fprintf(stderr, "Cleaner [pid:%d]: trap_signals() failed!\n", childpid);
			exit(1);
		}
		do {
			DIR * dp;
			struct dirent * ep;
			char * path = config_session_dir;
			char filename[SESSION_FILEPATH_MAX_LEN];
			int path_dir_len = strlen(path);
			int ep_name_len, left_len;
			struct stat ep_stat;
			strncpy(filename, path, path_dir_len);
			filename[path_dir_len] = '/';
			left_len = SESSION_FILEPATH_MAX_LEN - path_dir_len - 2;

			dp = opendir(path);
			if (dp != NULL)
			{
				time_t cur_time = time(NULL);
				time_t compare_time = (cur_time - 10); // 删除10秒前的超时会话文件，预留10秒，防止当前时间刚生成的会话文件被误删除
				int cpy_len;
				while((ep = readdir(dp)))
				{
					ep_name_len = strlen(ep->d_name);
					if(ep_name_len > 20) {
						cpy_len = (ep_name_len <= left_len) ?  ep_name_len : left_len;
						strncpy(filename + path_dir_len + 1, ep->d_name, cpy_len);
						filename[path_dir_len + 1 + cpy_len] = '\0';
						if(stat(filename, &ep_stat) == 0) {
							if(ep_stat.st_mtime < compare_time) {
								remove(filename);
								write_to_server_log_pipe(WRITE_TO_PIPE, "************ cleaner remove file: %s [m_time:%d < %d]\n", ep->d_name, ep_stat.st_mtime, compare_time);
							}
						}
						else
							write_to_server_log_pipe(WRITE_TO_PIPE, "!!!******!!! cleaner remove \"%s\" failed [%d] %s\n", filename, errno, strerror(errno));
					}
				}
				closedir(dp);
			}
			else {
				write_to_server_log_pipe(WRITE_TO_PIPE, "!!!******!!! cleaner opendir \"%s\" failed [%d] %s\n", path, errno, strerror(errno));
			}
			write_to_server_log_pipe(WRITE_TO_PIPE, "------------ cleaner sleep begin: %d\n", time(NULL));
			sleep(config_session_cleaner_interval);
			write_to_server_log_pipe(WRITE_TO_PIPE, "------------ cleaner sleep end: %d\n", time(NULL));
		} while(1);
	}
	else if(childpid > 0) { // childpid大于0，表示当前是主进程，就向日志中输出创建的子进程的信息
		write_to_server_log_pipe(WRITE_TO_LOG, "Master: Spawning cleaner [pid %d] \n", childpid);
		server_cleaner_process = childpid;
	}
}

/**
 * 将子进程退出的原因写入到日志中
 */
static void log_sig_child_exit(const char * child_name, pid_t pid, int status)
{
	if (WIFEXITED(status))
		write_to_server_log_pipe(WRITE_TO_LOG, "%s PID %d exited normally.  Exit number:  %d\n", child_name, pid, WEXITSTATUS(status));
	else {
		if (WIFSTOPPED(status))
			write_to_server_log_pipe(WRITE_TO_LOG, "%s PID %d was stopped by %d\n", child_name, pid, WSTOPSIG(status));
		else {
			if (WIFSIGNALED(status))
				write_to_server_log_pipe(WRITE_TO_LOG, "%s PID %d exited due to signal %d\n.", child_name, pid, WTERMSIG(status));
			else
				write_to_server_log_pipe(WRITE_TO_LOG, "%s PID %d exited, status: %d", child_name, pid, status);
		}
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
        	log_sig_child_exit("child", pid, status[i]);
			// 通过fork_child_process函数重新创建一个新的子进程，继续工作
			fork_child_process(i);
        }
    }
    int cleaner_status;
    pid = waitpid(server_cleaner_process, &cleaner_status, WNOHANG); /* waitpid时采用WNOHANG非阻塞模式 */
    if(pid < 0) {
		write_to_server_log_pipe(WRITE_TO_LOG, "waitpid error [%d] %s", errno, strerror(errno));
	}
	else if(!pid) {
		/* waitpid返回0，表示该cleaner进程正在运行中 */
		return;
	}
	else {
		// pid大于0，说明cleaner进程已经退出，则根据cleaner_status退出码，将进程退出的原因写入到日志中
		log_sig_child_exit("cleaner", pid, cleaner_status);
		// 通过fork_cleaner_process函数重新创建一个新的cleaner进程，继续工作
		fork_cleaner_process();
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

	// 向清理进程发送终止信号
	kill(server_cleaner_process, SIGTERM);

	/* 循环等待所有子进程结束 */
	while ((pid = wait(&status)) != -1)
		write_to_server_log_pipe(WRITE_TO_LOG, ".");

	write_to_server_log_pipe(WRITE_TO_LOG, "\nAll children reaped, shutting down.\n");

	// 删除共享内存
	DIR * dp;
	struct dirent * ep;
	char * path = "zengl/caches";
	char filename[SESSION_FILEPATH_MAX_LEN];
	int path_dir_len = strlen(path);
	int ep_name_len, left_len, del_shm_num = 0;
	key_t share_mem_key;
	struct stat ep_stat;
	strncpy(filename, path, path_dir_len);
	filename[path_dir_len] = '/';
	left_len = SESSION_FILEPATH_MAX_LEN - path_dir_len - 2;

	dp = opendir(path);
	if (dp != NULL) // 循环根据编译缓存的文件名，得到相应的共享内存key，并根据key将已存在的共享内存移除掉
	{
		int cpy_len;
		while((ep = readdir(dp)))
		{
			ep_name_len = strlen(ep->d_name);
			if(ep_name_len > 20) {
				cpy_len = (ep_name_len <= left_len) ?  ep_name_len : left_len;
				strncpy(filename + path_dir_len + 1, ep->d_name, cpy_len);
				filename[path_dir_len + 1 + cpy_len] = '\0';
				if(stat(filename, &ep_stat) == 0) {
					if(ep_stat.st_size > config_shm_min_size) {
						share_mem_key = ftok(filename, 1);
						int shm_id = shmget(share_mem_key, ep_stat.st_size, 0666);
						if(shm_id != -1) {
							shmctl(shm_id, IPC_RMID, NULL);
							write_to_server_log_pipe(WRITE_TO_LOG, "************ remove shm key: 0x%x [cache_file: %s]\n", share_mem_key, ep->d_name);
							del_shm_num++;
						}
						else if(errno != ENOENT) {
							write_to_server_log_pipe(WRITE_TO_LOG, "!!!******!!! remove shm key: 0x%x failed [%d] %s\n", share_mem_key, errno, strerror(errno));
						}
					}
				}
				else
					write_to_server_log_pipe(WRITE_TO_LOG, "!!!******!!! remove shm cache_path: \"%s\" failed [%d] %s\n", filename, errno, strerror(errno));
			}
		}
		closedir(dp);
	}
	else {
		write_to_server_log_pipe(WRITE_TO_LOG, "!!!******!!! opendir \"%s\" failed [%d] %s\n", path, errno, strerror(errno));
	}
	write_to_server_log_pipe(WRITE_TO_LOG, "------------ remove shm number: %d\n", del_shm_num);

	// 如果所有子进程都退出了，就释放相关资源，并退出主进程，子进程和主进程都退出后，整个程序也就退出了
	sem_unlink("accept_sem");
	sem_close(my_thread_lock.accept_sem);
	write_to_server_log_pipe(WRITE_TO_LOG, "closed accept_sem\n");
	shutdown(server_socket_fd, SHUT_RDWR);
	write_to_server_log_pipe(WRITE_TO_LOG, "shutdowned server socket\n");
	close(server_socket_fd);
	write_to_server_log_pipe(WRITE_TO_LOG, "closed server socket\n===================================\n\n");
	free(server_log_pipe_string.str);
	if(server_logfile != NULL) {
		free(server_logfile);
	}
	// 在退出程序时，自动清理掉pidfile对应的文件(该文件中记录了主进程的进程ID)
	if(strlen(config_pidfile) > 0) {
		unlink(config_pidfile);
	}
	exit(0);
}

/**
 * 当主进程接收到SIGUSR1信号时，会触发的信号处理函数，该信号处理函数会重新打开日志文件，
 * 通过该信号，可以实现在不重启程序的情况下，进行日志的备份和分割等操作
 */
void sig_usr1_callback()
{
	if(server_logfile != NULL) {
		int new_log_fd = -1;
		if ((new_log_fd = open(server_logfile, O_WRONLY|O_APPEND|O_CREAT, 0644)) < 0) {
			write_to_server_log_pipe(WRITE_TO_LOG, "open %s for server_log_fd failed [%d] %s \n", server_logfile,
					errno, strerror(errno));
			return ;
		}
		close(server_log_fd);
		server_log_fd = new_log_fd;
		write_to_server_log_pipe(WRITE_TO_LOG, "reopen %s in sigusr1 \n", server_logfile);
	}
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

    // 将SIGUSR1信号和sig_usr1_callback信号处理函数进行绑定
    server_sig_pairs[++i].signal          = SIGUSR1;
    server_sig_pairs[i].action.sa_handler = &sig_usr1_callback;

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
	// 在命令行模式下，如果开启了立即打印，则会直接通过printf函数将信息输出到终端
	if(is_immediate_print && is_run_in_cmd) {
		char str_null[1];
		str_null[0] = STR_NULL;
		dynamic_string_append(&my_data->response_body, str_null, 1, RESPONSE_BODY_STR_SIZE);
		printf("%s", my_data->response_body.str);
		// 释放response_body动态字符串
		dynamic_string_free(&my_data->response_body);
	}
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
	// 设置session模块的初始化函数，和session会话相关的C函数代码位于module_session.c文件里
	zenglApi_SetModInitHandle(VM_ARG,"session", module_session_init);
#ifdef USE_MAGICK
	// 设置magick模块的初始化函数，和magick模块相关的C函数代码位于module_magick.c文件里
	zenglApi_SetModInitHandle(VM_ARG,"magick", module_magick_init);
#endif
#ifdef USE_PCRE
	// 设置pcre模块的初始化函数，和pcre模块相关的C函数代码位于module_pcre.c文件里
	zenglApi_SetModInitHandle(VM_ARG,"pcre", module_pcre_init);
#endif
#ifdef USE_CURL
	// 设置curl模块的初始化函数，和curl模块相关的C函数代码位于module_curl.c文件里
	zenglApi_SetModInitHandle(VM_ARG,"curl", module_curl_init);
#endif
#ifdef USE_REDIS
	// 设置redis模块的初始化函数，和redis模块相关的C函数代码位于module_redis.c文件里
	zenglApi_SetModInitHandle(VM_ARG,"redis", module_redis_init);
#endif
#ifdef USE_OPENSSL
	// 设置openssl模块的初始化函数，和openssl模块相关的C函数代码位于module_openssl.c文件里
	zenglApi_SetModInitHandle(VM_ARG,"openssl", module_openssl_init);
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
		if(config_verbose)
			write_to_server_log_pipe(WRITE_TO_PIPE, "free socket_list[%d]/list_cnt:%d epoll_fd_add_count:%d pid:%d tid:%d\n", lst_idx,
					 socket_list->count, epoll_fd_add_count, getpid(), routine_get_tid());
		else
			write_to_server_log_pipe(WRITE_TO_PIPE_, "free [%d]/%d epoll:%d pid:%d tid:%d\n", lst_idx,
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
		write_to_server_log_pipe(WRITE_TO_PIPE_, "close single socket:%d pid:%d tid:%d\n", client_socket_fd, getpid(), routine_get_tid());
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
	if(config_verbose) {
		write_to_server_log_pipe(WRITE_TO_PIPE, "-----------------------------------\n%srecv [client_socket_fd:%d] [lst_idx:%d] [pid:%d] [tid:%d]:",
						current_time, socket_list->member[lst_idx].client_socket_fd, lst_idx, getpid(), routine_get_tid());
	}
	else {
		write_to_server_log_pipe(WRITE_TO_PIPE_, "%d/%02d/%02d %02d:%02d:%02d fd:%d idx:%d pid:%d tid:%d | ",
								(timeinfo->tm_year + 1900), (timeinfo->tm_mon + 1), (timeinfo->tm_mday),
								timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec,
								socket_list->member[lst_idx].client_socket_fd, lst_idx, getpid(), routine_get_tid());
	}
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
	if(config_verbose)
		write_to_server_log_pipe(WRITE_TO_PIPE, "url: %s\n", parser_data->request_url.str);
	else
		write_to_server_log_pipe(WRITE_TO_PIPE_, "url: %s | ", parser_data->request_url.str);
	// 通过http_parser_parse_url来解析url资源路径(包含查询字符串)，该函数会将路径信息和查询字符串信息给解析出来，并将解析结果存储到url_parser中
	if(http_parser_parse_url(parser_data->request_url.str,
			strlen(parser_data->request_url.str), 0,
			&(parser_data->url_parser))) {
		write_to_server_log_pipe(WRITE_TO_PIPE_, "**** failed to parse URL %s ****\n",
				socket_list->member[lst_idx].parser_data.request_url.str);
		routine_close_client_socket(socket_list, lst_idx);
		return -1;
	}
	char url_path[URL_PATH_SIZE];
	char decode_url_path[URL_PATH_SIZE];
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
	// 对客户端传递过来的url路径信息进行url解码，这样在linux中就可以访问utf8编码的中文路径了
	gl_request_url_decode(decode_url_path, url_path, strlen(url_path));
	write_to_server_log_pipe(WRITE_TO_PIPE, "url_path: %s\n", decode_url_path);
	int doc_fd;
	// full_path中存储了需要访问的目标文件的完整路径信息
	char full_path[FULL_PATH_SIZE];
	// status_code存储响应状态码，默认为200
	int status_code = 200;
	// 当发生403或404错误时，会将default_output_html指向特定的字符串，服务器会将这段字符串作为403或404错误的默认输出内容返回给客户端
	char * default_output_html = NULL;
	ZL_EXP_BOOL is_custom_status_code = ZL_EXP_FALSE; // 是否是自定义的请求头
	int content_length = 0;
	struct stat filestatus = {0};
	// 下面会根据webroot根目录，和url_path来构建full_path完整路径
	int full_length = main_full_path_append(full_path, 0, FULL_PATH_SIZE, webroot);
	int root_length = full_length;
	full_length += main_full_path_append(full_path, full_length, FULL_PATH_SIZE, decode_url_path);
	full_path[full_length] = '\0';
	stat(full_path, &filestatus);
	// 如果是访问目录，则将该目录中的index.html文件里的内容，作为结果反馈给客户端
	if(S_ISDIR(filestatus.st_mode)) {
		if(full_path[full_length - 1] == '/')
			full_length += main_full_path_append(full_path, full_length, FULL_PATH_SIZE, "index.html");
		else
			full_length += main_full_path_append(full_path, full_length, FULL_PATH_SIZE, "/index.html");
		full_path[full_length] = '\0';
		if(config_verbose)
			write_to_server_log_pipe(WRITE_TO_PIPE, "full_path: %s\n", full_path);
		else
			write_to_server_log_pipe(WRITE_TO_PIPE_, "full_path: %s | ", full_path);
		// 以只读方式打开文件
		doc_fd = open(full_path, O_RDONLY);
		if(doc_fd > 0) {
			stat(full_path, &filestatus);
		}
	}
	else {
		if(config_verbose)
			write_to_server_log_pipe(WRITE_TO_PIPE, "full_path: %s\n", full_path);
		else
			write_to_server_log_pipe(WRITE_TO_PIPE_, "full_path: %s | ", full_path);
		// 如果要访问的文件是以.zl结尾的，就将该文件当做zengl脚本来进行编译执行
		if(full_length > 3 && S_ISREG(filestatus.st_mode) && (strncmp(full_path + (full_length - 3), ".zl", 3) == 0)) {
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
			my_data.cookie_memblock.ptr = ZL_EXP_NULL;
			my_data.cookie_memblock.index = 0;
			my_data.my_parser_data = parser_data;
			my_data.response_body.str = PTR_NULL;
			my_data.response_body.count = my_data.response_body.size = 0;
			my_data.response_header.str = PTR_NULL;
			my_data.response_header.count = my_data.response_header.size = 0;
			my_data.resource_list.list = PTR_NULL;
			my_data.resource_list.count = my_data.resource_list.size = 0;
			my_data.pointer_list.list = NULL;
			my_data.pointer_list.count = my_data.pointer_list.size = 0;
			my_data.debug_info = PTR_NULL;
			ZL_EXP_VOID * VM;
			VM = zenglApi_Open();
			ZENGL_EXPORT_VM_MAIN_ARG_FLAGS flags = ZL_EXP_CP_AF_IN_DEBUG_MODE;
			// 只有在调试模式下，并且在配置文件中，设置了zl_debug_log时，才设置run_info处理函数，该函数会将zengl脚本的虚拟汇编指令写入到指定的日志文件
			if(config_debug_mode && (zl_debug_log != NULL)) {
				my_data.zl_debug_log = fopen(zl_debug_log,"w+");
				if(my_data.zl_debug_log != NULL) {
					zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_INFO,main_userdef_run_info);
					/**
					 * 如果不需要输出调试日志，就不用设置ZL_EXP_CP_AF_OUTPUT_DEBUG_INFO输出调试信息的标志，输出调试信息会占用很多执行时间
					 * 即便没有设置ZL_EXP_VFLAG_HANDLE_RUN_INFO处理句柄，也就是没有写入zl_debug_log日志文件，也会占用不少执行时间
					 */
					flags |= ZL_EXP_CP_AF_OUTPUT_DEBUG_INFO;
				}
			}
			zenglApi_SetFlags(VM, flags);
			// 设置在zengl脚本中使用print指令时，会执行的回调函数
			zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_PRINT,main_userdef_run_print);
			// 设置zengl脚本的模块初始化函数
			zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_MODULE_INIT,main_userdef_module_init);
			// 设置my_data额外数据
			zenglApi_SetExtraData(VM, "my_data", &my_data);
			pthread_mutex_lock(&(my_thread_lock.lock));

			DEBUG_INFO debug_info;
			// 如果开启了远程调试功能，则初始化远程调试相关的结构体，并通过zenglAPI设置中断回调函数等
			if(config_remote_debug_enable) {
				debug_init(&debug_info);
				my_data.debug_info = &debug_info;
				zenglApi_DebugSetBreakHandle(VM, debug_break, debug_conditionError,ZL_EXP_TRUE,ZL_EXP_FALSE); //设置调试API
			}

			char cache_path[80];
			ZL_EXP_BOOL is_reuse_cache;
			// 如果开启了zengl脚本的编译缓存，则尝试重利用缓存数据
			if(config_zengl_cache_enable) {
				// 根据脚本文件名得到缓存文件的路径信息
				main_get_zengl_cache_path(cache_path, sizeof(cache_path), full_path);
				// 尝试重利用缓存数据
				main_try_to_reuse_zengl_cache(VM, cache_path, full_path, &is_reuse_cache);
			}
			if(zenglApi_Run(VM, full_path) == -1) //编译执行zengl脚本
			{
				// 如果执行失败，则显示错误信息，并抛出500内部错误给客户端
				fatal_error_set_error_string(zenglApi_GetErrorString(VM));
				if(fatal_error_callback_exec(VM, full_path, fatal_error_get_error_string()) == -1) {
					write_to_server_log_pipe(WRITE_TO_PIPE_, "zengl run fatal error callback of <%s> failed: %s\n",
							full_path, zenglApi_GetErrorString(VM));
				}
				else {
					write_to_server_log_pipe(WRITE_TO_PIPE_, "zengl run <%s> failed: %s\n",
							full_path, fatal_error_get_error_string());
				}
				client_socket_list_append_send_data(socket_list, lst_idx, "HTTP/1.1 500 Internal Server Error\r\n", 36);
				client_socket_list_append_send_data(socket_list, lst_idx, "Content-Type: text/html\r\n", 25);
				dynamic_string_append(&my_data.response_body, "500 Internal Server Error", 25, 200);
				status_code = 500;
			}
			else {
				// 如果开启了编译缓存，那么在没有重利用缓存数据时(例如缓存文件不存在，或者原脚本内容发生的改变等)，就生成新的缓存数据，并将其写入缓存文件中
				if(config_zengl_cache_enable && !is_reuse_cache)
					main_write_zengl_cache_to_file(VM, cache_path);
				if(!(my_data.response_header.count > 0 && strncmp(my_data.response_header.str, "HTTP/", 5) == 0)) {
					client_socket_list_append_send_data(socket_list, lst_idx, "HTTP/1.1 200 OK\r\n", 17);
					if(my_data.response_header.count == 0 ||
					  !strcasestr(my_data.response_header.str, "content-type:")) { // 没有定义过Content-Type响应头，则默认输出text/html
						client_socket_list_append_send_data(socket_list, lst_idx, "Content-Type: text/html\r\n", 25);
					}
				}
				else
					is_custom_status_code = ZL_EXP_TRUE; // 用户自定义了http状态码
			}

			fata_error_free_all_ptrs();

			// 如果开启了远程调试，则在关闭zengl虚拟机之前，需要通过debug_exit函数来关闭掉打开的调试套接字，以及释放掉分配过的动态字符串资源
			if(config_remote_debug_enable)
				debug_exit(VM, &debug_info);

			pthread_mutex_unlock(&(my_thread_lock.lock));
			// 移除所有的资源指针，并清理这些资源指针所占用的内存
			resource_list_remove_all_resources(VM, &(my_data.resource_list));
			// 移除所有的数据指针，并清理这些数据指针所占用的内存
			pointer_list_remove_all_ptrs(VM, &(my_data.pointer_list));
#ifdef USE_MAGICK
			// 如果开启了magick模块，则通过export_magick_terminus将相关的资源释放掉
			export_magick_terminus();
#endif
#ifdef USE_CURL
			// 如果开启了curl模块，则通过export_curl_global_cleanup将相关的全局资源释放掉
			export_curl_global_cleanup();
#endif
			// 关闭zengl虚拟机及zl_debug_log日志文件
			zenglApi_Close(VM);
			if(my_data.zl_debug_log != NULL) {
				fclose(my_data.zl_debug_log);
			}
			// 如果在zengl脚本中设置了响应头，则先将响应头输出给客户端
			if(my_data.response_header.count > 0) {
				client_socket_list_append_send_data(socket_list, lst_idx, my_data.response_header.str, my_data.response_header.count);
				// 输出完响应头后，将response_header动态字符串释放掉
				dynamic_string_free(&my_data.response_header);
			}
			// zengl脚本中的输出数据会写入到my_data里的response_body动态字符串中，
			// 因此，将response_body动态字符串的长度作为Content-Length，并将其作为响应内容，反馈给客户端
			char response_content_length[20];
			content_length = my_data.response_body.count;
			sprintf(response_content_length, "%d", content_length);
			client_socket_list_append_send_data(socket_list, lst_idx, "Content-Length: ", 16);
			client_socket_list_append_send_data(socket_list, lst_idx, response_content_length, strlen(response_content_length));
			client_socket_list_append_send_data(socket_list, lst_idx, "\r\nConnection: Closed\r\nServer: zenglServer\r\n\r\n", 45);
			client_socket_list_append_send_data(socket_list, lst_idx, my_data.response_body.str, my_data.response_body.count);
			// 释放response_body动态字符串
			dynamic_string_free(&my_data.response_body);
			doc_fd = -2; // 将其设置为-2，就可以跳过后面的静态内容输出过程，因为上面已经输出过动态脚本的内容了
		}
		else {
			// 如果不是zengl脚本，则直接打开full_path对应的文件，如果打不开，说明文件不存在或者没有权限打开文件
			// 如果文件不存在则打开web根目录中的404.html文件，并设置404状态码，如果是没有权限打开文件，
			// 则设置403状态码，并设置错误的默认输出内容
			doc_fd = open(full_path, O_RDONLY);
			if(doc_fd == -1) {
				// 如果open函数返回-1，则说明无法打开文件，就设置403或404状态码，并将打开文件失败的具体原因记录到日志中
				if(config_verbose)
					write_to_server_log_pipe(WRITE_TO_PIPE, "open file failed: [%d] %s\n", errno, strerror(errno));
				else
					write_to_server_log_pipe(WRITE_TO_PIPE_, "open file failed: [%d] %s | ", errno, strerror(errno));
				// 如果是没有权限打开文件，则设置403状态码，并设置403错误的默认输出内容
				if(errno == EACCES) {
					status_code = 403;
					default_output_html = DEFAULT_OUTPUT_HTML_403;
				}
				else {
					full_length = root_length;
					full_length += main_full_path_append(full_path, full_length, FULL_PATH_SIZE, "/404.html");
					full_path[full_length] = '\0';
					stat(full_path, &filestatus);
					doc_fd = open(full_path, O_RDONLY);
					status_code = 404;
					// 如果web根目录中的404.html文件不存在或者无法打开，则设置404错误的默认输出内容
					if(doc_fd == -1)
						default_output_html = DEFAULT_OUTPUT_HTML_404;
				}
			}
		}
	}
	// 如果doc_fd大于0，则直接输出相关的静态文件的内容
	if(doc_fd > 0 || S_ISDIR(filestatus.st_mode)) {
		client_socket_list_append_send_data(socket_list, lst_idx, "HTTP/1.1 ", 9);
		ZL_EXP_BOOL is_reg_file = ZL_EXP_TRUE;
		// 非常规文件，直接返回403禁止访问
		if(!S_ISREG(filestatus.st_mode)) {
			status_code = 403;
			default_output_html = DEFAULT_OUTPUT_HTML_403;
			is_reg_file = ZL_EXP_FALSE;
			if(config_verbose)
				write_to_server_log_pipe(WRITE_TO_PIPE, "directory have no index.html, directory are not allowed directly access\n");
			else
				write_to_server_log_pipe(WRITE_TO_PIPE_, "directory have no index.html, directory are not allowed directly access | ");
		}
		else
			main_process_if_modified_since(parser_data->request_header.str, parser_data->request_header.count, &filestatus, socket_list, lst_idx, &status_code);
		switch(status_code){
		case 403:
			client_socket_list_append_send_data(socket_list, lst_idx, "403 Forbidden\r\n", 15);
			break;
		case 404:
			client_socket_list_append_send_data(socket_list, lst_idx, "404 Not Found\r\n", 15);
			break;
		case 200:
			client_socket_list_append_send_data(socket_list, lst_idx, "200 OK\r\n", 8);
			client_socket_list_append_send_data(socket_list, lst_idx, "Cache-Control: public, max-age=600\r\n", 36);
			break;
		case 304:
			client_socket_list_append_send_data(socket_list, lst_idx, "304 Not Modified\r\n", 18);
			client_socket_list_append_send_data(socket_list, lst_idx, "Cache-Control: public, max-age=600\r\n", 36);
			break;
		}
		char doc_fd_content_length[20] = {0};
		if(is_reg_file && status_code != 304) { // 获取常规文件的内容长度，并根据文件名后缀，在响应头中输出文件类型
			content_length = (int)lseek(doc_fd, 0, SEEK_END);
			lseek(doc_fd, 0, SEEK_SET);
			if(main_output_content_type(full_path, socket_list, lst_idx) && (status_code == 200)) {
				main_output_last_modified(&filestatus, socket_list, lst_idx);
			}
		}
		else if(default_output_html != NULL) { // 设置默认输出内容的内容类型和内容长度
			content_length = strlen(default_output_html);
			main_output_content_type("default_output.html", socket_list, lst_idx);
		}
		else
			content_length = 0;
		sprintf(doc_fd_content_length, "%d", content_length);
		client_socket_list_append_send_data(socket_list, lst_idx, "Content-Length: ", 16);
		client_socket_list_append_send_data(socket_list, lst_idx, doc_fd_content_length, strlen(doc_fd_content_length));
		client_socket_list_append_send_data(socket_list, lst_idx, "\r\nConnection: Closed\r\nServer: zenglServer\r\n\r\n", 45);
		if(is_reg_file && status_code != 304) { // 输出常规文件的内容
			char buffer[1025];
			int data_length;
			while((data_length = read(doc_fd, buffer, sizeof(buffer))) > 0){
				client_socket_list_append_send_data(socket_list, lst_idx, buffer, data_length);
			}
		}
		if(doc_fd > 0) {
			close(doc_fd);
		}
	}
	// 如果连404.html也不存在的话，则直接反馈404状态信息
	else if((status_code == 404 || status_code == 403) && doc_fd == -1) {
		if(status_code == 404)
			client_socket_list_append_send_data(socket_list, lst_idx, "HTTP/1.1 404 Not Found\r\n", 24);
		else
			client_socket_list_append_send_data(socket_list, lst_idx, "HTTP/1.1 403 Forbidden\r\n", 24);
		if(default_output_html != NULL) { // 设置默认输出内容的内容类型和内容长度
			char default_length[20] = {0};
			main_output_content_type("default_output.html", socket_list, lst_idx);
			content_length = strlen(default_output_html);
			client_socket_list_append_send_data(socket_list, lst_idx, "Content-Length: ", 16);
			sprintf(default_length, "%d", content_length);
			client_socket_list_append_send_data(socket_list, lst_idx, default_length, strlen(default_length));
		}
		else
			client_socket_list_append_send_data(socket_list, lst_idx, "Content-Length: 0", 17);
		client_socket_list_append_send_data(socket_list, lst_idx, "\r\nConnection: Closed\r\nServer: zenglServer\r\n\r\n", 45);
	}
	// 如果403或404错误设置了默认输出内容的话，则将默认输出内容返回给客户端
	if(default_output_html != NULL) {
		client_socket_list_append_send_data(socket_list, lst_idx, default_output_html, strlen(default_output_html));
	}
	// 在日志中输出响应状态码和响应主体数据的长度
	if(is_custom_status_code)
		write_to_server_log_pipe(WRITE_TO_PIPE_, "status: customize, ");
	else
		write_to_server_log_pipe(WRITE_TO_PIPE_, "status: %d, ", status_code);
	if(config_verbose)
		write_to_server_log_pipe(WRITE_TO_PIPE, "content length: %d\n", content_length);
	else
		write_to_server_log_pipe(WRITE_TO_PIPE_, "length: %d | ", content_length);
	// 通过client_socket_list_log_response_header函数，在日志中记录完整的响应头信息
	client_socket_list_log_response_header(socket_list, lst_idx);
	return lst_idx;
}

/**
 * 当使用了-r选项来运行脚本时，会在主进程中，以命令行的方式直接执行脚本
 * 例如: ./zenglServer -r "/v0_1_1/test.zl?a=12&b=456"
 * 就是直接在命令行中运行test.zl脚本，并向脚本中传递a参数和b参数
 * 命令行方式运行时，也需要提供完整的相对路径，以及类似http的请求参数
 */
static int main_run_cmd(char * run_cmd)
{
	time_t rawtime;
	struct tm * timeinfo;
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	char * current_time = asctime (timeinfo);
	write_to_server_log_pipe(WRITE_TO_PIPE_, "%d/%02d/%02d %02d:%02d:%02d pid:%d \n ",
							(timeinfo->tm_year + 1900), (timeinfo->tm_mon + 1), (timeinfo->tm_mday),
							timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec,
							getpid());
	write_to_server_log_pipe(WRITE_TO_PIPE_, "\n\n");
	MY_PARSER_DATA my_parser_data = {0};
	MY_PARSER_DATA * parser_data = &my_parser_data;
	char str_null[1];
	str_null[0] = STR_NULL;
	dynamic_string_append(&parser_data->request_url, run_cmd, (int)strlen(run_cmd), REQUEST_URL_STR_SIZE);
	dynamic_string_append(&parser_data->request_url, str_null, 1, REQUEST_URL_STR_SIZE);
	write_to_server_log_pipe(WRITE_TO_PIPE_, "url: %s\n", parser_data->request_url.str);
	// 通过http_parser_parse_url来解析url资源路径(包含查询字符串)，该函数会将路径信息和查询字符串信息给解析出来，并将解析结果存储到url_parser中
	if(http_parser_parse_url(parser_data->request_url.str,
			strlen(parser_data->request_url.str), 0,
			&(parser_data->url_parser))) {
		printf("**** failed to parse URL %s ****\n", parser_data->request_url.str);
		write_to_server_log_pipe(WRITE_TO_PIPE_, "**** failed to parse URL %s ****\n", parser_data->request_url.str);
		return -1;
	}

	char url_path[URL_PATH_SIZE];
	char decode_url_path[URL_PATH_SIZE];
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
	// 对客户端传递过来的url路径信息进行url解码，这样在linux中就可以访问utf8编码的中文路径了
	gl_request_url_decode(decode_url_path, url_path, strlen(url_path));
	write_to_server_log_pipe(WRITE_TO_PIPE_, "url_path: %s\n", decode_url_path);

	// full_path中存储了需要访问的目标文件的完整路径信息
	char full_path[FULL_PATH_SIZE];
	struct stat filestatus = {0};
	// 下面会根据webroot根目录，和url_path来构建full_path完整路径
	int full_length = main_full_path_append(full_path, 0, FULL_PATH_SIZE, webroot);
	int root_length = full_length;
	full_length += main_full_path_append(full_path, full_length, FULL_PATH_SIZE, decode_url_path);
	full_path[full_length] = '\0';
	int retval_stat = stat(full_path, &filestatus);

	// 如果文件不存在或者没有权限打开文件，则stat函数会返回-1，并将错误码记录到errno中
	if(retval_stat == -1) {
		printf("stat file '%s' failed: [%d] %s\n", full_path, errno, strerror(errno));
		write_to_server_log_pipe(WRITE_TO_PIPE_, "stat file '%s' failed: [%d] %s\n", full_path, errno, strerror(errno));
		return -1;
	}
	else if(S_ISDIR(filestatus.st_mode)) {
		const char * error_str = "it's a directory, can't be run!";
		printf("%s\n", error_str);
		write_to_server_log_pipe(WRITE_TO_PIPE_, "%s\n", error_str);
		return -1;
	}
	else {
		write_to_server_log_pipe(WRITE_TO_PIPE_, "full_path: %s\n", full_path);
		// 如果要访问的文件是以.zl结尾的，就将该文件当做zengl脚本来进行编译执行
		if(full_length > 3 && S_ISREG(filestatus.st_mode) && (strncmp(full_path + (full_length - 3), ".zl", 3) == 0)) {
			// my_data是传递给zengl脚本的额外数据，里面包含了客户端套接字等可能需要用到的信息
			MAIN_DATA my_data = {0};
			my_data.full_path = full_path;
			my_data.client_socket_fd = MAIN_RUN_IN_CMD_FD;
			my_data.my_parser_data = parser_data;
			ZL_EXP_VOID * VM;
			VM = zenglApi_Open();
			ZENGL_EXPORT_VM_MAIN_ARG_FLAGS flags = ZL_EXP_CP_AF_IN_DEBUG_MODE;
			// 只有在调试模式下，并且在配置文件中，设置了zl_debug_log时，才设置run_info处理函数，该函数会将zengl脚本的虚拟汇编指令写入到指定的日志文件
			if(config_debug_mode && (zl_debug_log != NULL)) {
				my_data.zl_debug_log = fopen(zl_debug_log,"w+");
				if(my_data.zl_debug_log != NULL) {
					zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_INFO,main_userdef_run_info);
					/**
					 * 如果不需要输出调试日志，就不用设置ZL_EXP_CP_AF_OUTPUT_DEBUG_INFO输出调试信息的标志，输出调试信息会占用很多执行时间
					 * 即便没有设置ZL_EXP_VFLAG_HANDLE_RUN_INFO处理句柄，也就是没有写入zl_debug_log日志文件，也会占用不少执行时间
					 */
					flags |= ZL_EXP_CP_AF_OUTPUT_DEBUG_INFO;
				}
			}
			zenglApi_SetFlags(VM, flags);
			// 设置在zengl脚本中使用print指令时，会执行的回调函数
			zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_RUN_PRINT,main_userdef_run_print);
			// 设置zengl脚本的模块初始化函数
			zenglApi_SetHandle(VM,ZL_EXP_VFLAG_HANDLE_MODULE_INIT,main_userdef_module_init);
			// 设置my_data额外数据
			zenglApi_SetExtraData(VM, "my_data", &my_data);

			DEBUG_INFO debug_info;
			// 如果开启了远程调试功能，则初始化远程调试相关的结构体，并通过zenglAPI设置中断回调函数等
			if(config_remote_debug_enable) {
				debug_init(&debug_info);
				my_data.debug_info = &debug_info;
				zenglApi_DebugSetBreakHandle(VM, debug_break, debug_conditionError,ZL_EXP_TRUE,ZL_EXP_FALSE); //设置调试API
			}

			char cache_path[80];
			ZL_EXP_BOOL is_reuse_cache;
			// 如果开启了zengl脚本的编译缓存，则尝试重利用缓存数据
			if(config_zengl_cache_enable) {
				// 根据脚本文件名得到缓存文件的路径信息
				main_get_zengl_cache_path(cache_path, sizeof(cache_path), full_path);
				// 尝试重利用缓存数据
				main_try_to_reuse_zengl_cache(VM, cache_path, full_path, &is_reuse_cache);
			}
			if(zenglApi_Run(VM, full_path) == -1) //编译执行zengl脚本
			{
				// 如果执行失败，则显示错误信息，并抛出500内部错误给客户端
				fatal_error_set_error_string(zenglApi_GetErrorString(VM));
				if(fatal_error_callback_exec(VM, full_path, fatal_error_get_error_string()) == -1) {
					write_to_server_log_pipe(WRITE_TO_PIPE_, "zengl run fatal error callback of <%s> failed: %s\n",
							full_path, zenglApi_GetErrorString(VM));
					printf("zengl run fatal error callback of <%s> failed: %s\n",full_path, zenglApi_GetErrorString(VM));
				}
				else {
					write_to_server_log_pipe(WRITE_TO_PIPE_, "zengl run <%s> failed: %s\n",
							full_path, fatal_error_get_error_string());
					if(fatal_error_get_default_cmd_action()) {
						printf("zengl run <%s> failed: %s\n",full_path, fatal_error_get_error_string());
					}
				}
			}
			else {
				// 如果开启了编译缓存，那么在没有重利用缓存数据时(例如缓存文件不存在，或者原脚本内容发生的改变等)，就生成新的缓存数据，并将其写入缓存文件中
				if(config_zengl_cache_enable && !is_reuse_cache)
					main_write_zengl_cache_to_file(VM, cache_path);
			}

			fata_error_free_all_ptrs();

			// 如果开启了远程调试，则在关闭zengl虚拟机之前，需要通过debug_exit函数来关闭掉打开的调试套接字，以及释放掉分配过的动态字符串资源
			if(config_remote_debug_enable)
				debug_exit(VM, &debug_info);

			// 移除所有的资源指针，并清理这些资源指针所占用的内存
			resource_list_remove_all_resources(VM, &(my_data.resource_list));
			// 移除所有的数据指针，并清理这些数据指针所占用的内存
			pointer_list_remove_all_ptrs(VM, &(my_data.pointer_list));
			#ifdef USE_MAGICK
				// 如果开启了magick模块，则通过export_magick_terminus将相关的资源释放掉
				export_magick_terminus();
			#endif
			#ifdef USE_CURL
				// 如果开启了curl模块，则通过export_curl_global_cleanup将相关的全局资源释放掉
				export_curl_global_cleanup();
			#endif
			// 关闭zengl虚拟机及zl_debug_log日志文件
			zenglApi_Close(VM);
			if(my_data.zl_debug_log != NULL) {
				fclose(my_data.zl_debug_log);
			}

			// 如果在zengl脚本中设置了响应头，则先将响应头输出给客户端
			if(my_data.response_header.count > 0) {
				dynamic_string_append(&my_data.response_header, str_null, 1, RESPONSE_HEADER_STR_SIZE);
				printf("%s", my_data.response_header.str);
				// 输出完响应头后，将response_header动态字符串释放掉
				dynamic_string_free(&my_data.response_header);
			}
			// 如果有响应主体数据，则将响应主体数据输出到终端
			if(my_data.response_body.count > 0) {
				dynamic_string_append(&my_data.response_body, str_null, 1, RESPONSE_BODY_STR_SIZE);
				printf("%s", my_data.response_body.str);
				// 释放response_body动态字符串
				dynamic_string_free(&my_data.response_body);
			}
			return 0;
		}
		else { // 只有以.zl结尾的常规文件，才会被当成zengl脚本来执行，其他文件在命令行下会直接报错，并返回
			const char * error_str = "it's not a normal zengl script file, can't be run!";
			printf("%s\n", error_str);
			write_to_server_log_pipe(WRITE_TO_PIPE_, "%s\n", error_str);
			return -1;
		}
	}
}
