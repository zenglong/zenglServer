/*
 * module_request.c
 *
 *  Created on: 2017-6-15
 *      Author: zengl
 */

#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#include "main.h"
#include "module_request.h"
#include "multipart_parser.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define CONVERT_HEADER_FIELD_LEN 11

// 枚举值用于判断当前读取到的multipart头信息是Content-Disposition头信息
// 还是Content-Type头信息
enum _my_multipart_header_status {
	MY_MULTIPART_HEADER_STATUS_NONE = 0,
	MY_MULTIPART_HEADER_STATUS_DISPOSITION = 1,
	MY_MULTIPART_HEADER_STATUS_CONTENT_TYPE = 2
};

// 对multipart头信息对应的值进行名值对解析时，需要用到的状态机
enum _my_parser_status {
	m_p_status_start = 1,
	m_p_status_key_start,
	m_p_status_key_end,
	m_p_status_before_value,
	m_p_status_value_start,
	m_p_status_value_escape,
	m_p_status_value_end,
	m_p_status_end
};

// 对请求头中的Cookie名值对进行解析时，需要用到的状态机
enum _my_cookie_parser_status {
	m_cookie_p_status_start = 1,
	m_cookie_p_status_key_start,
	m_cookie_p_status_key_end,
	m_cookie_p_status_value_start
};

// 从multipart中解析的各种数据，例如，通过Content-Disposition头信息可以解析到name和filename
// 从Content-Type头信息中可以解析到content_type内容类型
// content字段会指向每个part的具体数据内容
struct _my_multipart {
	char * name;
	char * filename;
	char * content_type;
	char * content;
	int name_length;
	int filename_length;
	int content_type_length;
	int content_length;
};

// 解析到的name，filename，content_type，content等，最终会通过zenglApi_AllocMem
// 或者zenglApi_ReAllocMem为其分配相应堆空间，以方便进行解码和zenglApi_SetMemBlockByHashKey设置内存块数据的操作
struct _my_multipart_alloc {
	char * name;
	char * filename;
	char * content_type;
	char * content;
};

typedef enum _my_multipart_header_status my_multipart_header_status;
typedef enum _my_parser_status my_parser_status;
typedef enum _my_cookie_parser_status my_cookie_parser_status;
typedef struct _my_multipart my_multipart;
typedef struct _my_multipart_alloc my_multipart_alloc;

// 使用第三方multipart_parser库解析multipart数据时，可以通过multipart_parser的
// data字段向其传递一个额外的自定义数据，下面的my_multipart_data结构体就是我们需要
// 传递的自定义数据，里面有VM_ARG(zengl虚拟机指针)，需要设置的memblock内存块，part和part_alloc(存储解析到的数据)等
struct _my_multipart_data {
	my_multipart_header_status status;
	my_multipart part;
	my_multipart_alloc part_alloc;
	ZL_EXP_VOID * VM_ARG;
	ZENGL_EXPORT_MEMBLOCK * memblock;
	MAIN_DATA * my_data;
};

typedef struct _my_multipart_data my_multipart_data;

static char * url_decode(char * dest, char * src, int src_len);

/**
 * 将request模块中的静态函数url_decode转为全局C函数，方便其他C模块直接调用
 */
char * gl_request_url_decode(char * dest, char * src, int src_len)
{
	return url_decode(dest, src, src_len);
}

/**
 * 对src字符串参数进行url解码，并存储到dest目标字符串中
 * 例如：%E7%A8%8B%E5%BA%8F%E5%91%98 解码后对应的就是UTF8编码的字符串“程序员”
 * 通过将%E7转为0xE7的字节，%A8转为0xA8的字节，从而实现解码
 */
static char * url_decode(char * dest, char * src, int src_len)
{
	//int src_len = strlen(src);
	int cp_start = 0, cp_count = 0, dest_len = 0, i = 0;
	char e_char[] = "00";
	for(;i < src_len;i++)
	{
		switch(src[i])
		{
		case '%':
			if(src[i+1] == '\0')
				continue;
			if(isxdigit(src[i+1]) && isxdigit(src[i+2]))
			{
				e_char[0] = src[i+1];
				e_char[1] = src[i+2];
				long int x = strtol(e_char, NULL, 16);
				cp_count = i - cp_start;
				if(cp_count > 0) {
					memcpy((dest + dest_len), &src[cp_start], cp_count);
					dest_len += cp_count;
				}
				dest[dest_len++] = x;
				i += 2;
				cp_start = i + 1;
			}
			break;
		case '+':
			cp_count = i - cp_start;
			if(cp_count > 0) {
				memcpy((dest + dest_len), &src[cp_start], cp_count);
				dest_len += cp_count;
			}
			dest[dest_len++] = ' ';
			cp_start = i + 1;
			break;
		}
	}
	cp_count = i - cp_start;
	if(cp_count > 0) {
		memcpy((dest + dest_len), &src[cp_start], cp_count);
		dest_len += cp_count;
	}
	dest[dest_len] = '\0';
	return dest;
}

/**
 * 对str字符串中的转义字符进行解析
 * 例如：ti\"tl\"e解析后就是ti"tl"e
 * 目前暂时只针对双引号，单引号和斜杠进行转义字符的解析
 */
static char * str_unescape(char * str)
{
	int str_len = strlen(str);
	char x;
	for(int i = 0; i < str_len;i++)
	{
		switch(str[i])
		{
		case '\\':
			x = str[i+1];
			if(x == '\0')
				return str;
			if(x == '"' || x == '\'' || x == '\\')
			{
				memmove(&str[i+1], &str[i+2], strlen(&str[i+2])+1);
				str_len -= 1;
				str[i] = x;
			}
			break;
		}
	}
	return str;
}

/**
 * 对url编码的字符串进行解析，并将解析出来的名值对信息存储到memblock对应的内存块(数组)中
 * 例如：title=hello&description=world&content=test&sb=Submit 的解析过程相当于执行下列语句：
 * memblock['title'] = 'hello';
 * memblock['description'] = 'world';
 * memblock['content'] = 'test';
 * memblock['sb'] = 'Submit';
 * GET和POST请求都可以使用该函数来解析url编码的字符串
 */
static void parse_urlencoded_str_to_memblock(ZL_EXP_VOID * VM_ARG, ZL_EXP_CHAR * q, ZL_EXP_INT q_len, ZENGL_EXPORT_MEMBLOCK * memblock)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	ZL_EXP_INT k = -1;
	ZL_EXP_INT v = -1;
	ZL_EXP_CHAR * decode_k = ZL_EXP_NULL;
	ZL_EXP_CHAR * decode_v = ZL_EXP_NULL;
	for(ZL_EXP_INT i = 0; i <= q_len; i++) {
		if(k == -1 && q[i] != '=' && q[i] != '&') {
			k = i;
		}
		switch(q[i]) {
		case '=':
			v = i + 1;
			break;
		case '&':
		case '#':
		case STR_NULL:
			if(k >= 0 && v > 0) {
				ZL_EXP_CHAR prev_v_char = q[v - 1];
				ZL_EXP_CHAR current_char = q[i];
				q[i] = q[v - 1] = STR_NULL;
				if(decode_k == ZL_EXP_NULL)
					decode_k = zenglApi_AllocMem(VM_ARG, (strlen(&q[k]) + 1));
				else
					decode_k = zenglApi_ReAllocMem(VM_ARG, decode_k, (strlen(&q[k]) + 1));
				//strcpy(decode_k, &q[k]);
				if(decode_v == ZL_EXP_NULL)
					decode_v = zenglApi_AllocMem(VM_ARG, (strlen(&q[v]) + 1));
				else
					decode_v = zenglApi_ReAllocMem(VM_ARG, decode_v, (strlen(&q[v]) + 1));
				//strcpy(decode_v, &q[v]);
				arg.type = ZL_EXP_FAT_STR;
				arg.val.str = url_decode(decode_v, &q[v], strlen(&q[v]));
				zenglApi_SetMemBlockByHashKey(VM_ARG, memblock, url_decode(decode_k, &q[k], strlen(&q[k])), &arg);
				q[v - 1] = prev_v_char;
				if(current_char != STR_NULL)
					q[i] = current_char;
				k = v = -1;
			}
			else {
				k = v = -1;
			}
			break;
		}
	}
	if(decode_k != ZL_EXP_NULL)
		zenglApi_FreeMem(VM_ARG, decode_k);
	if(decode_v != ZL_EXP_NULL)
		zenglApi_FreeMem(VM_ARG, decode_v);
}

/**
 * 将请求头中的key转为指定的格式，例如：content-type，content-Type，CONTENT-TYPE等请求头字段key都会被转为Content-Type，
 * cookie，COOKIE，cookiE等也都会被转为Cookie，这样转为统一的格式后，就始终可以通过Content-Type的key来获取内容类型，以及
 * 使用Cookie的key来获取cookie的值等，像cloudflare之类的cdn可能会将客户端传递过来的请求头key转为小写，所以需要将一些常规的key
 * 通过下面的函数转为指定的格式，方便在模块函数中以及在脚本中使用统一的key来访问请求头中的数据。
 *
 * 这里只对比较常见的key，例如content-type，content-length等进行了转换，
 * 其他的请求头key需要自行在脚本中进行处理(例如可以通过bltToLower模块函数生成全是小写的请求头key等)。
 */
static ZL_EXP_CHAR *  get_final_header_field(ZL_EXP_CHAR * field)
{
	ZL_EXP_CHAR * from[CONVERT_HEADER_FIELD_LEN] = {
		"host", "user-agent", "accept-language", "accept-encoding", "content-type", "content-length",
		"origin", "connection", "referer", "accept", "cookie"
	};
	ZL_EXP_CHAR * to[CONVERT_HEADER_FIELD_LEN] = {
		"Host", "User-Agent", "Accept-Language", "Accept-Encoding", "Content-Type", "Content-Length",
		"Origin", "Connection", "Referer", "Accept", "Cookie"
	};
	ZL_EXP_CHAR * result = field;
	int field_len = strlen(field);
	for(int i = 0; i < CONVERT_HEADER_FIELD_LEN; i++) {
		if(strlen(from[i]) == field_len) {
			if(strncasecmp(from[i], field, field_len) == 0) {
				result = to[i];
				break;
			}
		}
	}
	return result;
}

/**
 * 将请求头中的field和value字符串组成名值对，存储到哈希数组中
 * 这里将存储过程写入到单独的get_headers的静态函数里，这样，rqtGetHeaders模块函数以及
 * rqtGetBodyAsArray模块函数的内部就可以直接共用这个函数来获取头部信息了
 */
static void get_headers(ZL_EXP_VOID * VM_ARG, MAIN_DATA * my_data)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	MY_PARSER_DATA * my_parser_data = my_data->my_parser_data;

	// 如果没有创建过哈希数组，则创建哈希数组，并将请求头中所有的field与value构成的名值对，存储到哈希数组中
	if(my_data->headers_memblock.ptr == ZL_EXP_NULL) {
		if(zenglApi_CreateMemBlock(VM_ARG,&my_data->headers_memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
		zenglApi_AddMemBlockRefCount(VM_ARG,&my_data->headers_memblock,1); // 手动增加该内存块的引用计数值，使其不会在脚本函数返回时，被释放掉。
		// 所有的field和value字符串，都依次存储在request_header动态字符串中，通过'\0'字符串终止符分隔开
		if(my_parser_data->request_header.str != PTR_NULL && my_parser_data->request_header.count > 0) {
			ZL_EXP_CHAR * tmp = my_parser_data->request_header.str;
			ZL_EXP_CHAR * end = my_parser_data->request_header.str + my_parser_data->request_header.count;
			do{
				ZL_EXP_CHAR * field = tmp;
				ZL_EXP_CHAR * value = field + strlen(field) + 1;
				if(field >= end || value >= end) {
					break;
				}
				arg.type = ZL_EXP_FAT_STR;
				arg.val.str = value;
				ZL_EXP_CHAR * final_field = get_final_header_field(field);
				zenglApi_SetMemBlockByHashKey(VM_ARG, &my_data->headers_memblock, final_field, &arg);
				tmp = value + strlen(value) + 1;
			}while(1);
		}
		return;
	}
	else {
		// 如果之前已经创建过哈希数组，就直接返回
		return;
	}
}

// 使用状态机，将multipart请求头中的名值对信息解析出来
// 例如：Content-Disposition: form-data; name="我的文件"; filename="splashimage.jpg"
// 下面的函数可以将name -> 我的文件，filename -> splashimage.jpg 这样的名值对信息给解析出来
// 第三方multipart_parser库只会将外层的名值对解析出来，上例中，multipart_parser库只会解析出
// Content-Disposition -> form-data; name="我的文件"; filename="splashimage.jpg"，
// 也就是将冒号左侧当成请求头的字段名，冒号右侧当成请求头的字段值，而请求头的字段值中name和filename这种更具体的名值对信息
// 就只有自己写状态机来解析了，所以有了下面的函数
static int parse_multipart_header_value(char * s, int s_len,
						char ** key, int * key_len,
						char ** value, int * value_len)
{
	char c;
	char * k = NULL, * v = NULL;
	int k_len = 0, v_len = 0;
	int i;
	my_parser_status status = m_p_status_start;
	for(i = 0;(i < s_len) && (status != m_p_status_end);i++) {
		c = s[i];
		switch(status){
		case m_p_status_start:
			if(c != ' ') {
				k = &s[i];
				status = m_p_status_key_start;
			}
			break;
		case m_p_status_key_start:
			if(c == '=') {
				k_len = i - ((int)(k - s));
				status = m_p_status_key_end;
			}
			else if(c == ';') {
				k_len = i - ((int)(k - s));
				status = m_p_status_end;
			}
			break;
		case m_p_status_key_end:
			if(c == '"')
				status = m_p_status_before_value;
			break;
		case m_p_status_before_value:
			if(c != '"') {
				v = &s[i];
				status = m_p_status_value_start;
			}
			break;
		case m_p_status_value_start:
			if(c == '\\') {
				status = m_p_status_value_escape;
			}
			else if(c == '"') {
				v_len = i - ((int)(v - s));
				status = m_p_status_value_end;
			}
			break;
		case m_p_status_value_escape:
			status = m_p_status_value_start;
			break;
		case m_p_status_value_end:
			if(c == ';')
				status = m_p_status_end;
			break;
		}
	}
	if(k != NULL) {
		if(k_len == 0)
			k_len = s_len - ((int)(k - s));
	}
	if(v != NULL) {
		if(v_len == 0)
			v_len = s_len - ((int)(v - s));
	}
	(*key) = k;
	(*key_len) = k_len;
	(*value) = v;
	(*value_len) = v_len;
	return i;
}

// multipart_parser库在解析到每个请求头的字段名时会调用的回调函数
// 对于请求头 Content-Disposition: form-data; name="我的文件"; filename="splashimage.jpg"
// 当解析到冒号左侧的Content-Disposition时，就会调用下面这个回调函数，并将Content-Disposition的字符串起始指针at和对应的字符串长度length传递进来
static int read_multipart_header_name(multipart_parser* p, const char *at, size_t length)
{
	my_multipart_data * data = (my_multipart_data *)p->data;
	if(strncasecmp(at, "Content-Disposition", length) == 0) {
		data->status = MY_MULTIPART_HEADER_STATUS_DISPOSITION;
	}
	else if(strncasecmp(at, "Content-Type", length) == 0) {
		data->status = MY_MULTIPART_HEADER_STATUS_CONTENT_TYPE;
	}
	return 0;
}

// multipart_parser库在解析到每个请求头的字段值时会调用的回调函数
// 对于请求头 Content-Disposition: form-data; name="我的文件"; filename="splashimage.jpg"
// 当解析到冒号右侧的form-data; name="我的文件"; filename="splashimage.jpg"时，就会调用下面这个函数，
// 并将整个右侧的字符串的起始指针at和长度length作为参数传递进来
static int read_multipart_header_value(multipart_parser* p, const char *at, size_t length)
{
	my_multipart_data * data = (my_multipart_data *)p->data;
	char *s,*k,*v;
	int s_len, k_len, v_len, count;
	switch(data->status) {
	case MY_MULTIPART_HEADER_STATUS_DISPOSITION:
		{
			s = (char *)at; s_len = length;
			count = parse_multipart_header_value(s, s_len, &k, &k_len, &v, &v_len);
			if(!(k != NULL && strncasecmp(k, "form-data", k_len) == 0)) {
				return 0;
			}
			s += count;
			s_len -= count;
			while(s_len > 0) {
				count = parse_multipart_header_value(s, s_len, &k, &k_len, &v, &v_len);
				if(k != NULL && k_len > 0) {
					if(strncasecmp(k, "name", k_len) == 0) {
						if(v != NULL && v_len > 0) {
							data->part.name = v;
							data->part.name_length = v_len;
						}
					}
					else if(strncasecmp(k, "filename", k_len) == 0) {
						if(v != NULL && v_len > 0) {
							data->part.filename = v;
							data->part.filename_length = v_len;
						}
					}
				}
				s += count;
				s_len -= count;
			}
		}
		break;
	case MY_MULTIPART_HEADER_STATUS_CONTENT_TYPE:
		{
			s = (char *)at; s_len = length;
			count = parse_multipart_header_value(s, s_len, &k, &k_len, &v, &v_len);
			if(k != NULL && k_len > 0) {
				data->part.content_type = k;
				data->part.content_type_length = k_len;
			}
		}
		break;
	}
	return 0;
}

// 当解析multipart中每个part的主体数据时，会调用的回调函数
// 该回调函数可能会被调用很多次，每次at指向一部分主体数据，length对应这部分的长度，
// 只有当后面的on_multipart_data_end回调函数被调用时，才能说明该part的主体数据被解析完
static int read_multipart_data(multipart_parser* p, const char *at, size_t length)
{
	my_multipart_data * data = (my_multipart_data *)p->data;
	if(data->part.content == NULL) {
		data->part.content = (char *)at; // 回调函数第一次调用时的at指针才是part主体数据的起始指针
		data->part.content_length = length; // 设置起始长度
	}
	else {
		data->part.content_length += length; // 之后在调用该函数时，只需将length加入到主体数据的长度中即可
	}
	return 0;
}

// 当part的头部信息被全部解析完时，会调用的回调函数
static int on_multipart_headers_complete(multipart_parser * p)
{
	//my_multipart_data * data = (my_multipart_data *)p->data;
	return 0;
}

// 通过zenglApi_AllocMem或者zenglApi_ReAllocMem为part中的name，filename等的值分配堆空间，以方便对其进行解码，以及设置内存块的操作
static char * multipart_alloc_zlmem(ZL_EXP_VOID * VM_ARG, char * s, int size)
{
	if(s == ZL_EXP_NULL)
		s = zenglApi_AllocMem(VM_ARG, size);
	else
		s = zenglApi_ReAllocMem(VM_ARG, s, size);
	return s;
}

// 将zenglApi分配的堆空间全部释放掉
static void multipart_free_all_zlmem(multipart_parser * p)
{
	my_multipart_data * data = (my_multipart_data *)p->data;
	ZL_EXP_VOID * VM_ARG = data->VM_ARG;
	if(data->part_alloc.name)
		zenglApi_FreeMem(VM_ARG, data->part_alloc.name);
	if(data->part_alloc.filename)
		zenglApi_FreeMem(VM_ARG, data->part_alloc.filename);
	if(data->part_alloc.content_type)
		zenglApi_FreeMem(VM_ARG, data->part_alloc.content_type);
	if(data->part_alloc.content)
		zenglApi_FreeMem(VM_ARG, data->part_alloc.content);
}

// 当part的主体数据被全部解析完时，会调用的回调函数
static int on_multipart_data_end(multipart_parser * p)
{
	my_multipart_data * data = (my_multipart_data *)p->data;
	ZL_EXP_VOID * VM_ARG = data->VM_ARG;
	ZENGL_EXPORT_MEMBLOCK * memblock = data->memblock;
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};

	if(data->part.name)
		write_to_server_log_pipe(WRITE_TO_PIPE, "name:%.*s\n", data->part.name_length, data->part.name);
	if(data->part.filename)
		write_to_server_log_pipe(WRITE_TO_PIPE, "filename:%.*s\n", data->part.filename_length, data->part.filename);
	if(data->part.content_type)
		write_to_server_log_pipe(WRITE_TO_PIPE, "content_type:%.*s\n", data->part.content_type_length, data->part.content_type);
	if(data->part.content) {
		write_to_server_log_pipe(WRITE_TO_PIPE, "content:");
		// 如果传的是图片或者文件之类的包含二进制的数据，则写入日志时，可能会在日志中报无效的字符
		write_to_server_log_pipe(WRITE_TO_PIPE, "%.*s\n\n\n", data->part.content_length, data->part.content);
	}

	if(data->part.filename) {
		if(data->part.name && data->part.content) {
			ZENGL_EXPORT_MEMBLOCK file_memblock = {0};
			if(zenglApi_CreateMemBlock(VM_ARG,&file_memblock,0) == -1) {
				zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
			}
			data->part_alloc.filename = multipart_alloc_zlmem(VM_ARG, data->part_alloc.filename, data->part.filename_length + 1);
			//strncpy(data->part_alloc.filename, data->part.filename, data->part.filename_length);
			//data->part_alloc.filename[data->part.filename_length] = '\0';
			url_decode(data->part_alloc.filename, data->part.filename, data->part.filename_length);
			str_unescape(data->part_alloc.filename);
			arg.type = ZL_EXP_FAT_STR;
			arg.val.str = data->part_alloc.filename;
			zenglApi_SetMemBlockByHashKey(VM_ARG, &file_memblock, "filename", &arg);
			if(data->part.content_type) {
				data->part_alloc.content_type = multipart_alloc_zlmem(VM_ARG, data->part_alloc.content_type, data->part.content_type_length + 1);
				strncpy(data->part_alloc.content_type, data->part.content_type, data->part.content_type_length);
				data->part_alloc.content_type[data->part.content_type_length] = '\0';
				arg.type = ZL_EXP_FAT_STR;
				arg.val.str = data->part_alloc.content_type;
				zenglApi_SetMemBlockByHashKey(VM_ARG, &file_memblock, "type", &arg);
			}
			arg.type = ZL_EXP_FAT_INT;
			arg.val.integer = (ZL_EXP_LONG)data->part.content;
			zenglApi_SetMemBlockByHashKey(VM_ARG, &file_memblock, "content_ptr", &arg);
			arg.type = ZL_EXP_FAT_INT;
			arg.val.integer = (ZL_EXP_LONG)data->part.content_length;
			zenglApi_SetMemBlockByHashKey(VM_ARG, &file_memblock, "length", &arg);

			// 将文件内容指针加入指针列表，使其成为有效的数据指针，其他需要使用指针的模块函数，就不会报无效的指针的错误了
			MAIN_DATA * my_data = data->my_data;
			int ret_set_ptr = pointer_list_set_member(&(my_data->pointer_list),
					data->part.content,
					data->part.content_length,
					NULL);
			if(ret_set_ptr != 0) {
				zenglApi_Exit(VM_ARG, "rqtGetBodyAsArray add pointer to pointer_list failed, pointer_list_set_member error code:%d", ret_set_ptr);
			}

			data->part_alloc.name = multipart_alloc_zlmem(VM_ARG, data->part_alloc.name, data->part.name_length + 1);
			//strncpy(data->part_alloc.name, data->part.name, data->part.name_length);
			//data->part_alloc.name[data->part.name_length] = '\0';
			url_decode(data->part_alloc.name, data->part.name, data->part.name_length);
			str_unescape(data->part_alloc.name);
			arg.type = ZL_EXP_FAT_MEMBLOCK;
			arg.val.memblock = file_memblock;
			zenglApi_SetMemBlockByHashKey(VM_ARG, memblock, data->part_alloc.name, &arg);
		}
	}
	else if(data->part.name) {
		if(data->part.content) {
			data->part_alloc.name = multipart_alloc_zlmem(VM_ARG, data->part_alloc.name, data->part.name_length + 1);
			//strncpy(data->part_alloc.name, data->part.name, data->part.name_length);
			//data->part_alloc.name[data->part.name_length] = '\0';
			url_decode(data->part_alloc.name, data->part.name, data->part.name_length);
			str_unescape(data->part_alloc.name);
			data->part_alloc.content = multipart_alloc_zlmem(VM_ARG, data->part_alloc.content, data->part.content_length + 1);
			strncpy(data->part_alloc.content, data->part.content, data->part.content_length);
			data->part_alloc.content[data->part.content_length] = '\0';
			arg.type = ZL_EXP_FAT_STR;
			arg.val.str = data->part_alloc.content;
			zenglApi_SetMemBlockByHashKey(VM_ARG, memblock, data->part_alloc.name, &arg);
		}
	}

	memset(&data->part, 0, sizeof(my_multipart));
	data->status = MY_MULTIPART_HEADER_STATUS_NONE;
	return 0;
}

/**
 * 使用状态机，将请求头中的Cookie名值对信息解析出来
 * 例如：Cookie: name=zengl; hobby=play game;
 * 下面的函数可以将name -> zengl和hobby -> play game这样的名值对信息给解析出来
 * 外部调用者，就可以通过解析出来的key(名)，value(值)，来设置哈希数组成员
 */
static int parse_cookie_header_value(char * s, int s_len,
						char ** key, int * key_len,
						char ** value, int * value_len)
{
	char c;
	char * k = NULL, * v = NULL;
	int k_len = 0, v_len = 0;
	int i;
	my_cookie_parser_status status = m_cookie_p_status_start;
	for(i = 0; i < s_len; i++) {
		c = s[i];
		if(c == ';') {
			i++;
			break;
		}
		switch(status){
		case m_cookie_p_status_start:
			if(c != ' ') {
				if(c == '=') {
					k_len = 0;
					status = m_cookie_p_status_key_end;
				}
				else {
					k = &s[i];
					k_len++;
					status = m_cookie_p_status_key_start;
				}
			}
			break;
		case m_cookie_p_status_key_start:
			if(c == '=')
				status = m_cookie_p_status_key_end;
			else
				k_len++;
			break;
		case m_cookie_p_status_key_end:
			v = &s[i];
			v_len++;
			status = m_cookie_p_status_value_start;
			break;
		case m_cookie_p_status_value_start:
			v_len++;
			break;
		}
	}
	// 对于请求头 Cookie: name=zengl; hobby=play game; hello worlds
	// 其中 hello worlds 等效于 =hello worlds ，也就是key是空的，因此，这种情况，需要将解析出来的key作为value进行返回，而key则设置为NULL
	if(status == m_cookie_p_status_key_start) {
		// 将k对应的指针赋值给v，长度赋值给v_len，再将k设置为NULL，k_len设置为0，也就是将解析出来的key设置为空，并将原始的key作为value返回
		v = k;
		v_len = k_len;
		k = NULL;
		k_len = 0;
	}
	(*key) = k;
	(*key_len) = k_len;
	(*value) = v;
	(*value_len) = v_len;
	return i;
}

/**
 * rqtGetHeaders模块函数，将请求头中的field和value字符串组成名值对，存储到哈希数组中，
 * 并将该数组作为结果返回，例如：
 * headers = rqtGetHeaders();
 * print 'user agent: ' + headers['User-Agent'] + '<br/>';
 * 该例子通过模块函数，获取到头部信息，并通过headers['User-Agent']来获取到浏览器的UA信息
 * 该模块函数只会在脚本第一次调用时，创建哈希数组，之后再调用该函数时，就会直接将之前创建的数组返回
 */
ZL_EXP_VOID module_request_GetHeaders(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	get_headers(VM_ARG, my_data);
	zenglApi_SetRetValAsMemBlock(VM_ARG,&my_data->headers_memblock);
}

/**
 * rqtGetBody模块函数，用于返回请求的body(主体数据)，如果没有请求主体数据，则返回空字符串，
 * 例如：
 * body = rqtGetBody();
 * if(body)
 * 		print 'request body: ' + body;
 * endif
 * 对于application/x-www-form-urlencoded类型(表单提交时Content-Type的默认类型)的post请求，该例子可能显示的结果为：
 * request body: title=hello&description=world&content=test&sb=Submit
 * 如果指定了第一个参数，那么模块函数会将body(主体数据)的总的字节数写入到该参数中，
 * 例如：rqtGetBody(&body_count) 会将字节数写入到body_count变量里，
 * 如果指定了第二个参数，那么模块函数还会将body(主体数据)的起始字节的指针值写入到该参数中，
 * 例如：rqtGetBody(&body_count, &body_ptr) 会将字节数写入到body_count变量，同时将指针值写入到body_ptr变量，
 * 获取到指针值后，就可以通过bltWriteFile模块函数将body的所有数据(包括上传文件的二进制数据)都写入到文件中，
 * 当然也可以通过其他模块函数，利用指针去做别的事情，
 * 第一个和第二个参数必须是address type(引用类型)
 */
ZL_EXP_VOID module_request_GetBody(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	MY_PARSER_DATA * my_parser_data = my_data->my_parser_data;

	if(argcount == 1 || argcount == 2) {
		zenglApi_GetFunArgInfo(VM_ARG,1,&arg);
		switch(arg.type){
		case ZL_EXP_FAT_ADDR:
		case ZL_EXP_FAT_ADDR_LOC:
		case ZL_EXP_FAT_ADDR_MEMBLK:
			break;
		default:
			zenglApi_Exit(VM_ARG,"the first argument of rqtGetBody must be address type");
			break;
		}
		arg.type = ZL_EXP_FAT_INT;
		// 如果追加了NULL字符(正常情况都会追加)，那么body的count的值，会比实际追加的请求主体数据的字节数多一个字节，这里我们只返回实际的字节数
		if(my_parser_data->is_request_body_append_null == ZL_EXP_TRUE)
			arg.val.integer = (my_parser_data->request_body.count - 1);
		else
			arg.val.integer = my_parser_data->request_body.count;
		int body_count = arg.val.integer;
		zenglApi_SetFunArg(VM_ARG,1,&arg);
		if(argcount == 2) {
			zenglApi_GetFunArgInfo(VM_ARG,2,&arg);
			switch(arg.type){
			case ZL_EXP_FAT_ADDR:
			case ZL_EXP_FAT_ADDR_LOC:
			case ZL_EXP_FAT_ADDR_MEMBLK:
				break;
			default:
				zenglApi_Exit(VM_ARG,"the second argument of rqtGetBody must be address type");
				break;
			}
			arg.type = ZL_EXP_FAT_INT;
			if(body_count > 0) {
				int ret_set_ptr = pointer_list_set_member(&(my_data->pointer_list), my_parser_data->request_body.str, body_count, NULL);
				if(ret_set_ptr != 0) {
					zenglApi_Exit(VM_ARG, "rqtGetBody add pointer to pointer_list failed, pointer_list_set_member error code:%d", ret_set_ptr);
				}
				arg.val.integer = (ZL_EXP_LONG)my_parser_data->request_body.str;
			}
			else
				arg.val.integer = 0;
			zenglApi_SetFunArg(VM_ARG,2,&arg);
		}
	}
	else if(argcount != 0) {
		zenglApi_Exit(VM_ARG,"usage: rqtGetBody() | rqtGetBody(&body_count) | rqtGetBody(&body_count, &body_ptr)");
	}

	if(my_parser_data->request_body.str != PTR_NULL && my_parser_data->request_body.count > 0) {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, my_parser_data->request_body.str, 0, 0);
	}
	else {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, "", 0, 0);
	}
}

/**
 * rqtGetBodyAsArray模块函数，主要用于将POST请求的主体数据转为数组的形式返回，
 * 该模块函数既可以解析Content-Type为application/x-www-form-urlencoded的表单请求，
 * 也可以解析Content-Type为multipart/form-data的请求
 * 例如：
	body_array = rqtGetBodyAsArray();
	for(i=0;bltIterArray(body_array,&i,&k,&v);)
		print k +": " + v + '<br/>';
		for(j=0;bltIterArray(v,&j,&inner_k,&inner_v);)
			print "&nbsp;&nbsp;" + inner_k + ": " + inner_v + "<br/>";
			if(inner_k == 'filename')
				bltWriteFile(v['filename'], v['content_ptr'], v['length']);
			endif
		endfor
	endfor

	* 对于下面这个application/x-www-form-urlencoded类型的请求：

	POST /v0_2_0/post.zl HTTP/1.1
	Host: 192.168.0.103:8083
	User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,.....
	Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
	Accept-Encoding: gzip, deflate
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 116
	Referer: http://192.168.0.103:8083/v0_2_0/form.html
	Connection: keep-alive
	Upgrade-Insecure-Requests: 1

	ti%22tl%22e=%E6%A0%87%E9%A2%98&description=%E6%8F%8F%E8%BF%B0&content=%E5%86%85%E5%AE%B9%E9%83%A8%E5%88%86&sb=Submit

	* 脚本在执行时，得到的结果如下：

	ti"tl"e: 标题
	description: 描述
	content: 内容部分
	sb: Submit

	脚本会对主体数据中的名值对进行url解码，例如，ti%22tl%22e被解码为ti"tl"e，%E6%A0%87%E9%A2%98被解码为标题等等

	* 对于下面这个multipart/form-data类型的请求：

	POST /v0_2_0/post.zl HTTP/1.1
	................................
	Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJLB14p6QUQR9oO4G
	................................

	------WebKitFormBoundaryJLB14p6QUQR9oO4G
	Content-Disposition: form-data; name="ti%22tl%22e"

	测试。。！
	------WebKitFormBoundaryJLB14p6QUQR9oO4G
	Content-Disposition: form-data; name="description"

	描述。。
	------WebKitFormBoundaryJLB14p6QUQR9oO4G
	Content-Disposition: form-data; name="content"

	内容哈哈。。。
	------WebKitFormBoundaryJLB14p6QUQR9oO4G
	Content-Disposition: form-data; name="我的文件"; filename="timg.jpg"
	Content-Type: image/jpeg

	.................................

	* 脚本在执行时，得到的结果如下：

	ti"tl"e: 测试。。！
	description: 描述。。
	content: 内容哈哈。。。
	我的文件:
	  filename: timg.jpg
	  type: image/jpeg
	  content_ptr: 140540188302856
	  length: 16212
	sb: Submit

	请求中的name被转为了数组的字符串key，具体的内容则被转为了该key对应的值，
	如果某个part上传的是文件，那么key对应的值将会是一个数组，该数组中包含了
	filename文件名，type文件类型，content_ptr指向文件数据的指针，以及length文件长度
	脚本中就可以通过 bltWriteFile(v['filename'], v['content_ptr'], v['length']);
	将POST上传的文件数据保存到某个文件中
 */
ZL_EXP_VOID module_request_GetBodyAsArray(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZL_EXP_CHAR * content_type = ZL_EXP_NULL;
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(my_data->body_memblock.ptr == ZL_EXP_NULL) {
		if(zenglApi_CreateMemBlock(VM_ARG,&my_data->body_memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
		zenglApi_AddMemBlockRefCount(VM_ARG,&my_data->body_memblock,1); // 手动增加该内存块的引用计数值，使其不会在脚本函数返回时，被释放掉。
		MY_PARSER_DATA * my_parser_data = my_data->my_parser_data;
		if(my_parser_data->request_body.str != PTR_NULL && my_parser_data->request_body.count > 0) {
			get_headers(VM_ARG, my_data);
			ZENGL_EXPORT_MOD_FUN_ARG retval = zenglApi_GetMemBlockByHashKey(VM_ARG,&my_data->headers_memblock, "Content-Type");
			if(retval.type == ZL_EXP_FAT_STR) {
				content_type = retval.val.str;
				if(strcasestr(content_type, "application/x-www-form-urlencoded")) {
					ZL_EXP_CHAR * q = my_parser_data->request_body.str;
					ZL_EXP_INT q_len = my_parser_data->request_body.count;
					parse_urlencoded_str_to_memblock(VM_ARG, q, q_len, &my_data->body_memblock);
				}
				else if(strcasestr(content_type, "multipart/form-data")) {
					const ZL_EXP_CHAR * boundary_key = "boundary=";
					ZL_EXP_CHAR * boundary = strcasestr(content_type, boundary_key);
					if(boundary) {
						ZL_EXP_INT content_type_length = strlen(content_type);
						boundary += strlen(boundary_key);
						if(boundary < (content_type + content_type_length)) {
							ZL_EXP_CHAR * q = my_parser_data->request_body.str;
							ZL_EXP_INT q_len = my_parser_data->request_body.count;
							write_to_server_log_pipe(WRITE_TO_PIPE, "%s[debug]\n", boundary); // debug
							multipart_parser_settings callbacks;
							memset(&callbacks, 0, sizeof(multipart_parser_settings));
							callbacks.on_header_field = read_multipart_header_name;
							callbacks.on_header_value = read_multipart_header_value;
							callbacks.on_headers_complete = on_multipart_headers_complete;
							callbacks.on_part_data = read_multipart_data;
							callbacks.on_part_data_end = on_multipart_data_end;
							multipart_parser* parser = multipart_parser_init(boundary, &callbacks);
							my_multipart_data my_mp_data = {0};
							my_mp_data.VM_ARG = VM_ARG;
							my_mp_data.memblock = &my_data->body_memblock;
							my_mp_data.my_data = my_data;
							multipart_parser_set_data(parser, &my_mp_data);
							multipart_parser_execute(parser, q, q_len);
							multipart_free_all_zlmem(parser);
							multipart_parser_free(parser);
						}
					}
				}
			}
		}
		zenglApi_SetRetValAsMemBlock(VM_ARG,&my_data->body_memblock);
	}
	else {
		zenglApi_SetRetValAsMemBlock(VM_ARG,&my_data->body_memblock);
	}
}

/**
 * rqtGetQueryAsString模块函数，用于获取url资源路径中，查询字符串的原始字符串值，
 * 例如：
 * query_string = rqtGetQueryAsString();
 * print 'query string: ' + query_string + '<br/>';
 * 对于 GET /test.zl?name=zengl&job=programmer HTTP/1.1 的http请求，
 * 上面例子显示的结果就是：query string: name=zengl&job=programmer
 * 如果没有查询字符串，那么该模块函数就会返回空字符串
 */
ZL_EXP_VOID module_request_GetQueryAsString(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	MY_PARSER_DATA * my_parser_data = my_data->my_parser_data;
	struct http_parser_url * url_parser = &my_parser_data->url_parser;

	if((url_parser->field_set & (1 << UF_QUERY)) && (url_parser->field_data[UF_QUERY].len > 0)) {
		ZL_EXP_INT end_pos = url_parser->field_data[UF_QUERY].off + url_parser->field_data[UF_QUERY].len;
		ZL_EXP_CHAR orig_char = my_parser_data->request_url.str[end_pos];
		my_parser_data->request_url.str[end_pos] = STR_NULL;
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, my_parser_data->request_url.str + url_parser->field_data[UF_QUERY].off, 0, 0);
		if(orig_char != STR_NULL) {
			my_parser_data->request_url.str[end_pos] = orig_char;
		}
	}
	else {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, "", 0, 0);
	}
}

/**
 * rqtGetQuery模块函数，用于返回查询字符串的哈希数组形式
 * 例如：
 * querys = rqtGetQuery();
 * print 'querys[\'name\']: ' + querys['name'] + '<br/>';
 * print 'querys[\'job\']: ' + querys['job'] + '<br/>';
 * 对于 GET /test.zl?name=zengl&job=programmer HTTP/1.1 的http请求，
 * 上面例子显示的结果就是：
 * querys['name']: zengl
 * querys['job']: programmer
 *
 * 该模块函数会自动将key:value进行url解码，例如：
 * 对于 GET /v0_1_1/test.zl?%E5%B7%A5%E4%BD%9C=%E7%BC%96%E7%A8%8B HTTP/1.1 的http请求，
 * 解析后的数组成员为：
 * 工作: 编程
 * 其中%E5%B7%A5%E4%BD%9C解码为UTF8字符串“工作”，%E7%BC%96%E7%A8%8B则解码为UTF8字符串“编程”
 *
 * 该模块函数只会在第一次调用时，创建哈希数组，之后再调用该模块函数时，就会直接将之前创建过的数组返回
 */
ZL_EXP_VOID module_request_GetQuery(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	MY_PARSER_DATA * my_parser_data = my_data->my_parser_data;
	struct http_parser_url * url_parser = &my_parser_data->url_parser;
	if(my_data->query_memblock.ptr == ZL_EXP_NULL) {
		if(zenglApi_CreateMemBlock(VM_ARG,&my_data->query_memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
		zenglApi_AddMemBlockRefCount(VM_ARG,&my_data->query_memblock,1); // 手动增加该内存块的引用计数值，使其不会在脚本函数返回时，被释放掉。
		if((url_parser->field_set & (1 << UF_QUERY)) && (url_parser->field_data[UF_QUERY].len > 0)) {
			ZL_EXP_CHAR * q = my_parser_data->request_url.str + url_parser->field_data[UF_QUERY].off;
			ZL_EXP_INT q_len = url_parser->field_data[UF_QUERY].len;
			parse_urlencoded_str_to_memblock(VM_ARG, q, q_len, &my_data->query_memblock);
		}
		zenglApi_SetRetValAsMemBlock(VM_ARG,&my_data->query_memblock);
	}
	else {
		zenglApi_SetRetValAsMemBlock(VM_ARG,&my_data->query_memblock);
	}
}

/**
 * rqtSetResponseHeader模块函数，用于设置需要输出到客户端的响应头
 * 例如：rqtSetResponseHeader("Set-Cookie: name=zengl"); 在执行后
 * 响应头中就会输出Set-Cookie: name=zengl\r\n信息，从而可以设置客户端的cookie
 */
ZL_EXP_VOID module_request_SetResponseHeader(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 1)
		zenglApi_Exit(VM_ARG,"usage: rqtSetResponseHeader(response_header)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument of rqtSetResponseHeader must be string");
	}
	char * response_header = arg.val.str;
	int response_header_length = strlen(response_header);
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	dynamic_string_append(&my_data->response_header, response_header, response_header_length, RESPONSE_HEADER_STR_SIZE);
	dynamic_string_append(&my_data->response_header, "\r\n", 2, RESPONSE_HEADER_STR_SIZE);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, (response_header_length + 2), 0);
}

/**
 * rqtGetResponseHeader模块函数，用于返回脚本中设置过的响应头信息
 */
ZL_EXP_VOID module_request_GetResponseHeader(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	// 响应头信息存储在response_header动态字符串中
	if(my_data->response_header.count > 0) {
		char * response_header = (char *)zenglApi_AllocMem(VM_ARG, my_data->response_header.count + 1);
		strncpy(response_header, my_data->response_header.str, my_data->response_header.count);
		// 动态字符串是通过response_header.count来确定字符串的长度的，并没有对数据进行过清0处理，因此，需要手动追加一个'\0'的字符串终止符，这样返回的字符串中才不会包含count后的无效字符。
		response_header[my_data->response_header.count] = STR_NULL;
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, response_header, 0, 0);
		zenglApi_FreeMem(VM_ARG, response_header);
	}
	else {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, "", 0, 0);
	}
}

/**
 * rqtGetCookie模块函数，用于将请求头中的Cookie名值对信息以数组的形式返回
 * 例如：
 * cookies = rqtGetCookie();
 * for(i=0; bltIterArray(cookies,&i,&k,&v); )
 *		print k +": " + v + '<br/>';
 * endfor
 * 该脚本在执行时，如果客户端的请求头中包含 Cookie: name=zengl; hobby=play game; hello worlds 信息时
 * 执行的结果就会是：
 *	name: zengl
 *	hobby: play game
 *	: hello worlds
 *	请求头Cookie中的hello worlds等效于=hello worlds，也就是key为空
 */
ZL_EXP_VOID module_request_GetCookie(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(my_data->cookie_memblock.ptr == ZL_EXP_NULL) {
		if(zenglApi_CreateMemBlock(VM_ARG,&my_data->cookie_memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
		zenglApi_AddMemBlockRefCount(VM_ARG,&my_data->cookie_memblock,1); // 手动增加该内存块的引用计数值，使其不会在脚本函数返回时，被释放掉。
		get_headers(VM_ARG, my_data);
		ZENGL_EXPORT_MOD_FUN_ARG cookie_header_value = zenglApi_GetMemBlockByHashKey(VM_ARG,&my_data->headers_memblock, "Cookie");
		if(cookie_header_value.type == ZL_EXP_FAT_STR) {
			ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
			char *s,*k,*v, prev_last_k_char, prev_last_v_char;
			int s_len, k_len, v_len, count;
			s = cookie_header_value.val.str; s_len = strlen(cookie_header_value.val.str);
			while(s_len > 0) {
				count = parse_cookie_header_value(s, s_len, &k, &k_len, &v, &v_len);
				if(k_len > 0) {
					prev_last_k_char = k[k_len];
					k[k_len] = STR_NULL;
					arg.type = ZL_EXP_FAT_STR;
					if(v_len > 0) {
						prev_last_v_char = v[v_len];
						v[v_len] = STR_NULL;
						arg.val.str = v;
						zenglApi_SetMemBlockByHashKey(VM_ARG, &my_data->cookie_memblock, k, &arg);
						v[v_len] = prev_last_v_char;
					}
					else if(v_len == 0) {
						arg.val.str = "";
						zenglApi_SetMemBlockByHashKey(VM_ARG, &my_data->cookie_memblock, k, &arg);
					}
					k[k_len] = prev_last_k_char;
				}
				else if(k_len == 0 && v_len > 0) {
					prev_last_v_char = v[v_len];
					v[v_len] = STR_NULL;
					arg.type = ZL_EXP_FAT_STR;
					arg.val.str = v;
					zenglApi_SetMemBlockByHashKey(VM_ARG, &my_data->cookie_memblock, "", &arg);
					v[v_len] = prev_last_v_char;
				}
				s += count;
				s_len -= count;
			}
		}
		zenglApi_SetRetValAsMemBlock(VM_ARG,&my_data->cookie_memblock);
	}
	else {
		zenglApi_SetRetValAsMemBlock(VM_ARG,&my_data->cookie_memblock);
	}
}

/**
 * request模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
 */
ZL_EXP_VOID module_request_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetHeaders",module_request_GetHeaders);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetBody",module_request_GetBody);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetBodyAsArray",module_request_GetBodyAsArray);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetQueryAsString",module_request_GetQueryAsString);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetQuery",module_request_GetQuery);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtSetResponseHeader",module_request_SetResponseHeader);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetResponseHeader",module_request_GetResponseHeader);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetCookie",module_request_GetCookie);
}
