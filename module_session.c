/*
 * module_session.c
 *
 *  Created on: 2017-12-3
 *      Author: zengl
 *
 * 该模块用于处理和session会话相关的内容
 * 在写入会话数据时，zengl脚本中的数组，会先转为json格式，再保存到session会话文件中
 * 在读取会话数据时，会先通过json-parser第三方解析程式，将json解析出来，再转为zengl数组等进行返回
 * json-parser的github地址：https://github.com/udp/json-parser
 */

#include "main.h"
#include "module_session.h"
#include "randutils.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

/**
 * 解析json时，自定义的内存分配函数，将使用zenglApi_AllocMem来分配内存
 * 该Api接口分配的内存，如果没有在脚本中手动释放的话，会在脚本结束并关闭虚拟机时，被自动释放掉
 */
void * my_json_mem_alloc(size_t size, int zero, ZL_EXP_VOID * VM_ARG)
{
	void * retptr = zenglApi_AllocMem(VM_ARG, size);
	if(zero) {
		memset(retptr, 0, size);
	}
	return retptr;
}

/**
 * 解析json时，自定义的内存释放函数，将使用zenglApi_FreeMem接口函数来释放内存
 */
void my_json_mem_free(void * ptr, ZL_EXP_VOID * VM_ARG)
{
	zenglApi_FreeMem(VM_ARG, ptr);
}

/**
 * 由于json中的字符串是用双引号包起来的，因此，字符串内部的双引号和反斜杠需要进行转义
 */
void session_escape_str(ZL_EXP_VOID * VM_ARG, ZL_EXP_CHAR ** e_str, ZL_EXP_CHAR * s_str)
{
	ZL_EXP_CHAR * escape_str = (*e_str);
	if(escape_str == ZL_EXP_NULL)
		escape_str = zenglApi_AllocMem(VM_ARG, (strlen(s_str) * 2 + 1));
	else
		escape_str = zenglApi_ReAllocMem(VM_ARG, escape_str, (strlen(s_str) * 2 + 1));
	ZL_EXP_CHAR * escape_str_cur = escape_str;
	ZL_EXP_CHAR * s_str_cur = s_str;
	ZL_EXP_CHAR * s_str_start = s_str;
	ZL_EXP_INT count = 0;
	for(; (*s_str_cur) != '\0'; s_str_cur++) {
		switch((*s_str_cur)) {
		case '"':
		case '\\':
			count = s_str_cur - s_str_start;
			if(count > 0) {
				strncpy(escape_str_cur, s_str_start, count);
				escape_str_cur += count;
			}
			*escape_str_cur++ = '\\';
			*escape_str_cur++ = (*s_str_cur);
			s_str_start = s_str_cur + 1;
			break;
		}
	}
	// 将剩余的字符拷贝过去
	if(s_str_start < s_str_cur) {
		count = s_str_cur - s_str_start;
		strncpy(escape_str_cur, s_str_start, count);
		escape_str_cur += count;
	}
	(*escape_str_cur) = '\0';
	(*e_str) = escape_str;
}

/**
 * 将zengl脚本中的数组转为json格式，并写入session会话文件
 * 如果数组中还包含了数组，那么所包含的数组在转为json时，会递归调用当前函数
 * 如果数组成员有对应的哈希key(字符串作为key)，那么生成的json会用大括号包起来
 * 例如：{"hello":"world","name":"zengl"}
 * 如果数组成员没有哈希key，那么生成的json会用中括号包起来
 * 例如：[1,2,3,3.14159,"zengl language"]
 */
static void session_write_array_to_file(ZL_EXP_VOID * VM_ARG, FILE * session_file, ZENGL_EXPORT_MEMBLOCK memblock)
{
	ZL_EXP_INT size,count,process_count,i,j;
	ZL_EXP_CHAR * key, * mblk_str;
	ZL_EXP_CHAR * escape_str = ZL_EXP_NULL;
	// make_object用于判断是否生成对象格式的json，对象格式的json字符串会用大括号包起来，并用冒号来分隔数组成员的哈希key与值
	ZL_EXP_BOOL make_object = ZL_EXP_FALSE;
	ZENGL_EXPORT_MOD_FUN_ARG mblk_val = {ZL_EXP_FAT_NONE,{0}};
	zenglApi_GetMemBlockInfo(VM_ARG,&memblock,&size,ZL_EXP_NULL);
	count = zenglApi_GetMemBlockNNCount(VM_ARG, &memblock);
	if(count > 0)
	{
		for(i=1,process_count=0; i<=size && process_count < count; i++)
		{
			mblk_val = zenglApi_GetMemBlock(VM_ARG,&memblock,i);
			zenglApi_GetMemBlockHashKey(VM_ARG,&memblock,i-1,&key);
			switch(mblk_val.type)
			{
			case ZL_EXP_FAT_INT:
			case ZL_EXP_FAT_FLOAT:
			case ZL_EXP_FAT_STR:
			case ZL_EXP_FAT_MEMBLOCK:
				if(process_count == 0) {
					if(key != ZL_EXP_NULL) {
						fprintf(session_file, "{");
						make_object = ZL_EXP_TRUE;
					}
					else {
						fprintf(session_file, "[");
						make_object = ZL_EXP_FALSE;
					}
				}
				process_count++;
				break;
			}
			switch(mblk_val.type)
			{
			case ZL_EXP_FAT_INT: // 对数组中的整数进行转换处理
				if(make_object) {
					if(key != ZL_EXP_NULL)
						fprintf(session_file, "\"%s\":%ld",key,mblk_val.val.integer);
					else
						fprintf(session_file, "\"%d\":%ld",i-1,mblk_val.val.integer);
				}
				else
					fprintf(session_file, "%ld",mblk_val.val.integer);
				break;
			case ZL_EXP_FAT_FLOAT: // 对数组中的浮点数进行转换处理
				if(make_object) {
					if(key != ZL_EXP_NULL)
						fprintf(session_file, "\"%s\":%.16g",key,mblk_val.val.floatnum);
					else
						fprintf(session_file, "\"%d\":%.16g",i-1,mblk_val.val.floatnum);
				}
				else
					fprintf(session_file, "%.16g",mblk_val.val.floatnum);
				break;
			case ZL_EXP_FAT_STR: // 对数组中的字符串进行处理
				// 通过strchr库函数来检测字符串中是否包含双引号或者反斜杠，如果都不包含可以无需进行转义
				if(strchr(mblk_val.val.str, '"') == NULL &&  strchr(mblk_val.val.str, '\\') == NULL) {
					mblk_str = mblk_val.val.str;
				}
				else {
					// 如果字符串中包含双引号或者反斜杠，就需要先将双引号和反斜杠进行转义
					session_escape_str(VM_ARG, &escape_str, mblk_val.val.str);
					mblk_str = escape_str;
				}
				if(make_object) {
					if(key != ZL_EXP_NULL)
						fprintf(session_file, "\"%s\":\"%s\"",key,mblk_str);
					else
						fprintf(session_file, "\"%d\":\"%s\"",i-1,mblk_str);
				}
				else
					fprintf(session_file, "\"%s\"",mblk_str);
				break;
			case ZL_EXP_FAT_MEMBLOCK: // 如果数组成员本身又是一个数组，那么就递归调用当前函数去生成内部数组的json格式
				if(make_object) {
					if(key != ZL_EXP_NULL)
						fprintf(session_file, "\"%s\":",key);
					else
						fprintf(session_file, "\"%d\":",i-1);
				}
				session_write_array_to_file(VM_ARG, session_file, mblk_val.val.memblock);
				break;
			}
			if(process_count == count)
				fprintf(session_file, "%s", (make_object ? "}" : "]")); // 如果处理完当前数组的所有成员，就用大括号或者中括号来闭合
			else
				fprintf(session_file, ","); // 数组成员之间在生成的json中用逗号分隔开
		}
		if(escape_str != ZL_EXP_NULL) { // 释放掉转义字符串所分配的内存
			zenglApi_FreeMem(VM_ARG, escape_str);
		}
	}
}

/**
 * 将模块函数的返回值设置为空数组
 * 将返回空数组的操作写入静态函数，方便其他模块函数直接调用，减少一些冗余代码
 */
static void session_return_empty_array(ZL_EXP_VOID * VM_ARG)
{
	ZENGL_EXPORT_MEMBLOCK memblock;
	if(zenglApi_CreateMemBlock(VM_ARG,&memblock,0) == -1) {
		zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
	}
	zenglApi_SetRetValAsMemBlock(VM_ARG,&memblock);
}

/**
 * 设置session会话文件的超时时间
 * 通过utimes库函数，将会话文件的modification times(修改时间)设置为当前时间加上session_expire秒数
 * cleaner进程在定期清理会话文件时，如果某个会话文件的修改时间小于当前时间(实际操作时是跟当前时间减10比较)，就清理掉该会话文件
 */
static void session_set_expire(char * filename, long session_expire)
{
	struct timeval times[2] = {0};
	times[0].tv_sec = times[1].tv_sec = (time(NULL) + session_expire);
	utimes(filename, times);
}

/**
 * 根据session_dir会话目录和arg_str会话文件名，生成会话文件的相对路径，并存储到filename中
 */
static void session_make_filename(char * filename, char * session_dir, ZL_EXP_CHAR * arg_str)
{
	int session_dir_len = strlen(session_dir);
	strncpy(filename, session_dir, session_dir_len);
	filename[session_dir_len] = '/';
	int filename_arg_len = strlen(arg_str);
	int left_len = SESSION_FILEPATH_MAX_LEN - session_dir_len - 2;
	filename_arg_len = (filename_arg_len <= left_len) ? filename_arg_len : left_len;
	strncpy(filename + session_dir_len + 1, arg_str, filename_arg_len);
	filename[session_dir_len + 1 + filename_arg_len] = '\0';
}

/**
 * 将json对象或json数组转换为zengl脚本中可以使用的数组
 * json对象是使用大括号包起来的包含名值对的json数据
 * 例如：{"hello":"world","name":"zengl"}
 * json数组是使用中括号包起来的只有整数索引(索引从0开始)和对应的值的json数据
 * 例如：[1,2,3,3.14159,"zengl language"]，其中成员1的索引为0，成员2的索引为1，成员3的索引为2，成员3.14159的索引为3，以此类推
 *
 * 该函数的memblock参数是外部调用者，在调用该函数前，创建的内存块(所有的zengl数组在内部都是内存块)
 * value参数是使用json-parser解析json字符串后得到的存储了json成员的结构
 * 该函数会循环读取value中的json成员，如果value是json_object(json对象)，则将json成员中的名值对写入到memblock内存块中
 * 例如：{"hello":"world","name":"zengl"}转换为zengl数组，等效于下面这段脚本：
 * a['hello'] = 'world';
 * a['name'] = 'zengl';
 * 如果value是json_array(json数组)，则将json成员的值和对应的索引写入到memblock内存块中
 * 例如：[1,2,3,3.14159,"zengl language"]转为zengl数组，等效于下面这段脚本：
 * a[0] = 1;
 * a[1] = 2;
 * a[2] = 3;
 * a[3] = 3.14159;
 * a[4] = "zengl language";
 */
void process_json_object_array(ZL_EXP_VOID * VM_ARG, ZENGL_EXPORT_MEMBLOCK * memblock, json_value * value,
		unsigned int depth, unsigned int max_depth)
{
	if (value == NULL) {
		return;
	}
	if(depth > max_depth) {
		zenglApi_Exit(VM_ARG, "json depth %u is big than %u", depth, max_depth);
	}
	int length = value->u.object.length;
	char * member_name;
	json_value * member_value;
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	// 循环读取value中的json成员
	for (int x = 0; x < length; x++) {
		if(value->type == json_object) { // 如果value是json对象，则读取出json成员里的名值对信息，并分别赋值给member_name和member_value
			member_name = value->u.object.values[x].name;
			member_value = value->u.object.values[x].value;
		}
		else
			member_value = value->u.array.values[x];
		switch (member_value->type) {
		case json_none:
			arg.type = ZL_EXP_FAT_NONE;
			break;
		case json_boolean: // bool类型会被转换为整数存储到zengl数组中
			arg.type = ZL_EXP_FAT_INT;
			arg.val.integer = (ZL_EXP_LONG)member_value->u.boolean;
			break;
		case json_integer:
			arg.type = ZL_EXP_FAT_INT;
			arg.val.integer = (ZL_EXP_LONG)member_value->u.integer;
			break;
		case json_double:
			arg.type = ZL_EXP_FAT_FLOAT;
			arg.val.floatnum = member_value->u.dbl;
			break;
		case json_string:
			arg.type = ZL_EXP_FAT_STR;
			arg.val.str = member_value->u.string.ptr;
			break;
		case json_object:
		case json_array:
			arg.type = ZL_EXP_FAT_MEMBLOCK;
			// 如果json成员本身又是一个json对象或者json数组，将创建一个新的memblock(内存块)，并递归调用当前函数去处理
			if(zenglApi_CreateMemBlock(VM_ARG,&arg.val.memblock,0) == -1) {
				zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
			}
			process_json_object_array(VM_ARG, &arg.val.memblock, member_value, (++depth), max_depth);
			break;
		default:
			arg.type = ZL_EXP_FAT_NONE;
			break;
		}
		if(value->type == json_object) // json对象会将名值对写入内存块
			zenglApi_SetMemBlockByHashKey(VM_ARG, memblock, member_name, &arg);
		else // json数组会将索引和值写入内存块
			zenglApi_SetMemBlock(VM_ARG, memblock, (x+1), &arg);
	}
}

/**
 * sessGetData模块函数，根据会话文件名，将会话数据转为zengl脚本可以识别的数据类型
 * 如果会话数据是一个json对象或者json数组，那么返回的就会是zengl数组，如果会话数据是整数，返回的也会是整数等
 */
ZL_EXP_VOID module_session_get_data(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 1)
		zenglApi_Exit(VM_ARG,"usage:sessGetData(sess_file_name)");
	// 获取第一个参数，也就是会话文件名
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [sess_file_name] of sessGetData must be string");
	}
	// 如果是空的会话文件名，直接返回空数组
	if(strlen(arg.val.str) == 0) {
		session_return_empty_array(VM_ARG);
		return;
	}
	char filename[SESSION_FILEPATH_MAX_LEN];
	char * session_dir;
	long session_expire;
	// 先通过main_get_session_config函数获取会话目录，然后根据会话目录和会话文件名生成会话文件的相对路径
	main_get_session_config(&session_dir, &session_expire, NULL);
	session_make_filename(filename, session_dir, arg.val.str);

	int file_size;
	struct stat filestatus;
	if ( stat(filename, &filestatus) != 0) {
		session_return_empty_array(VM_ARG);
		return;
	}
	time_t cur_time = time(NULL);
	// 如果会话文件的修改时间(修改时间被用作超时时间)小于当前时间，则该会话文件已经超时，直接删除掉该文件，并返回空数组
	if(filestatus.st_mtime < cur_time) {
		remove(filename); // 删除超时的会话文件
		write_to_server_log_pipe(WRITE_TO_PIPE, "debug info: sessionGetData remove file: %s [m_time:%d < %d]\n", filename, filestatus.st_mtime, cur_time);
		session_return_empty_array(VM_ARG);
		return;
	}
	file_size = filestatus.st_size;
	FILE * fp = fopen(filename, "rb");
	// fp为NULL，直接返回空数组
	if (fp == NULL) {
		session_return_empty_array(VM_ARG);
		return;
	}
	char * file_contents = (char *)zenglApi_AllocMem(VM_ARG, file_size);
	int nread = fread(file_contents, file_size, 1, fp);
	if ( nread != 1 ) {
		fclose(fp);
		zenglApi_Exit(VM_ARG,"sessGetData error: Unable t read content of \"%s\"", filename);
	}
	fclose(fp);
	json_value * value;
	json_char * json = (json_char*)file_contents;
	json_settings settings = { 0 };
	settings.mem_alloc = my_json_mem_alloc;
	settings.mem_free = my_json_mem_free;
	settings.user_data = VM_ARG;
	json_char json_error_str[json_error_max];
	// 通过json-parser第三方解析程式来解析会话文件中的json数据，解析的结果是一个json_value结构
	value = json_parse_ex (&settings, json, file_size, json_error_str);
	if (value == NULL) {
		zenglApi_Exit(VM_ARG,"sessGetData error: Unable to parse data, json error: %s", json_error_str);
	}
	ZENGL_EXPORT_MEMBLOCK memblock;
	switch (value->type) {
	case json_none: // 将json中的null转为整数0
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		break;
	case json_object:
	case json_array:
		// 如果是json对象或json数组，则创建一个memblock内存块
		if(zenglApi_CreateMemBlock(VM_ARG,&memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
		// 通过process_json_object_array函数，循环将value中的json成员填充到memblock中
		process_json_object_array(VM_ARG, &memblock, value, 1, 1000);
		zenglApi_SetRetValAsMemBlock(VM_ARG,&memblock);
		break;
	case json_integer:
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)value->u.integer, 0);
		break;
	case json_double:
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_FLOAT, ZL_EXP_NULL, 0, value->u.dbl);
		break;
	case json_string:
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, value->u.string.ptr, 0, 0);
		break;
	case json_boolean: // 将json中的bool类型转为整数，例如：true转为1，false转为0
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)value->u.boolean, 0);
		break;
	default:
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		break;
	}
	json_value_free_ex (&settings, value);
	zenglApi_FreeMem(VM_ARG, file_contents);
	// 设置会话文件session_expire秒后过期，其实就是将会话文件的修改时间设置为当前时间加上session_expire秒后的时间值
	// 因此，会话文件的修改时间就是过期时间
	session_set_expire(filename, session_expire);
}

/**
 * sessSetData模块函数，将zengl数据写入到sess_file_name会话文件
 * 在写入时，如果是zengl数组，则会被先转为json格式，再写入会话文件
 * 例如：
 * a['hello'] = 'world';
 * a['name'] = 'zengl';
 * sessSetData(sess_id, a);
 * 执行后，写入sess_id会话文件中的内容就会是: {"hello":"world","name":"zengl"}
 */
ZL_EXP_VOID module_session_set_data(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 2)
		zenglApi_Exit(VM_ARG,"usage:sessSetData(sess_file_name, data)");
	// 获取第一个参数，也就是会话文件名
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [sess_file_name] of sessSetData must be string");
	}
	// 如果是空的会话文件名，直接返回0
	if(strlen(arg.val.str) == 0) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		return;
	}
	char filename[SESSION_FILEPATH_MAX_LEN];
	char * session_dir;
	long session_expire;
	// 先通过main_get_session_config函数获取会话目录，然后根据会话目录和会话文件名生成会话文件的相对路径
	main_get_session_config(&session_dir, &session_expire, NULL);
	session_make_filename(filename, session_dir, arg.val.str);

	struct stat filestatus;
	if ( stat(filename, &filestatus) == 0) {
		time_t cur_time = time(NULL);
		if(filestatus.st_mtime < cur_time) {
			remove(filename); // 删除超时的会话文件，超时的会话文件，既不能进行读取操作，也不能进行写入操作
			write_to_server_log_pipe(WRITE_TO_PIPE, "debug info: sessSetData remove file: %s [m_time:%d < %d]\n", filename, filestatus.st_mtime, cur_time);
			zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
			return;
		}
	}

	FILE * session_file = fopen(filename, "w+");
	if(session_file == NULL) {
		zenglApi_Exit(VM_ARG,"sessSetData open file \"%s\" failed [%d] %s", filename, errno, strerror(errno));
	}
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	switch(arg.type) {
	case ZL_EXP_FAT_MEMBLOCK:
		// 通过session_write_array_to_file函数将zengl数组转为json格式，并写入session_file会话文件
		session_write_array_to_file(VM_ARG, session_file, arg.val.memblock);
		break;
	case ZL_EXP_FAT_INT:
		fprintf(session_file, "%ld",arg.val.integer);
		break;
	case ZL_EXP_FAT_FLOAT:
		fprintf(session_file, "%.16g",arg.val.floatnum);
		break;
	case ZL_EXP_FAT_STR:
		fprintf(session_file, "%s",arg.val.str);
		break;
	default:
		fprintf(session_file, "null");
		break;
	}
	fclose(session_file);
	// 设置会话文件session_expire秒后过期，其实就是将会话文件的修改时间设置为当前时间加上session_expire秒后的时间值
	// 因此，会话文件的修改时间就是过期时间
	session_set_expire(filename, session_expire);
	// 执行成功，返回整数1
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 1, 0);
}

/**
 * sessDelete模块函数，根据sess_file_name会话文件名删除会话文件
 */
ZL_EXP_VOID module_session_delete(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 1)
		zenglApi_Exit(VM_ARG,"usage:sessDelete(sess_file_name)");
	// 获取第一个参数，也就是会话文件名
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [sess_file_name] of sessDelete must be string");
	}
	// 如果是空的会话文件名，直接返回0
	if(strlen(arg.val.str) == 0) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		return;
	}
	char filename[SESSION_FILEPATH_MAX_LEN];
	char * session_dir;
	long session_expire;
	// 先通过main_get_session_config函数获取会话目录，然后根据会话目录和会话文件名生成会话文件的相对路径
	main_get_session_config(&session_dir, &session_expire, NULL);
	session_make_filename(filename, session_dir, arg.val.str);

	struct stat filestatus;
	if ( stat(filename, &filestatus) == 0) {
		remove(filename); // 删除会话文件
	}
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 1, 0);
}

/**
 * sessMakeId模块函数，生成40个字符的随机字符串，并将该字符串作为结果返回
 * 该随机字符串可以用作会话文件名
 * 生成随机字符串时，所使用的random_get_bytes函数，是从libuuid库中移植过来的，
 * 其中会用到/dev/urandom或者/dev/random等，具有比较高的随机性
 */
ZL_EXP_VOID module_session_make_id(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	unsigned int v, i;
	char buf[50];
	char * p = buf;
	for (i = 0; i < 5; i++) {
		random_get_bytes(&v, sizeof(v));
		sprintf(p, "%08x", v);
		p += 8;
	}
	(*p) = '\0';
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, buf, 0, 0);
}

/**
 * session模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
 */
ZL_EXP_VOID module_session_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"sessGetData", module_session_get_data);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"sessSetData", module_session_set_data);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"sessDelete", module_session_delete);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"sessMakeId", module_session_make_id);
}
