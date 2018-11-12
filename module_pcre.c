/*
 * module_pcre.c
 *
 *  Created on: Nov 2, 2018
 *      Author: zengl
 */

#include "module_builtin.h"
#include "module_pcre.h"
#include <pcre.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_INDEX_NUM 20
#define REPLACE_INDEX_SIZE 10

/**
 * 正则表达式替换操作时，第二个需要替换的字符串参数中，如果有{1}，{2}之类的替换分组信息，
 * 就将替换分组信息解析出来，每个替换分组信息对应一个pcre_replace_index结构体，
 * 前提是正则替换函数开启了使用分组进行替换的功能
 */
typedef struct _pcre_replace_index {
	int escape_start;
	int escape_end;
	int capture_index; // 分组索引值，{1}对应的索引值为1，{2}对应的索引值为2，以此类推，{0}表示匹配到的完整字符串
} pcre_replace_index;

/**
 * 解析分组得到的pcre_replace_index结构会存储在动态数组中，
 * 下面的pcre_replace_index_manage是该动态数组的管理器，
 * 利用该管理器可以对数组进行动态的扩容
 */
typedef struct _pcre_replace_index_manage{
	ZL_EXP_BOOL is_init; // 判断替换字符串中的分组信息是否都解析到了动态数组中
	int count; // 动态数组的有效成员数
	int size;  // 动态数组可以容纳的成员数，当有效成员数会超过可容纳的数量时，就会对数组进行动态扩容
	pcre_replace_index * indexes; // 指向存储pcre_replace_index结构体的动态数组
	char * escape_str; // 转义后的替换字符串
	int escape_cnt;    // 转义后的替换字符串的字符数
} pcre_replace_index_manage;

/**
 * 将正则匹配和正则替换模块函数中的第四个modifier参数，从字符串格式转为对应的pcre选项
 * modifier中的字符'i'，会转为PCRE_CASELESS选项，表示正则匹配时，忽略大小写
 * modifier中的字符's'，会转为PCRE_DOTALL选项，表示正则匹配时，'.'点字符能匹配任意字符，包括换行符
 * modifier中的字符'm'，会转为PCRE_MULTILINE选项，表示正则匹配时，^和$能匹配多行字符串中的任意一行的起始和结束位置
 */
static int st_pcre_get_options(ZL_EXP_VOID * VM_ARG, int arg_index,
			ZENGL_EXPORT_MOD_FUN_ARG * arg, const char * function_name)
{
	int options = 0;
	zenglApi_GetFunArg(VM_ARG, arg_index, arg);
	if(arg->type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the fourth argument [modifier] of %s must be string", function_name);
	}
	char * modifier = arg->val.str;
	int modifier_len = strlen(modifier);
	for(int i=0; i < modifier_len;i++) {
		switch(modifier[i]) {
		case 'i':
			options |= PCRE_CASELESS;
			break;
		case 's':
			options |= PCRE_DOTALL;
			break;
		case 'm':
			options |= PCRE_MULTILINE;
			break;
		}
	}
	return options;
}

/**
 * 下面是pcreMatch和pcreMatchAll模块函数的公共处理函数，
 * 该函数会将模块函数中的pattern，subject，result_array和可选的modifier参数都解析出来，
 * pattern表示需要匹配的正则表达式，subject表示需要匹配的主体内容
 * 匹配的结果会存储在result_array数组中，可选的modifier表示额外的匹配选项
 * 在解析出参数后，会使用pcre_compile的库函数来编译正则表达式，
 * 并通过pcre_fullinfo库函数获取正则表达式中包含的分组数量信息
 * pcre库的官方网站：http://www.pcre.org
 */
static void st_pcre_match_common(ZL_EXP_VOID * VM_ARG, ZL_EXP_INT argcount, ZENGL_EXPORT_MOD_FUN_ARG * arg,
			char ** arg_subject, int * arg_total_count, pcre ** arg_re, const char * function_name)
{
	if(argcount < 3)
		zenglApi_Exit(VM_ARG,"usage: %s(pattern, subject, &result_array[, modifier])", function_name);
	zenglApi_GetFunArg(VM_ARG,1, arg);
	if(arg->type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [pattern] of %s must be string", function_name);
	}
	char * pattern = arg->val.str;
	zenglApi_GetFunArg(VM_ARG,2, arg);
	if(arg->type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [subject] of %s must be string", function_name);
	}
	char * subject = arg->val.str;
	zenglApi_GetFunArgInfo(VM_ARG,3, arg);
	switch(arg->type){
	case ZL_EXP_FAT_ADDR:
	case ZL_EXP_FAT_ADDR_LOC:
	case ZL_EXP_FAT_ADDR_MEMBLK:
		break;
	default:
		zenglApi_Exit(VM_ARG,"the third argument [&result_array] of %s must be address type", function_name);
		break;
	}
	int options = 0;
	if(argcount > 3) {
		options = st_pcre_get_options(VM_ARG, 4, arg, function_name);
	}
	pcre * re;
	const char * error;
	int erroffset;
	re = pcre_compile(pattern, options, &error, &erroffset, NULL);
	if (re == NULL) {
		zenglApi_Exit(VM_ARG,"%s error, PCRE compilation failed at offset %d: %s", function_name, erroffset, error);
	}
	int capture_count = 0;
	int total_count = 1;
	pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &capture_count);
	total_count = (total_count + capture_count) * 3;
	(*arg_subject) = subject;
	(*arg_total_count) = total_count;
	(*arg_re) = re;
	return;
}

/**
 * 将替换字符串中解析得到的capture_index(需要进行替换的分组索引值)，
 * 以及该分组索引之前的转义字符串的起始和结束位置记录到pcre_replace_index结构体中，
 * 并将该结构体追加到pcre_replace_index_manage管理的动态数组的末尾
 */
static void st_pcre_replace_manage_add(ZL_EXP_VOID * VM_ARG, pcre_replace_index_manage * index_manage,
		int escape_start, int escape_end, int capture_index)
{
	if(index_manage->indexes == NULL) {
		index_manage->size = REPLACE_INDEX_SIZE;
		index_manage->indexes = zenglApi_AllocMem(VM_ARG, index_manage->size * sizeof(pcre_replace_index));
		memset(index_manage->indexes, 0, index_manage->size * sizeof(pcre_replace_index));
	}
	else if(index_manage->count >= index_manage->size) {
		index_manage->size += REPLACE_INDEX_SIZE;
		index_manage->indexes = zenglApi_ReAllocMem(VM_ARG, index_manage->indexes, index_manage->size * sizeof(pcre_replace_index));
		memset((index_manage->indexes + (index_manage->size - REPLACE_INDEX_SIZE)), 0,
				REPLACE_INDEX_SIZE * sizeof(pcre_replace_index));
	}
	index_manage->indexes[index_manage->count].escape_start = escape_start;
	index_manage->indexes[index_manage->count].escape_end = escape_end;
	index_manage->indexes[index_manage->count].capture_index = capture_index;
	index_manage->count++;
}

/**
 * 根据替换字符串得到转义后的实际需要替换的字符串，
 * 在pcreReplace正则表达式替换模块函数中，第二个replace参数里面可以包含{1}，{2}之类的需要替换的分组信息，
 * {1}表示这个位置由索引值为1的正则表达式分组来替换，{2}表示由索引值为2的分组来替换等，
 * 那么如果不希望{1}表示替换分组信息，而是表示普通的'{1}'字符串，那么就需要使用'^'对'{'进行转义，让'{'成为普通的字符，
 * 同时，'^'对自己也可以进行转义，两个'^'表示一个普通的'^'字符，
 * 之所以没用'\'来转义，是因为'\'在zengl脚本解析字符串时已经被转义过一次了，所以就换了一个转义字符
 */
static void st_pcre_replace_add_index(ZL_EXP_VOID * VM_ARG, char * replace, int start, int end,
		pcre_replace_index_manage * index_manage, int capture_index)
{
	if(index_manage->escape_str == NULL) {
		int replace_length = strlen(replace);
		index_manage->escape_str = zenglApi_AllocMem(VM_ARG, (replace_length + 1) * sizeof(char));
		index_manage->escape_cnt = 0;
	}
	int escape_start = index_manage->escape_cnt;
	int j = escape_start;
	for(int i = start; i < end; i++,j++) {
		switch(replace[i]) {
		case '^':
			if((i + 1) < end && (replace[i + 1] == '^' || replace[i + 1] == '{')) {
				index_manage->escape_str[j] = replace[i + 1];
				i++;
				continue;
			}
		default:
			index_manage->escape_str[j] = replace[i];
			break;
		}
	}
	index_manage->escape_cnt = j;
	index_manage->escape_str[index_manage->escape_cnt] = '\0';
	int escape_end = j;
	st_pcre_replace_manage_add(VM_ARG, index_manage, escape_start, escape_end, capture_index);
}

/**
 * 在pcreReplace模块函数执行实际的替换操作之前，需要先对第二个replace参数进行初始化解析(前提是，use_capture是不为0的值)
 * 在解析时，replace参数中的{1}，{2}，{3}等会被转为需要替换的分组信息(主要是分组索引值)，并存储到pcre_replace_index_manage管理的动态数组中，
 * 同时replace中的'^'字符会对'{'进行转义，让'{'变为普通的字符，从而让{1}变为普通的字符串，例如^{1}得到的结果就是{1}，而不会被分组替换掉
 */
static void st_pcre_replace_init(ZL_EXP_VOID * VM_ARG, char * replace, pcre_replace_index_manage * index_manage)
{
	int replace_length = strlen(replace);
	int start = 0;
	for(int i=0; i < replace_length;i++) {
		switch(replace[i]) {
		case '^':
			i++;
			break;
		case '{':
			{
				char index_num[MAX_INDEX_NUM];
				int end = i++;
				ZL_EXP_BOOL has_break = ZL_EXP_FALSE;
				int j=0;
				for(; i < replace_length; i++) {
					if(replace[i] > 0 && isdigit(replace[i])) {
						if(j < (MAX_INDEX_NUM - 1)) {
							index_num[j++] = replace[i];
						}
					}
					else if(replace[i] == '}') {
						index_num[j] = '\0';
						has_break = ZL_EXP_TRUE;
						break;
					}
					else {
						i--;
						j = 0;
						index_num[j] = '\0';
						break;
					}
				}
				if(has_break && j > 0) {
					int index = 0;
					for(int d = 0; d < j; d++) {
						index = 10 * index + (index_num[d] - '0');
					}
					st_pcre_replace_add_index(VM_ARG, replace, start, end, index_manage, index);
					start = i + 1;
				}
			}
			break;
		}
	}
	if(start < replace_length) {
		st_pcre_replace_add_index(VM_ARG, replace, start, replace_length, index_manage, -1);
	}
	index_manage->is_init = ZL_EXP_TRUE;
}

/**
 * 利用pcre_replace_index_manage管理的动态数组执行实际的替换操作，
 * 该函数会先将数组中pcre_replace_index里的escape_start到escape_end的转义字符串拷贝到infoString结果字符串中，
 * 再根据pcre_replace_index里的capture_index分组索引值，将需要替换的分组字符串拷贝到infoString结果字符串，
 * 循环处理完每一项后，完成一次正则匹配替换操作
 */
static void st_pcre_replace_do(ZL_EXP_VOID * VM_ARG, BUILTIN_INFO_STRING * infoString,
		pcre_replace_index_manage * index_manage, int rc, char * subject, int * ovector)
{
	for(int i = 0; i < index_manage->count; i++) {
		pcre_replace_index * item = &index_manage->indexes[i];
		if(item->escape_end > item->escape_start) {
			builtin_make_info_string(VM_ARG, infoString, "%.*s", (item->escape_end - item->escape_start),
					(index_manage->escape_str + item->escape_start));
		}
		if(item->capture_index >= 0 && item->capture_index < rc) {
			char * substring_start = subject + ovector[2 * item->capture_index];
			int substring_length = ovector[2 * item->capture_index + 1] - ovector[2 * item->capture_index];
			builtin_make_info_string(VM_ARG, infoString, "%.*s", substring_length, substring_start);
		}
	}
}

/**
 * 释放掉pcreMatchAll模块函数在执行时分配过的相关资源
 */
static void st_pcre_free_all(ZL_EXP_VOID * VM_ARG, pcre * re, int * ovector, ZENGL_EXPORT_MEMBLOCK * memblocks)
{
	if(re != NULL) {
		free(re);
	}
	if(ovector != NULL) {
		zenglApi_FreeMem(VM_ARG, ovector);
	}
	if(memblocks != NULL) {
		zenglApi_FreeMem(VM_ARG, memblocks);
	}
}

/**
 * 释放掉pcreReplace模块函数在执行过程中分配过的相关资源
 */
static void st_pcre_replace_free_all(ZL_EXP_VOID * VM_ARG, pcre * re, int * ovector, pcre_replace_index_manage * index_manage)
{
	if(re != NULL) {
		free(re);
	}
	if(ovector != NULL) {
		zenglApi_FreeMem(VM_ARG, ovector);
	}
	if(index_manage->escape_str != NULL) {
		zenglApi_FreeMem(VM_ARG, index_manage->escape_str);
	}
	if(index_manage->indexes != NULL) {
		zenglApi_FreeMem(VM_ARG, index_manage->indexes);
	}
}

/**
 * pcreMatch模块函数，通过正则表达式进行匹配，只匹配一次，返回值为0表示没匹配到，返回值大于0表示匹配到了，
 * 该模块函数的第一个参数pattern表示需要匹配的正则表达式，第二个参数subject表示需要匹配的主体内容，
 * 第三个参数result_array以数组的形式存储匹配的结果，匹配结果中，第一个成员表示匹配到的包括各分组在内的完整字符串，
 * result_array第二个成员表示匹配到的索引值为1的第一个分组，第三个成员表示匹配到的索引值为2的第二个分组，以此类推。
 * 由于result_array要存储匹配的结果，因此，必须是引用类型，
 * 第四个参数modifier是可选的，表示额外的匹配选项，例如，当modifier中包含字符'i'时，表示忽略大小写等，
 * 例如：
 * use builtin, request, pcre;
 * rqtSetResponseHeader("Content-Type: text/html; charset=utf-8");
 * ret = pcreMatch('^(\d+)\s+<Title>(.*?)</Title>$', 'hello\n\n112 <title>世界你好吗\n！</title>', &results, 'ism');
 * if(!ret)
 * 	print 'no match';
 * else
 * 	for(i=0;bltIterArray(results,&i,&k, &v);)
 * 		print k + '):' + v;
 * 	endfor
 * endif
 * 得到的结果是：
 * 0):112 <title>世界你好吗
 * ！</title>
 * 1):112
 * 2):世界你好吗
 * ！
 */
ZL_EXP_VOID module_pcre_match(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	char * subject = NULL;
	pcre * re = NULL;
	int total_count = 0;
	st_pcre_match_common(VM_ARG, argcount, &arg, &subject, &total_count, &re, "pcreMatch");
	int * ovector = zenglApi_AllocMem(VM_ARG, total_count * sizeof(int));
	int rc = pcre_exec(re, NULL, subject, strlen(subject), 0, 0, ovector, total_count);
	free(re);
	if(rc < 0) {
		zenglApi_FreeMem(VM_ARG, ovector);
		if(rc == PCRE_ERROR_NOMATCH)
			zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		else
			zenglApi_Exit(VM_ARG,"pcreMatch Matching error %d", rc);
		return;
	}
	ZENGL_EXPORT_MEMBLOCK memblock = {0};
	if(zenglApi_CreateMemBlock(VM_ARG,&memblock,0) == -1) {
		zenglApi_FreeMem(VM_ARG, ovector);
		zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
	}
	for (int i = 0; i < rc; i++) {
		char * substring_start = subject + ovector[2*i];
		int substring_length = ovector[2*i+1] - ovector[2*i];
		char tmp = substring_start[substring_length];
		substring_start[substring_length] = '\0';
		arg.type = ZL_EXP_FAT_STR;
		arg.val.str = substring_start;
		zenglApi_SetMemBlock(VM_ARG,&memblock,(i + 1),&arg);
		substring_start[substring_length] = tmp;
	}
	arg.type = ZL_EXP_FAT_MEMBLOCK;
	arg.val.memblock = memblock;
	zenglApi_SetFunArg(VM_ARG,3,&arg);
	zenglApi_FreeMem(VM_ARG, ovector);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, rc, 0);
}

/**
 * pcreMatchAll模块函数，通过正则表达式进行匹配，
 * 该模块函数与pcreMatch的区别是，它能匹配到所有的字符串，而不像pcreMatch只匹配一次，
 * pcreMatchAll和pcreMatch的参数是一样的，参数的含义可以参考pcreMatch模块函数，
 * pcreMatchAll匹配的结果和pcreMatch一样存储在result_array数组中，
 * 只不过该模块函数的result_array是一个二维数组，也就是说，result_array的每个成员都是一个数组，
 * 索引值为0的第一个成员对应的数组中，都存储的是匹配到的完整的字符串，
 * 索引值为1的第二个成员对应的数组中，都存储的是第一个分组的字符串，
 * 索引值为2的第三个成员对应的数组中，都存储的是第二个分组的字符串，以此类推
 * 例如：
	use builtin, request, pcre;
	rqtSetResponseHeader("Content-Type: text/html; charset=utf-8");
	ret = pcreMatchAll('^(\d+)\s+<Title>(.*?)</Title>$', 'hello\n\n112 <title>世界你好吗\n！！</title>\n3223 <TItle>～～hello world哈哈～～</TItle>', &results, 'ism');
	if(!ret)
		print 'no match';
	else
		for(i=0;bltIterArray(results,&i,&k, &v);)
			// print k + '):' + v;
			print k + '):';
			for(j=0;bltIterArray(v, &j, &kk, &vv);)
				print '['+ kk + ']:' + vv;
			endfor
		endfor
		print '';
		for(j=0;bltIterArray(results[2], &j, &kk, &vv);)
			print '['+ kk + ']:' + vv;
		endfor
	endif

 * 得到的结果会是：
	0):
	[0]:112 <title>世界你好吗
	！！</title>
	[1]:3223 <TItle>～～hello world哈哈～～</TItle>
	1):
	[0]:112
	[1]:3223
	2):
	[0]:世界你好吗
	！！
	[1]:～～hello world哈哈～～

	[0]:世界你好吗
	！！
	[1]:～～hello world哈哈～～
 */
ZL_EXP_VOID module_pcre_match_all(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	char * subject = NULL;
	pcre * re = NULL;
	int total_count = 0;
	st_pcre_match_common(VM_ARG, argcount, &arg, &subject, &total_count, &re, "pcreMatchAll");
	int * ovector = zenglApi_AllocMem(VM_ARG, total_count * sizeof(int));
	int match_count = 0;
	int subject_length = strlen(subject);
	ZENGL_EXPORT_MEMBLOCK * memblocks = NULL;
	for(int offset = 0, j = 0; offset < subject_length; j++) {
		int rc = pcre_exec(re, NULL, subject, strlen(subject), offset, 0, ovector, total_count);
		if(rc < 0) {
			if(rc == PCRE_ERROR_NOMATCH)
				break;
			else {
				st_pcre_free_all(VM_ARG, re, ovector, memblocks);
				zenglApi_Exit(VM_ARG,"pcreMatchAll Matching error %d", rc);
			}
		}
		match_count++;
		if(memblocks == NULL) {
			memblocks = zenglApi_AllocMem(VM_ARG, total_count * sizeof(ZENGL_EXPORT_MEMBLOCK));
			memset(memblocks, 0, total_count * sizeof(ZENGL_EXPORT_MEMBLOCK));
		}
		for (int i = 0; i < rc; i++) {
			char * substring_start = subject + ovector[2*i];
			int substring_length = ovector[2*i+1] - ovector[2*i];
			char tmp = substring_start[substring_length];
			substring_start[substring_length] = '\0';
			arg.type = ZL_EXP_FAT_STR;
			arg.val.str = substring_start;
			if(memblocks[i].ptr == NULL) {
				if(zenglApi_CreateMemBlock(VM_ARG,&memblocks[i],0) == -1) {
					st_pcre_free_all(VM_ARG, re, ovector, memblocks);
					zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
				}
			}
			zenglApi_SetMemBlock(VM_ARG,&memblocks[i],(j + 1),&arg);
			substring_start[substring_length] = tmp;
		}
		offset = ovector[1];
	}
	if(match_count > 0 && memblocks != NULL) {
		ZENGL_EXPORT_MEMBLOCK memblock = {0};
		if(zenglApi_CreateMemBlock(VM_ARG,&memblock,0) == -1) {
			st_pcre_free_all(VM_ARG, re, ovector, memblocks);
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
		for(int i = 0; i < total_count; i++) {
			if(memblocks[i].ptr != NULL) {
				arg.type = ZL_EXP_FAT_MEMBLOCK;
				arg.val.memblock = memblocks[i];
				zenglApi_SetMemBlock(VM_ARG,&memblock,(i + 1),&arg);
			}
			else
				break;
		}
		arg.type = ZL_EXP_FAT_MEMBLOCK;
		arg.val.memblock = memblock;
		zenglApi_SetFunArg(VM_ARG,3,&arg);
	}
	st_pcre_free_all(VM_ARG, re, ovector, memblocks);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, match_count, 0);
}

/**
 * pcreReplace模块函数，通过正则表达式执行替换操作
 * 该模块函数的第一个参数pattern表示需要匹配的正则表达式，第二个参数replace表示需要进行替换的字符串，
 * 第三个参数subject表示需要进行匹配和替换的主体字符串，第四个参数modifier是可选的，表示额外的匹配选项，
 * 第五个参数use_capture也是可选的，表示replace参数中的{1}，{2}等是否需要被替换为对应的分组，默认是1，表示需要替换，
 * 第六个参数replace_num也是可选的，表示需要替换多少个字符串，默认为-1，表示全部替换，如果为1表示替换1个，为2表示替换前2个，以此类推。
 * 当use_capture是不为0的值时，replace中的{0}表示替换为匹配的完整字符串，{1}表示替换为匹配到的第一个分组，{2}表示替换为匹配到的第二个分组等
 * replace中的'^'字符可以转义'{'，从而让{1}等变为普通的字符串，例如：'^{1}'就表示'{1}'的普通字符串，'^'还会将自己转义，'^^'表示一个'^'，
 * 转义操作也发生在use_capture不为0的时候，如果use_capture为0，则不会有分组替换操作，也不会有replace的转义操作，
 *
 * 该模块函数的使用，可以参考下面的例子：
	use builtin, request, pcre;
	def TRUE 1;
	def FALSE 0;

	rqtSetResponseHeader("Content-Type: text/html; charset=utf-8");

	ret = pcreReplace('^(\d+)\s+<Title>(.*?)</Title>$', '[title]^^^{1}{2}[/title]',
				'hello\n\n112 <title>世界你好吗\n！！</title>\n3223 <TItle>～～hello world哈哈～～</TItle>', 'ism');
	print ret;
	print '';
	ret = pcreReplace('^(\d+)\s+<Title>(.*?)</Title>$', '[title]^^^{1}{2}[/title]',
				'hello\n\n112 <title>世界你好吗\n！！</title>\n3223 <TItle>～～hello world哈哈～～</TItle>', 'ism', FALSE);
	print ret;
	print '';
	ret = pcreReplace('^(\d+)\s+<Title>(.*?)</Title>$', '[title]^^{1}{2}[/title]',
				'hello\n\n112 <title>世界你好吗\n！！</title>\n3223 <TItle>～～hello world哈哈～～</TItle>', 'ism', TRUE, 1);
	print ret;

 * 上面得到的结果会是：
	hello

	[title]^{1}世界你好吗
	！！[/title]
	[title]^{1}～～hello world哈哈～～[/title]

	hello

	[title]^^^{1}{2}[/title]
	[title]^^^{1}{2}[/title]

	hello

	[title]^112世界你好吗
	！！[/title]
	3223 <TItle>～～hello world哈哈～～</TItle>
 */
ZL_EXP_VOID module_pcre_replace(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 3)
		zenglApi_Exit(VM_ARG,"usage: pcreReplace(pattern, replace, subject[, modifier[, use_capture[, replace_num]]])");
	zenglApi_GetFunArg(VM_ARG,1, &arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [pattern] of pcreReplace must be string");
	}
	char * pattern = arg.val.str;
	zenglApi_GetFunArg(VM_ARG,2, &arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [replace] of pcreReplace must be string");
	}
	char * replace = arg.val.str;
	zenglApi_GetFunArg(VM_ARG,3, &arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the third argument [subject] of pcreReplace must be string");
	}
	char * subject = arg.val.str;
	int options = 0;
	if(argcount > 3) {
		options = st_pcre_get_options(VM_ARG, 4, &arg, "pcreReplace");
	}
	int use_capture = ZL_EXP_TRUE;
	if(argcount > 4) {
		zenglApi_GetFunArg(VM_ARG, 5, &arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the fifth argument [use_capture] of pcreReplace must be integer");
		}
		use_capture = arg.val.integer;
	}
	int replace_num = -1;
	if(argcount > 5) {
		zenglApi_GetFunArg(VM_ARG, 6, &arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the sixth argument [replace_num] of pcreReplace must be integer");
		}
		replace_num = arg.val.integer;
	}
	pcre * re;
	const char * error;
	int erroffset;
	re = pcre_compile(pattern, options, &error, &erroffset, NULL);
	if (re == NULL) {
		zenglApi_Exit(VM_ARG,"pcreReplace error, PCRE compilation failed at offset %d: %s", erroffset, error);
	}
	int capture_count = 0;
	int total_count = 1;
	pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &capture_count);
	total_count = (total_count + capture_count) * 3;
	int * ovector = zenglApi_AllocMem(VM_ARG, total_count * sizeof(int));
	int match_count = 0;
	BUILTIN_INFO_STRING infoString = { 0 };
	int subject_length = strlen(subject);
	int offset = 0;
	pcre_replace_index_manage index_manage = {0};
	for(; offset < subject_length; ) {
		int rc = pcre_exec(re, NULL, subject, strlen(subject), offset, 0, ovector, total_count);
		if(rc < 0) {
			if(rc == PCRE_ERROR_NOMATCH)
				break;
			else {
				st_pcre_replace_free_all(VM_ARG, re, ovector, &index_manage);
				if(infoString.str != NULL) {
					zenglApi_FreeMem(VM_ARG, infoString.str);
				}
				zenglApi_Exit(VM_ARG,"pcreReplace Matching error %d", rc);
			}
		}
		match_count++;
		if(replace_num >= 0 && match_count > replace_num) {
			break;
		}
		int len = ovector[0] - offset;
		if(len > 0) {
			builtin_make_info_string(VM_ARG, &infoString, "%.*s", len, (subject + offset));
		}
		if(use_capture) {
			if(index_manage.is_init == ZL_EXP_FALSE) {
				st_pcre_replace_init(VM_ARG, replace, &index_manage);
			}
			st_pcre_replace_do(VM_ARG, &infoString, &index_manage, rc, subject, ovector);
		}
		else
			builtin_make_info_string(VM_ARG, &infoString, "%s", replace);
		offset = ovector[1];
	}
	if(offset > 0 && offset < subject_length) {
		builtin_make_info_string(VM_ARG, &infoString, "%s", (subject + offset));
	}
	st_pcre_replace_free_all(VM_ARG, re, ovector, &index_manage);
	if(infoString.str != NULL) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, infoString.str, 0, 0);
		zenglApi_FreeMem(VM_ARG, infoString.str);
	}
	else
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_STR, subject, 0, 0);
}

/**
 * pcre模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
 */
ZL_EXP_VOID module_pcre_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"pcreMatch",module_pcre_match);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"pcreMatchAll",module_pcre_match_all);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"pcreReplace",module_pcre_replace);
}
