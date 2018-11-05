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

typedef struct _pcre_replace_index {
	int escape_start;
	int escape_end;
	int capture_index;
} pcre_replace_index;

typedef struct _pcre_replace_index_manage{
	ZL_EXP_BOOL is_init;
	int count;
	int size;
	pcre_replace_index * indexes;
	char * escape_str;
	int escape_cnt;
} pcre_replace_index_manage;

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

ZL_EXP_VOID module_pcre_replace(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 3)
		zenglApi_Exit(VM_ARG,"usage: pcreReplace(pattern, replace, subject[, modifier])");
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
		int len = ovector[0] - offset;
		if(len > 0) {
			builtin_make_info_string(VM_ARG, &infoString, "%.*s", len, (subject + offset));
		}
		if(index_manage.is_init == ZL_EXP_FALSE) {
			st_pcre_replace_init(VM_ARG, replace, &index_manage);
		}
		st_pcre_replace_do(VM_ARG, &infoString, &index_manage, rc, subject, ovector);
		// builtin_make_info_string(VM_ARG, &infoString, "%s", replace);
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

ZL_EXP_VOID module_pcre_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"pcreMatch",module_pcre_match);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"pcreMatchAll",module_pcre_match_all);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"pcreReplace",module_pcre_replace);
}
