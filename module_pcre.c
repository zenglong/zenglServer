/*
 * module_pcre.c
 *
 *  Created on: Nov 2, 2018
 *      Author: zengl
 */

#include "module_pcre.h"
#include <pcre.h>
#include <stdlib.h>
#include <string.h>

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

ZL_EXP_VOID module_pcre_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"pcreMatch",module_pcre_match);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"pcreMatchAll",module_pcre_match_all);
}
