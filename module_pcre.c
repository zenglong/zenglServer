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

ZL_EXP_VOID module_pcre_match(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 3)
		zenglApi_Exit(VM_ARG,"usage: pcreMatch(pattern, subject, &result_array[, modifier])");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument [pattern] of pcreMatch must be string");
	}
	char * pattern = arg.val.str;
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [subject] of pcreMatch must be string");
	}
	char * subject = arg.val.str;
	int options = 0;
	if(argcount > 3) {
		zenglApi_GetFunArg(VM_ARG,4,&arg);
		if(arg.type != ZL_EXP_FAT_STR) {
			zenglApi_Exit(VM_ARG,"the fourth argument [modifier] of pcreMatch must be string");
		}
		char * modifier = arg.val.str;
		int modifier_len = strlen(modifier);
		for(int m=0; m < modifier_len;m++) {
			switch(modifier[m]) {
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
	}
	pcre * re;
	const char * error;
	int erroffset;
	re = pcre_compile(pattern, options, &error, &erroffset, NULL);
	if (re == NULL) {
		zenglApi_Exit(VM_ARG,"pcreMatch error, PCRE compilation failed at offset %d: %s", erroffset, error);
	}
	int capture_count = 0;
	int total_count = 1;
	pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &capture_count);
	total_count = (total_count + capture_count) * 3;
	int * ovector = zenglApi_AllocMem(VM_ARG, total_count * sizeof(int));
	int rc, i;
	rc = pcre_exec(re, NULL, subject, strlen(subject), 0, 0, ovector, total_count);
	if(rc < 0) {
		free(re);
		zenglApi_FreeMem(VM_ARG, ovector);
		if(rc == PCRE_ERROR_NOMATCH)
			zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		else
			zenglApi_Exit(VM_ARG,"pcreMatch Matching error %d", rc);
		return;
	}
	ZENGL_EXPORT_MEMBLOCK memblock = {0};
	if(zenglApi_CreateMemBlock(VM_ARG,&memblock,0) == -1) {
		zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
	}
	for (i = 0; i < rc; i++) {
		char * substring_start = subject + ovector[2*i];
		int substring_length = ovector[2*i+1] - ovector[2*i];
		char tmp = substring_start[substring_length];
		substring_start[substring_length] = '\0';
		arg.type = ZL_EXP_FAT_STR;
		arg.val.str = substring_start;
		zenglApi_SetMemBlock(VM_ARG,&memblock,(i + 1),&arg);
		substring_start[substring_length] = tmp;
	}
	zenglApi_GetFunArgInfo(VM_ARG,3,&arg);
	switch(arg.type){
	case ZL_EXP_FAT_ADDR:
	case ZL_EXP_FAT_ADDR_LOC:
	case ZL_EXP_FAT_ADDR_MEMBLK:
		break;
	default:
		zenglApi_Exit(VM_ARG,"the third argument [&result_array] of pcreMatch must be address type");
		break;
	}
	arg.type = ZL_EXP_FAT_MEMBLOCK;
	arg.val.memblock = memblock;
	zenglApi_SetFunArg(VM_ARG,3,&arg);
	free(re);
	zenglApi_FreeMem(VM_ARG, ovector);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, rc, 0);
}

ZL_EXP_VOID module_pcre_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"pcreMatch",module_pcre_match);
}
