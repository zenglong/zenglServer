/*
 * fatal_error_callback.c
 *
 *  Created on: Sep 5, 2020
 *      Author: root
 */

#include "main.h"
#include "fatal_error_callback.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char * call_function_name = NULL;
static char * call_class_name = NULL;

static char * fatal_error_copy_string(char * from, char * to)
{
	if(to != NULL) {
		free(to);
	}
	int from_len = strlen(from);
	if(from_len <= 0)
		return NULL;
	to = malloc(from_len + 1);
	memcpy(to, from, from_len);
	to[from_len] = '\0';
	return to;
}

void fatal_error_set_function_name(char * function_name)
{
	call_function_name = fatal_error_copy_string(function_name, call_function_name);
}

void fatal_error_set_class_name(char * class_name)
{
	call_class_name = fatal_error_copy_string(class_name, call_class_name);
}

int fatal_error_callback_exec(ZL_EXP_VOID * VM, char * script_file, char * fatal_error)
{
	if(call_function_name == NULL) {
		return 0;
	}
	zenglApi_ReUse(VM,0);
	zenglApi_Push(VM,ZL_EXP_FAT_STR,fatal_error,0,0);
	if(zenglApi_Call(VM, script_file, call_function_name, call_class_name) == -1) {
		return -1;
	}
	return 0;
}

void fata_error_free_all_ptrs()
{
	if(call_function_name != NULL) {
		free(call_function_name);
		call_function_name = NULL;
	}
	if(call_class_name != NULL) {
		free(call_class_name);
		call_class_name = NULL;
	}
}
