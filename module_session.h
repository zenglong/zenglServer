/*
 * module_session.h
 *
 *  Created on: 2017-12-3
 *      Author: zengl
 */

#ifndef MODULE_SESSION_H_
#define MODULE_SESSION_H_

#include "json.h"
#include "common_header.h"

#define SESSION_FILEPATH_MAX_LEN 128

/**
 * 解析json时，自定义的内存分配函数，将使用zenglApi_AllocMem来分配内存
 * 该Api接口分配的内存，如果没有在脚本中手动释放的话，会在脚本结束并关闭虚拟机时，被自动释放掉
 */
void * my_json_mem_alloc(size_t size, int zero, ZL_EXP_VOID * VM_ARG);

/**
 * 解析json时，自定义的内存释放函数，将使用zenglApi_FreeMem接口函数来释放内存
 */
void my_json_mem_free(void * ptr, ZL_EXP_VOID * VM_ARG);

/**
 * 由于json中的字符串是用双引号包起来的，因此，字符串内部的双引号和反斜杠需要进行转义
 */
void session_escape_str(ZL_EXP_VOID * VM_ARG, ZL_EXP_CHAR ** e_str, ZL_EXP_CHAR * s_str);

void process_json_object_array(ZL_EXP_VOID * VM_ARG, ZENGL_EXPORT_MEMBLOCK * memblock, json_value * value,
		unsigned int depth, unsigned int max_depth);

ZL_EXP_VOID module_session_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID);

#endif /* MODULE_SESSION_H_ */
