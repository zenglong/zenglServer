/*
 * module_builtin.h
 *
 *  Created on: 2017-7-16
 *      Author: zengl
 */

#ifndef MODULE_BUILTIN_H_
#define MODULE_BUILTIN_H_

#include "common_header.h"

typedef struct _builtin_mustache_context builtin_mustache_context;

struct _builtin_mustache_context {
	ZENGL_EXPORT_MOD_FUN_ARG ctx;
};

/**
 * builtin模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
 */
ZL_EXP_VOID module_builtin_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID);

#endif /* MODULE_BUILTIN_H_ */
