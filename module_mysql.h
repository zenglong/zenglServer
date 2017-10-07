/*
 * module_builtin.h
 *
 *  Created on: 2017-7-16
 *      Author: zengl
 */

#ifndef MODULE_MYSQL_H_
#define MODULE_MYSQL_H_

#include "common_header.h"

/**
 * mysql模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄(对应的C函数)
 */
ZL_EXP_VOID module_mysql_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID);

#endif /* MODULE_MYSQL_H_ */
