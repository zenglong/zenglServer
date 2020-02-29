/*
 * module_redis.h
 *
 *  Created on: Feb 22, 2020
 *      Author: zengl
 */

#ifndef MODULE_REDIS_H_
#define MODULE_REDIS_H_

#include "common_header.h"

/**
 * redis模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄(对应的C函数)
 */
ZL_EXP_VOID module_redis_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID);

#endif /* MODULE_REDIS_H_ */
