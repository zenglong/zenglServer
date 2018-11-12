/*
 * module_pcre.h
 *
 *  Created on: Nov 2, 2018
 *      Author: zengl
 */

#ifndef MODULE_PCRE_H_
#define MODULE_PCRE_H_

#include "common_header.h"

/**
 * pcre模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
 */
ZL_EXP_VOID module_pcre_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID);

#endif /* MODULE_PCRE_H_ */
