/*
 * module_request.h
 *
 *  Created on: 2017-6-15
 *      Author: zengl
 */

#ifndef MODULE_REQUEST_H_
#define MODULE_REQUEST_H_

#include "common_header.h"

// 将request模块中的静态函数url_decode转为全局C函数，方便其他C模块直接调用
char * gl_request_url_decode(char * dest, char * src, int src_len);

// request模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
ZL_EXP_VOID module_request_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID);

#endif /* MODULE_REQUEST_H_ */
