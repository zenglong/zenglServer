/*
 * module_request.h
 *
 *  Created on: 2017-6-15
 *      Author: zengl
 */

#ifndef MODULE_REQUEST_H_
#define MODULE_REQUEST_H_

#ifndef ZL_EXP_OS_IN_LINUX
	#define ZL_EXP_OS_IN_LINUX
#endif

#include "zengl/linux/zengl_exportfuns.h"

// request模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
ZL_EXP_VOID module_request_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID);

#endif /* MODULE_REQUEST_H_ */
