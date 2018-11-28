/*
 * module_curl.h
 *
 *  Created on: Nov 20, 2018
 *      Author: zengl
 */

#ifndef MODULE_CURL_H_
#define MODULE_CURL_H_

#include "common_header.h"

/**
 * 如果使用了curl_global_init库函数进行过curl的初始化操作，
 * 则在结束时，需要使用curl_global_cleanup库函数来清理掉初始化操作所分配的资源，
 * zenglServer会在脚本执行结束时，自动调用下面这个函数来完成清理操作
 */
void export_curl_global_cleanup();

/**
 * curl模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄(对应的C函数)
 */
ZL_EXP_VOID module_curl_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID);

#endif /* MODULE_CURL_H_ */
