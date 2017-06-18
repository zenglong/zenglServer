/*
 * module_request.h
 *
 *  Created on: 2017-6-15
 *      Author: zengl
 */

#ifndef MODULE_REQUEST_H_
#define MODULE_REQUEST_H_

#include "zengl/linux/zengl_exportfuns.h"

ZL_EXP_VOID module_request_GetHeaders(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount);

ZL_EXP_VOID module_request_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID);

#endif /* MODULE_REQUEST_H_ */
