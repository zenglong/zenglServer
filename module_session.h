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

void process_json_object_array(ZL_EXP_VOID * VM_ARG, ZENGL_EXPORT_MEMBLOCK * memblock, json_value * value);

ZL_EXP_VOID module_session_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID);

#endif /* MODULE_SESSION_H_ */
