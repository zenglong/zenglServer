/*
 * module_curl.c
 *
 *  Created on: Nov 20, 2018
 *      Author: zengl
 */

#include "module_curl.h"
#include <curl/curl.h>

ZL_EXP_VOID module_curl_version(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, (char *)curl_version(), 0, 0);
}

ZL_EXP_VOID module_curl_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"curlVersion",module_curl_version);
}
