/*
 * module_request.c
 *
 *  Created on: 2017-6-15
 *      Author: zengl
 */

#include "main.h"
#include "module_request.h"
#include <string.h>

ZL_EXP_VOID module_request_GetHeaders(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	MY_PARSER_DATA * my_parser_data = my_data->my_parser_data;

	if(my_data->headers_memblock.ptr == ZL_EXP_NULL) {
		// TODO CreateMemBlock创建的内存块，refcount默认为0，有可能导致内存块被释放掉，因此，后期需要对内存块的有效性进行检测，或者直接在此处通过别的接口将refcount设置为大于0的值，让该内存块被创建后能够一直存在。
		if(zenglApi_CreateMemBlock(VM_ARG,&my_data->headers_memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
		if(my_parser_data->request_header.str != PTR_NULL && my_parser_data->request_header.count > 0) {
			ZL_EXP_CHAR * tmp = my_parser_data->request_header.str;
			ZL_EXP_CHAR * end = my_parser_data->request_header.str + my_parser_data->request_header.count;
			do{
				ZL_EXP_CHAR * field = tmp;
				ZL_EXP_CHAR * value = field + strlen(field) + 1;
				if(field >= end || value >= end) {
					break;
				}
				arg.type = ZL_EXP_FAT_STR;
				arg.val.str = value;
				zenglApi_SetMemBlockByHashKey(VM_ARG, &my_data->headers_memblock, field, &arg);
				tmp = value + strlen(value) + 1;
			}while(1);
		}
		zenglApi_SetRetValAsMemBlock(VM_ARG,&my_data->headers_memblock);
	}
	else {
		zenglApi_SetRetValAsMemBlock(VM_ARG,&my_data->headers_memblock);
	}
}

ZL_EXP_VOID module_request_GetBody(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	MY_PARSER_DATA * my_parser_data = my_data->my_parser_data;

	if(my_parser_data->request_body.str != PTR_NULL && my_parser_data->request_body.count > 0) {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, my_parser_data->request_body.str, 0, 0);
	}
	else {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, "", 0, 0);
	}
}

ZL_EXP_VOID module_request_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetHeaders",module_request_GetHeaders);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetBody",module_request_GetBody);
}
