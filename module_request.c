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
		if(zenglApi_CreateMemBlock(VM_ARG,&my_data->headers_memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
		zenglApi_AddMemBlockRefCount(VM_ARG,&my_data->headers_memblock,1); // 手动增加该内存块的引用计数值，使其不会在脚本函数返回时，被释放掉。
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
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	MY_PARSER_DATA * my_parser_data = my_data->my_parser_data;

	if(my_parser_data->request_body.str != PTR_NULL && my_parser_data->request_body.count > 0) {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, my_parser_data->request_body.str, 0, 0);
	}
	else {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, "", 0, 0);
	}
}

ZL_EXP_VOID module_request_GetQueryAsString(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	MY_PARSER_DATA * my_parser_data = my_data->my_parser_data;
	struct http_parser_url * url_parser = &my_parser_data->url_parser;

	if((url_parser->field_set & (1 << UF_QUERY)) && (url_parser->field_data[UF_QUERY].len > 0)) {
		ZL_EXP_INT end_pos = url_parser->field_data[UF_QUERY].off + url_parser->field_data[UF_QUERY].len;
		ZL_EXP_CHAR orig_char = my_parser_data->request_url.str[end_pos];
		my_parser_data->request_url.str[end_pos] = STR_NULL;
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, my_parser_data->request_url.str + url_parser->field_data[UF_QUERY].off, 0, 0);
		if(orig_char != STR_NULL) {
			my_parser_data->request_url.str[end_pos] = orig_char;
		}
	}
	else {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, "", 0, 0);
	}
}

ZL_EXP_VOID module_request_GetQuery(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	MY_PARSER_DATA * my_parser_data = my_data->my_parser_data;
	struct http_parser_url * url_parser = &my_parser_data->url_parser;

	if(my_data->query_memblock.ptr == ZL_EXP_NULL) {
		if(zenglApi_CreateMemBlock(VM_ARG,&my_data->query_memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
		zenglApi_AddMemBlockRefCount(VM_ARG,&my_data->query_memblock,1); // 手动增加该内存块的引用计数值，使其不会在脚本函数返回时，被释放掉。
		if((url_parser->field_set & (1 << UF_QUERY)) && (url_parser->field_data[UF_QUERY].len > 0)) {
			ZL_EXP_CHAR * q = my_parser_data->request_url.str + url_parser->field_data[UF_QUERY].off;
			ZL_EXP_INT q_len = url_parser->field_data[UF_QUERY].len;
			ZL_EXP_INT k = -1;
			ZL_EXP_INT v = -1;
			for(ZL_EXP_INT i = 0; i <= q_len; i++) {
				if(k == -1 && q[i] != '=' && q[i] != '&') {
					k = i;
				}
				switch(q[i]) {
				case '=':
					v = i + 1;
					break;
				case '&':
				case '#':
				case STR_NULL:
					if(k >= 0 && v > 0) {
						ZL_EXP_CHAR prev_v_char = q[v - 1];
						ZL_EXP_CHAR current_char = q[i];
						q[i] = q[v - 1] = STR_NULL;
						arg.type = ZL_EXP_FAT_STR;
						arg.val.str = &q[v];
						zenglApi_SetMemBlockByHashKey(VM_ARG, &my_data->query_memblock, &q[k], &arg);
						q[v - 1] = prev_v_char;
						if(current_char != STR_NULL)
							q[i] = current_char;
						k = v = -1;
					}
					else {
						k = v = -1;
					}
					break;
				}
			}
		}
		zenglApi_SetRetValAsMemBlock(VM_ARG,&my_data->query_memblock);
	}
	else {
		zenglApi_SetRetValAsMemBlock(VM_ARG,&my_data->query_memblock);
	}
}

ZL_EXP_VOID module_request_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetHeaders",module_request_GetHeaders);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetBody",module_request_GetBody);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetQueryAsString",module_request_GetQueryAsString);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"rqtGetQuery",module_request_GetQuery);
}
