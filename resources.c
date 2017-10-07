/*
 * resources.c
 *
 *  Created on: 2017-10-5
 *      Author: zengl
 */

#include "resources.h"
#include <string.h>
#include <stdlib.h>

#define RESOURCE_EXTEND_SIZE 10

// 资源列表操作时，可能会返回的错误码
typedef enum _RESOURCE_LIST_ERRORS{
	RESOURCE_LIST_ERR_INIT_PTR_NOT_NULL = 1,
	RESOURCE_LIST_ERR_INIT_MALLOC_FAILED,
	RESOURCE_LIST_ERR_REALLOC_FAILED,
	RESOURCE_LIST_ERR_NOT_FOUND_EMPTY_PTR,
	RESOURCE_LIST_ERR_REMOVE_MEMBER_FAILED,
} RESOURCE_LIST_ERRORS;

/**
 * 资源列表初始化
 */
static int resource_list_init(RESOURCE_LIST * resource_list)
{
	if(resource_list->list != PTR_NULL) {
		return RESOURCE_LIST_ERR_INIT_PTR_NOT_NULL;
	}
	resource_list->size = RESOURCE_EXTEND_SIZE;
	resource_list->count = 0;
	resource_list->list = (RESOURCE_LIST_MEMBER *)malloc(resource_list->size * sizeof(RESOURCE_LIST_MEMBER));
	if(resource_list->list == PTR_NULL) {
		return RESOURCE_LIST_ERR_INIT_MALLOC_FAILED;
	}
	memset(resource_list->list, 0, resource_list->size * sizeof(RESOURCE_LIST_MEMBER));
	return 0;
}

/**
 * 向资源列表中添加成员
 * ptr参数表示资源相关的指针，如果ptr资源没有在脚本中被手动清理的话，
 * 那么在脚本退出时，就会自动调用destroy_callback回调函数去清理ptr指针所对应的资源
 */
int resource_list_set_member(RESOURCE_LIST * resource_list, void * ptr, ResourceDestroyCallBack destroy_callback)
{
	if(resource_list->list == PTR_NULL) {
		int retval = resource_list_init(resource_list);
		if(retval != 0) {
			return retval;
		}
	}
	if(resource_list->count == resource_list->size) {
		resource_list->size += RESOURCE_EXTEND_SIZE;
		resource_list->list = (RESOURCE_LIST_MEMBER *)realloc(resource_list->list, resource_list->size * sizeof(RESOURCE_LIST_MEMBER));
		if(resource_list->list == PTR_NULL)
			return RESOURCE_LIST_ERR_REALLOC_FAILED;
		memset((resource_list->list + (resource_list->size - RESOURCE_EXTEND_SIZE)), 0, RESOURCE_EXTEND_SIZE * sizeof(RESOURCE_LIST_MEMBER));
	}
	for(int i = 0; i < resource_list->size;i++) {
		if(resource_list->list[i].ptr == PTR_NULL) {
			resource_list->list[i].ptr = ptr;
			resource_list->list[i].destroy_callback = destroy_callback;
			resource_list->count++;
			return 0;
		}
	}
	return RESOURCE_LIST_ERR_NOT_FOUND_EMPTY_PTR;
}

/**
 * 将ptr资源指针从资源列表中移除，如果在zengl脚本中手动清理过ptr资源的话，
 * 就需要调用此函数，将指针从资源列表中移除，防止脚本退出时，再次触发清理操作
 */
int resource_list_remove_member(RESOURCE_LIST * resource_list, void * ptr)
{
	if(!ptr || !resource_list)
		return 0;
	if(resource_list->list == PTR_NULL) {
		return 0;
	}
	for(int i = 0; i < resource_list->size;i++) {
		if(resource_list->list[i].ptr == ptr) {
			resource_list->list[i].ptr = PTR_NULL;
			resource_list->list[i].destroy_callback = PTR_NULL;
			resource_list->count--;
			return 0;
		}
	}
	return RESOURCE_LIST_ERR_REMOVE_MEMBER_FAILED;
}

/**
 * zengl脚本退出时，会自动调用下面的函数，通过destroy_callback回调函数，来清理所有未清理掉的资源
 */
int resource_list_remove_all_resources(void * VM_ARG, RESOURCE_LIST * resource_list)
{
	if(!resource_list)
		return 0;
	if(resource_list->list == PTR_NULL) {
		return 0;
	}
	if(resource_list->count == 0) {
		return 0;
	}
	for(int i = 0; i < resource_list->size;i++) {
		if(resource_list->list[i].ptr != PTR_NULL && resource_list->list[i].destroy_callback != PTR_NULL) {
			resource_list->list[i].destroy_callback(VM_ARG, resource_list->list[i].ptr);
			resource_list->count--;
			if(resource_list->count == 0) {
				break;
			}
		}
	}
	resource_list->count = resource_list->size = 0;
	free(resource_list->list);
	resource_list->list = PTR_NULL;
	return 0;
}
