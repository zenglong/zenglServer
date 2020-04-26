/*
 * pointer.c
 *
 *  Created on: Apr 4, 2020
 *      Author: zengl
 */

#include "pointer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 指针列表初始化和动态扩容的大小
#define POINTER_EXTEND_SIZE 10

// 指针列表操作时，可能会返回的错误码
typedef enum _POINTER_LIST_ERRORS{
	POINTER_LIST_ERR_INIT_PTR_NOT_NULL = 1,
	POINTER_LIST_ERR_INIT_MALLOC_FAILED,
	POINTER_LIST_ERR_REALLOC_FAILED,
	POINTER_LIST_ERR_NOT_FOUND_EMPTY_PTR,
	POINTER_LIST_ERR_REMOVE_MEMBER_FAILED,
	POINTER_LIST_ERR_PTR_IS_NULL,
	POINTER_LIST_ERR_PTR_SIZE_INVALID,
} POINTER_LIST_ERRORS;

/**
 * 指针列表初始化
 */
static int pointer_list_init(POINTER_LIST * pointer_list)
{
	if(pointer_list->list != NULL) {
		return POINTER_LIST_ERR_INIT_PTR_NOT_NULL;
	}
	pointer_list->size = POINTER_EXTEND_SIZE;
	pointer_list->count = 0;
	pointer_list->list = (POINTER_LIST_MEMBER *)malloc(pointer_list->size * sizeof(POINTER_LIST_MEMBER));
	if(pointer_list->list == NULL) {
		return POINTER_LIST_ERR_INIT_MALLOC_FAILED;
	}
	memset(pointer_list->list, 0, pointer_list->size * sizeof(POINTER_LIST_MEMBER));
	return 0;
}

/**
 * 从指针列表中，获取数据指针对应的列表索引值，如果返回-1表示该指针不存在，是一个无效的数据指针
 */
int pointer_list_get_ptr_idx(POINTER_LIST * pointer_list, void * ptr)
{
	if(!ptr || !pointer_list || !pointer_list->list)
		return -1;
	for(int i = 0; i < pointer_list->size;i++) {
		if(pointer_list->list[i].ptr == ptr) {
			return i;
		}
	}
	return -1;
}

/**
 * 向指针列表中添加成员
 * ptr参数表示数据相关的指针，如果ptr数据指针没有在脚本中被手动清理的话(通过bltFree内建模块函数)，
 * ptr_size参数表示该数据指针所指向的二进制数据的实际的字节大小
 * 那么在脚本退出时，就会自动调用destroy_callback回调函数去释放ptr数据指针所占用的内存空间
 */
int pointer_list_set_member(POINTER_LIST * pointer_list, void * ptr, int ptr_size, PointerDestroyCallBack destroy_callback)
{
	if(ptr == NULL) {
		return POINTER_LIST_ERR_PTR_IS_NULL;
	}
	if(ptr_size <= 0) {
		return POINTER_LIST_ERR_PTR_SIZE_INVALID;
	}
	if(pointer_list->list == NULL) {
		int retval = pointer_list_init(pointer_list);
		if(retval != 0) {
			return retval;
		}
	}
	if(pointer_list->count == pointer_list->size) {
		pointer_list->size += POINTER_EXTEND_SIZE;
		pointer_list->list = (POINTER_LIST_MEMBER *)realloc(pointer_list->list, pointer_list->size * sizeof(POINTER_LIST_MEMBER));
		if(pointer_list->list == NULL)
			return POINTER_LIST_ERR_REALLOC_FAILED;
		memset((pointer_list->list + (pointer_list->size - POINTER_EXTEND_SIZE)), 0, POINTER_EXTEND_SIZE * sizeof(POINTER_LIST_MEMBER));
	}
	int ptr_orig_idx = pointer_list_get_ptr_idx(pointer_list, ptr);
	if(ptr_orig_idx >= 0) {
		pointer_list->list[ptr_orig_idx].ptr_size = ptr_size;
		pointer_list->list[ptr_orig_idx].destroy_callback = destroy_callback;
		return 0;
	}
	for(int i = 0; i < pointer_list->size;i++) {
		if(pointer_list->list[i].ptr == NULL) {
			pointer_list->list[i].ptr = ptr;
			pointer_list->list[i].ptr_size = ptr_size;
			pointer_list->list[i].destroy_callback = destroy_callback;
			pointer_list->count++;
			return 0;
		}
	}
	return POINTER_LIST_ERR_NOT_FOUND_EMPTY_PTR;
}

/**
 * 将ptr数据指针从指针列表中移除，如果要在模块函数中手动清理ptr指针的话，
 * 就需要调用此函数，将指针从指针列表中移除，防止脚本退出时，再次触发清理操作
 * destroy_ptr参数表示是否在移除指针时，调用destroy_callback来释放指针的内存空间
 */
int pointer_list_remove_member(void * VM_ARG, POINTER_LIST * pointer_list, void * ptr, int destroy_ptr)
{
	if(!ptr || !pointer_list)
		return 0;
	if(pointer_list->list == NULL) {
		return 0;
	}
	for(int i = 0; i < pointer_list->size;i++) {
		if(pointer_list->list[i].ptr == ptr) {
			if(destroy_ptr && pointer_list->list[i].destroy_callback != NULL) {
				pointer_list->list[i].destroy_callback(VM_ARG, pointer_list->list[i].ptr);
			}
			pointer_list->list[i].ptr = NULL;
			pointer_list->list[i].ptr_size = 0;
			pointer_list->list[i].destroy_callback = NULL;
			pointer_list->count--;
			return 0;
		}
	}
	return POINTER_LIST_ERR_REMOVE_MEMBER_FAILED;
}

/**
 * zengl脚本退出时，会自动调用下面的函数，通过destroy_callback回调函数，来清理所有未清理掉的数据指针
 */
int pointer_list_remove_all_ptrs(void * VM_ARG, POINTER_LIST * pointer_list)
{
	if(!pointer_list)
		return 0;
	if(pointer_list->list == NULL) {
		return 0;
	}
	if(pointer_list->count == 0) {
		return 0;
	}
	for(int i = 0; i < pointer_list->size;i++) {
		if(pointer_list->list[i].ptr != NULL) {
			if(pointer_list->list[i].destroy_callback != NULL) {
				pointer_list->list[i].destroy_callback(VM_ARG, pointer_list->list[i].ptr);
			}
			pointer_list->count--;
			if(pointer_list->count == 0) {
				break;
			}
		}
	}
	pointer_list->count = pointer_list->size = 0;
	free(pointer_list->list);
	pointer_list->list = NULL;
	return 0;
}
