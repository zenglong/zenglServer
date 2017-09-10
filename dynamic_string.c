/*
 * dynamic_string.c
 *
 *  Created on: 2017-6-18
 *      Author: zengl
 */

#include "dynamic_string.h"
#include <string.h>
#include <stdlib.h>

/**
 * 动态字符串的初始化函数，此为static静态函数，由下面的dynamic_string_append函数在动态字符串初始化状态时调用
 */
static int dynamic_string_init(DYNAMIC_STRING * dyn_str, int init_size)
{
	if(dyn_str->str != PTR_NULL){
		return -1;
	}
	dyn_str->size = init_size;
	dyn_str->count = 0;
	dyn_str->str = (char *)malloc(dyn_str->size * sizeof(char));
	if(dyn_str->str == PTR_NULL) {
		return -2;
	}
	return 0;
}

/**
 * 向动态字符串dyn_str中追加append_str字符串，append_str_length表示需要追加的字符串的有效长度，
 * extend_size参数表示动态字符串初始化及动态扩容的大小
 */
int dynamic_string_append(DYNAMIC_STRING * dyn_str, char * append_str, int append_str_length, int extend_size)
{
	if(append_str_length <= 0)
		return 0;
	if(dyn_str->str == PTR_NULL) {
		int ret_val = dynamic_string_init(dyn_str, extend_size);
		if(ret_val < 0)
			return ret_val;
	}
	int total_count = dyn_str->count + append_str_length;
	if(total_count > dyn_str->size) {
		while(1){
			dyn_str->size += extend_size;
			if(total_count < dyn_str->size)
				break;
		}
		dyn_str->str = (char *)realloc(dyn_str->str, dyn_str->size);
		if(dyn_str->str == PTR_NULL)
			return -3;
	}
	memcpy((dyn_str->str + dyn_str->count), append_str, append_str_length);
	dyn_str->count = total_count;
	return 0;
}

/**
 * 释放动态字符串
 */
void dynamic_string_free(DYNAMIC_STRING * dyn_str)
{
	if(dyn_str->str == PTR_NULL) {
		return;
	}
	free(dyn_str->str);
	dyn_str->count = 0;
	dyn_str->size = 0;
}
