/*
 * dynamic_string.h
 *
 *  Created on: 2017-6-18
 *      Author: zengl
 */

#ifndef DYNAMIC_STRING_H_
#define DYNAMIC_STRING_H_

#ifndef PTR_NULL
#define PTR_NULL ((void*)0)
#endif

#ifndef STR_NULL
#define STR_NULL '\0'
#endif

// 动态字符串相关的结构体的定义
typedef struct _DYNAMIC_STRING{
	int count;   // 动态字符串中的有效字符数
	int size;    // 动态字符串的容量(可以容纳的字符数)，该size可以动态增加大小，从而让动态字符串可以容纳所需的字符
	char * str;  // 指向字符串的起始位置
} DYNAMIC_STRING;

/**
 * 向动态字符串dyn_str中追加append_str字符串，append_str_length表示需要追加的字符串的有效长度，
 * extend_size参数表示动态字符串初始化及动态扩容的大小
 */
int dynamic_string_append(DYNAMIC_STRING * dyn_str, char * append_str, int append_str_length, int extend_size);

// 释放动态字符串
void dynamic_string_free(DYNAMIC_STRING * dyn_str);

#endif /* DYNAMIC_STRING_H_ */
