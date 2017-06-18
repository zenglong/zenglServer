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

typedef struct _DYNAMIC_STRING{
	int count;
	int size;
	char * str;
} DYNAMIC_STRING;

int dynamic_string_append(DYNAMIC_STRING * dyn_str, char * append_str, int append_str_length, int extend_size);

void dynamic_string_free(DYNAMIC_STRING * dyn_str);

#endif /* DYNAMIC_STRING_H_ */
