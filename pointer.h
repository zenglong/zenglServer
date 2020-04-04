/*
 * pointer.h
 *
 *  Created on: Apr 4, 2020
 *      Author: zengl
 */

#ifndef POINTER_H_
#define POINTER_H_

typedef void (*PointerDestroyCallBack)(void * VM_ARG,void * ptr);

typedef struct _POINTER_LIST_MEMBER {
	void * ptr;
	int ptr_size;
	PointerDestroyCallBack destroy_callback;
} POINTER_LIST_MEMBER;

typedef struct _POINTER_LIST {
	int count;
	int size;
	POINTER_LIST_MEMBER * list;
} POINTER_LIST;

int pointer_list_get_ptr_idx(POINTER_LIST * pointer_list, void * ptr);

int pointer_list_set_member(POINTER_LIST * pointer_list, void * ptr, int ptr_size, PointerDestroyCallBack destroy_callback);

int pointer_list_remove_member(void * VM_ARG, POINTER_LIST * pointer_list, void * ptr, int destroy_ptr);

int pointer_list_remove_all_ptrs(void * VM_ARG, POINTER_LIST * pointer_list);

#endif /* POINTER_H_ */
