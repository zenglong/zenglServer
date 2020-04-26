/*
 * pointer.h
 *
 *  Created on: Apr 4, 2020
 *      Author: zengl
 */

#ifndef POINTER_H_
#define POINTER_H_

// 自动清理数据指针的回调函数的函数指针的类型定义
typedef void (*PointerDestroyCallBack)(void * VM_ARG,void * ptr);

// 指针列表动态数组中包含的每个成员的结构体的类型定义
typedef struct _POINTER_LIST_MEMBER {
	void * ptr;    // 数据指针
	int ptr_size;  // 数据指针所指向的二进制数据的字节大小
	PointerDestroyCallBack destroy_callback; // 用于清理数据指针的回调函数
} POINTER_LIST_MEMBER;

// 指针列表相关的结构体的定义
typedef struct _POINTER_LIST {
	int count; // list列表中包含的指针数量
	int size;  // list列表当前的容量，当count等于size时，size就会自动增加，并通过size的值，对list数组进行动态扩容
	POINTER_LIST_MEMBER * list; // list指针，指向可以动态扩容的数组，数组中的每个成员都是一个POINTER_LIST_MEMBER结构体
} POINTER_LIST;

/**
 * 从指针列表中，获取数据指针对应的列表索引值，如果返回-1表示该指针不存在，是一个无效的数据指针
 */
int pointer_list_get_ptr_idx(POINTER_LIST * pointer_list, void * ptr);

/**
 * 向指针列表中添加成员
 * ptr参数表示数据相关的指针，如果ptr数据指针没有在脚本中被手动清理的话(通过bltFree内建模块函数)，
 * ptr_size参数表示该数据指针所指向的二进制数据的实际的字节大小
 * 那么在脚本退出时，就会自动调用destroy_callback回调函数去释放ptr数据指针所占用的内存空间
 */
int pointer_list_set_member(POINTER_LIST * pointer_list, void * ptr, int ptr_size, PointerDestroyCallBack destroy_callback);

/**
 * 将ptr数据指针从指针列表中移除，如果要在模块函数中手动清理ptr指针的话，
 * 就需要调用此函数，将指针从指针列表中移除，防止脚本退出时，再次触发清理操作
 * destroy_ptr参数表示是否在移除指针时，调用destroy_callback来释放指针的内存空间
 */
int pointer_list_remove_member(void * VM_ARG, POINTER_LIST * pointer_list, void * ptr, int destroy_ptr);

/**
 * zengl脚本退出时，会自动调用下面的函数，通过destroy_callback回调函数，来清理所有未清理掉的数据指针
 */
int pointer_list_remove_all_ptrs(void * VM_ARG, POINTER_LIST * pointer_list);

#endif /* POINTER_H_ */
