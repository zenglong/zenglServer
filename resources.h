/*
 * resources.h
 *
 *  Created on: 2017-10-5
 *      Author: zengl
 */

#ifndef RESOURCES_H_
#define RESOURCES_H_

#ifndef PTR_NULL
#define PTR_NULL ((void*)0)
#endif

// 自动清理资源的回调函数的函数指针的类型定义
typedef void (*ResourceDestroyCallBack)(void * VM_ARG,void * ptr);

// 资源列表动态数组中包含的每个成员的结构体的类型定义
typedef struct _RESOURCE_LIST_MEMBER {
	void * ptr; // 需要清理的资源指针
	ResourceDestroyCallBack destroy_callback; // 清理资源的回调函数
} RESOURCE_LIST_MEMBER;

// 资源列表相关的结构体的定义
typedef struct _RESOURCE_LIST {
	int count; // list列表中包含的资源数量
	int size;  // list列表当前的容量，当count等于size时，size就会自动增加，并通过size的值，对list数组进行动态扩容
	RESOURCE_LIST_MEMBER * list; // list指针，指向可以动态扩容的数组，数组中的每个成员都是一个RESOURCE_LIST_MEMBER结构体
} RESOURCE_LIST;

/**
 * 向资源列表中添加成员
 * ptr参数表示资源相关的指针，如果ptr资源没有在脚本中被手动清理的话，
 * 那么在脚本退出时，就会自动调用destroy_callback回调函数去清理ptr指针所对应的资源
 */
int resource_list_set_member(RESOURCE_LIST * resource_list, void * ptr, ResourceDestroyCallBack destroy_callback);
/**
 * 将ptr资源指针从资源列表中移除，如果在zengl脚本中手动清理过ptr资源的话，
 * 就需要调用此函数，将指针从资源列表中移除，防止脚本退出时，再次触发清理操作
 */
int resource_list_remove_member(RESOURCE_LIST * resource_list, void * ptr);
/**
 * zengl脚本退出时，会自动调用下面的函数，通过destroy_callback回调函数，来清理所有未清理掉的资源
 */
int resource_list_remove_all_resources(void * VM_ARG, RESOURCE_LIST * resource_list);

#endif /* RESOURCES_H_ */
