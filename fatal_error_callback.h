/*
 * fatal_error_callback.h
 *
 *  Created on: Sep 5, 2020
 *      Author: root
 */

#ifndef FATAL_ERROR_CALLBACK_H_
#define FATAL_ERROR_CALLBACK_H_

/**
 * 设置运行时错误回调函数名
 */
void fatal_error_set_function_name(char * function_name);

/**
 * 设置运行时错误回调相关的类名，如果回调函数属于某个类中定义的方法的话，就需要通过此函数来设置回调相关的类名
 */
void fatal_error_set_class_name(char * class_name);

/**
 * 设置运行时错误发生时，需要传递给脚本回调函数的错误信息
 */
void fatal_error_set_error_string(char * error_string);

/**
 * 将运行时错误信息以字符串的形式返回
 */
char * fatal_error_get_error_string();

/**
 * 设置是否需要在命令模式下，执行默认动作，当为0时表示不需要执行默认动作，当不为0时则表示需要执行默认动作
 */
void fatal_error_set_default_cmd_action(int default_cmd_action);

/**
 * 判断是否需要执行默认动作，返回0表示不需要执行默认动作，否则表示需要执行默认动作
 */
int fatal_error_get_default_cmd_action();

/**
 * 当脚本发生严重的运行时错误时，如果脚本中设置了运行时错误回调函数的话，就调用该回调函数来处理运行时错误，
 * 同时会将错误信息和函数栈追踪信息，通过参数传递给回调函数
 */
int fatal_error_callback_exec(void * VM, char * script_file, char * fatal_error);

/**
 * 将运行时错误回调函数名，类名和错误信息相关的字符串给释放掉，同时将回调函数名，类名，错误信息以及是否执行默认动作等重置为默认值
 */
void fata_error_free_all_ptrs();

#endif /* FATAL_ERROR_CALLBACK_H_ */
