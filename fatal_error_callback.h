/*
 * fatal_error_callback.h
 *
 *  Created on: Sep 5, 2020
 *      Author: root
 */

#ifndef FATAL_ERROR_CALLBACK_H_
#define FATAL_ERROR_CALLBACK_H_

void fatal_error_set_function_name(char * function_name);

void fatal_error_set_class_name(char * class_name);

int fatal_error_callback_exec(void * VM, char * script_file, char * fatal_error);

void fata_error_free_all_ptrs();

#endif /* FATAL_ERROR_CALLBACK_H_ */
