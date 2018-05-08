/*
 * module_magick.h
 *
 *  Created on: May 27, 2018
 *      Author: zengl
 */

#ifndef MODULE_MAGICK_H_
#define MODULE_MAGICK_H_

#include "common_header.h"

/**
 * 如果使用了MagickWandGenesis初始化MagickWand环境
 * 则在结束时，需要使用MagickWandTerminus来终止MagickWand环境
 * zenglServer会在脚本执行结束时，自动调用下面这个函数来执行终止环境的操作
 */
void export_magick_terminus();

/**
 * magick模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
 */
ZL_EXP_VOID module_magick_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID);

#endif /* MODULE_MAGICK_H_ */
