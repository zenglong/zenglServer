/*
 * module_magick.c
 *
 *  Created on: May 27, 2018
 *      Author: zengl
 */

#include "main.h"
#include "module_magick.h"
#include <string.h>
#include <sys/stat.h>

/**
 * zenglServer使用ImageMagick来操作jpg,png,gif之类的图像
 * ImageMagick的官方网站：www.imagemagick.org
 * 并使用MagickWand封装的API来操作ImageMagick
 * MagickWand对应的网站地址：https://www.imagemagick.org/script/magick-wand.php
 * 目前只支持imagemagick 6的版本，暂不支持imagemagick 7的版本
 */
#include <wand/MagickWand.h>

/**
 * 根据当前执行脚本的目录路径，加上filename文件名，来生成可以被fopen等C库函数使用的路径，定义在module_builtin.c文件中
 */
void builtin_make_fullpath(char * full_path, char * filename, MAIN_DATA * my_data);

static __thread ZL_EXP_BOOL st_is_magick_genesis = ZL_EXP_FALSE;

/**
 * 通过MagickWandGenesis初始化MagickWand环境
 * 在调用MagickWand其他接口之前，需要先使用MagickWandGenesis来初始化环境
 * zenglServer会根据需要自动初始化该环境，因此，脚本中无需手动执行初始化操作
 */
static ZL_EXP_BOOL st_magick_wand_genesis()
{
	if(st_is_magick_genesis == ZL_EXP_FALSE) {
		MagickWandGenesis();
		st_is_magick_genesis = ZL_EXP_TRUE;
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] MagickWandGenesis \n"); // debug
		return ZL_EXP_TRUE;
	}
	else
		return ZL_EXP_FALSE;
}

/**
 * 这是一个和MagickWand相关的资源释放回调函数，由于MagickWand操作图像时，会先通过NewMagickWand得到一个MagickWand实例，
 * 再由该实例去执行各种图像操作，例如，加载图像，调整图像大小等，该实例在创建和使用过程中，会分配内存资源
 * 如果脚本中没有通过magickDestroyWand模块函数手动释放掉这些实例资源的话，zenglServer会在脚本执行结束时，自动通过下面这个回调函数，
 * 以及DestroyMagickWand接口来释放掉NewMagickWand所分配的实例，以防止内存泄露
 * 每个NewMagickWand创建的实例的指针都会存储到zenglServer的资源列表中，这样就可以在脚本执行结束时，检测是否有没有释放掉的实例
 */
static void st_magick_destroy_wand_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	if(ptr != NULL) {
		MagickWand * magick_wand = (MagickWand *)ptr;
		ClearMagickWand(magick_wand);
		DestroyMagickWand(magick_wand);
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] DestroyMagickWand: %x\n", magick_wand); // debug
	}
}

/**
 * DrawingWand相关的资源释放回调函数，当执行图像矢量操作时，例如绘制文字时，需要先分配一个DrawingWand实例，然后使用该实例去执行各种矢量操作。
 * 这些DrawingWand实例会在脚本执行结束时，由zenglServer自动通过下面这个回调函数释放掉
 */
static void st_magick_destroy_drawing_wand_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	if(ptr != NULL) {
		DrawingWand * d_wand = (DrawingWand *)ptr;
		ClearDrawingWand(d_wand);
		DestroyDrawingWand(d_wand);
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] DestroyDrawingWand: %x\n", d_wand); // debug
	}
}

/**
 * PixelWand相关的资源释放回调函数，当执行像素操作时，例如设置颜色时，需要先分配一个PixelWand实例
 * 这些PixelWand实例会在脚本执行结束时，由zenglServer自动通过下面这个函数释放掉
 */
static void st_magick_destroy_pixel_wand_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	if(ptr != NULL) {
		PixelWand * p_wand = (PixelWand *)ptr;
		ClearPixelWand(p_wand);
		DestroyPixelWand(p_wand);
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] DestroyPixelWand: %x\n", p_wand); // debug
	}
}

/**
 * 当使用MagickGetImageBlob这个API获取了图像的二进制数据后，这些二进制数据需要通过MagickRelinquishMemory的API进行清理，
 * 当脚本结束后，zenglServer会自动调用下面这个回调函数对这些二进制资源进行清理
 */
static void st_magick_destroy_image_blob_callback(ZL_EXP_VOID * VM_ARG, void * ptr)
{
	if(ptr != NULL) {
		MagickRelinquishMemory(ptr);
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] DestroyImageBlob: %x\n", ptr); // debug
	}
}

/**
 * 在使用某个MagickWand实例指针执行相关图像操作前，会先通过下面这个函数来检测指针是否是一个有效的实例指针
 * 由于每个新建的实例的指针都会存储到资源列表中，因此，如果在资源列表中找得到该指针，则说明是一个有效的实例指针
 */
static ZL_EXP_BOOL st_is_valid_magick_wand(RESOURCE_LIST * resource_list, void * magick_wand)
{
	int ret = resource_list_get_ptr_idx(resource_list, magick_wand, st_magick_destroy_wand_callback);
	if(ret >= 0)
		return ZL_EXP_TRUE;
	else
		return ZL_EXP_FALSE;
}

/**
 * 在使用DrawingWand实例指针进行矢量操作前，会先通过下面这个函数来检测指针是否是一个有效的DrawingWand实例指针
 * 如果在资源列表中找到了该指针(同时释放回调函数是st_magick_destroy_drawing_wand_callback时)，则说明是一个有效的DrawingWand实例指针
 */
static ZL_EXP_BOOL st_is_valid_drawing_wand(RESOURCE_LIST * resource_list, void * d_wand)
{
	int ret = resource_list_get_ptr_idx(resource_list, d_wand, st_magick_destroy_drawing_wand_callback);
	if(ret >= 0)
		return ZL_EXP_TRUE;
	else
		return ZL_EXP_FALSE;
}

/**
 * 在使用PixelWand实例指针进行像素操作前，会先通过下面这个函数来检测该指针是否是一个有效的PixelWand实例指针
 * 如果在资源列表中找到了该指针(同时释放回调函数是st_magick_destroy_pixel_wand_callback时)，则说明是一个有效的PixelWand实例指针
 */
static ZL_EXP_BOOL st_is_valid_pixel_wand(RESOURCE_LIST * resource_list, void * p_wand)
{
	int ret = resource_list_get_ptr_idx(resource_list, p_wand, st_magick_destroy_pixel_wand_callback);
	if(ret >= 0)
		return ZL_EXP_TRUE;
	else
		return ZL_EXP_FALSE;
}

/**
 * 模块函数会通过下面这个函数来检查提供的指针参数是否是有效的实例指针，如果不是有效的实例指针，则抛出错误
 * 该函数又会通过st_is_valid_magick_wand来进行基础的检测，如果st_is_valid_magick_wand返回0，则抛出错误
 */
static MAIN_DATA * st_assert_magick_wand(ZL_EXP_VOID * VM_ARG, void * magick_wand, const char * module_fun_name)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!st_is_valid_magick_wand(&(my_data->resource_list), magick_wand)) {
		zenglApi_Exit(VM_ARG,"%s runtime error: invalid magick_wand", module_fun_name);
	}
	return my_data;
}

/**
 * 模块函数会通过下面这个函数来检查提供的指针参数是否是有效的DrawingWand实例指针，如果不是有效的实例指针，则抛出错误
 * 该函数又会通过st_is_valid_drawing_wand来进行基础的检测，如果st_is_valid_drawing_wand返回0，则抛出错误
 */
static MAIN_DATA * st_assert_drawing_wand(ZL_EXP_VOID * VM_ARG, void * d_wand, const char * module_fun_name)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!st_is_valid_drawing_wand(&(my_data->resource_list), d_wand)) {
		zenglApi_Exit(VM_ARG,"%s runtime error: invalid drawing wand", module_fun_name);
	}
	return my_data;
}

/**
 * 模块函数会通过下面这个函数来检查提供的指针参数是否是有效的PixelWand实例指针，如果不是有效的实例指针，则抛出错误
 * 该函数又会通过st_is_valid_pixel_wand来进行基础的检测，如果st_is_valid_pixel_wand返回0，则抛出错误
 */
static MAIN_DATA * st_assert_pixel_wand(ZL_EXP_VOID * VM_ARG, void * p_wand, const char * module_fun_name)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	if(!st_is_valid_pixel_wand(&(my_data->resource_list), p_wand)) {
		zenglApi_Exit(VM_ARG,"%s runtime error: invalid pixel wand", module_fun_name);
	}
	return my_data;
}

/**
 * 如果使用了MagickWandGenesis初始化MagickWand环境
 * 则在结束时，需要使用MagickWandTerminus来终止MagickWand环境
 * zenglServer会在脚本执行结束时，自动调用下面这个函数来执行终止环境的操作
 */
void export_magick_terminus()
{
	if(st_is_magick_genesis == ZL_EXP_TRUE) {
		MagickWandTerminus();
		st_is_magick_genesis = ZL_EXP_FALSE;
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] MagickWandTerminus \n"); // debug
	}
}

/**
 * magickWandGenesis模块函数，初始化MagickWand环境
 * 在zengl脚本中无需手动调用该模块函数来执行初始化操作，因为，zenglServer会根据需要自动执行初始化操作
 * 当然也可以手动通过该模块函数来执行初始化，如果手动执行过，则zenglServer就不会再重复执行初始化操作了
 * 因为一旦初始化后，会设置st_is_magick_genesis静态全局变量，如果该变量的值被设置了，就说明已经初始化过了，可以防止重复的初始化操作
 */
ZL_EXP_VOID module_magick_wand_genesis(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	int retval = (int)st_magick_wand_genesis();
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, retval, 0);
}

/**
 * magickNewWand模块函数，新建一个MagickWand实例，并将该实例的指针返回
 * 在执行具体的图像操作之前，需要先新建一个MagickWand实例，因为，大部分图像操作接口都需要接受一个实例指针作为参数
 * 该模块函数在创建了一个实例指针后，还会将该指针存储到资源列表中，这样，其他的图像操作函数在接受到一个实例指针时，
 * 就可以根据该指针是否存在于资源列表中来判断是否是一个有效的实例指针了，并且如果脚本中没有手动释放掉这些实例指针的话，
 * zenglServer还可以从资源列表中将未释放掉的实例指针给自动释放掉
 *
 * magickNewWand模块函数在调用时，不需要提供任何参数，它会将新建好的实例指针以整数的形式作为结果返回
 */
ZL_EXP_VOID module_magick_new_wand(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	st_magick_wand_genesis();
	MagickWand * magick_wand = NewMagickWand();
	write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] NewMagickWand: %x\n", magick_wand); // debug
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)magick_wand, 0);
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int ret_code = resource_list_set_member(&(my_data->resource_list), magick_wand, st_magick_destroy_wand_callback);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "magickNewWand add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
	}
}

/**
 * magickNewDrawingWand模块函数，新建一个DrawingWand实例，并将该实例的指针返回
 * 在执行具体的图像矢量操作之前，需要先新建一个DrawingWand实例，因为，大部分图像矢量操作接口都需要接受一个DrawingWand实例指针作为参数
 * 该模块函数在创建了一个DrawingWand实例指针后，还会将该指针存储到资源列表中，最后将创建好的实例指针以整数的形式作为结果返回
 */
ZL_EXP_VOID module_magick_new_drawing_wand(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	st_magick_wand_genesis();
	DrawingWand * d_wand = NewDrawingWand();
	write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] NewDrawingWand: %x\n", d_wand); // debug
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)d_wand, 0);
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int ret_code = resource_list_set_member(&(my_data->resource_list), d_wand, st_magick_destroy_drawing_wand_callback);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "magickNewDrawingWand add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
	}
}

/**
 * magickNewPixelWand模块函数，新建一个PixelWand实例，并将该实例的指针返回
 * 在执行具体的像素操作之前，需要先新建一个PixelWand实例，因为，大部分像素操作接口都需要接受一个PixelWand实例指针作为参数
 * 该模块函数在创建了一个PixelWand实例指针后，还会将该指针存储到资源列表中，最后将创建好的实例指针以整数的形式作为结果返回
 */
ZL_EXP_VOID module_magick_new_pixel_wand(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	st_magick_wand_genesis();
	PixelWand * p_wand = NewPixelWand();
	write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] NewPixelWand: %x\n", p_wand); // debug
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)p_wand, 0);
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int ret_code = resource_list_set_member(&(my_data->resource_list), p_wand, st_magick_destroy_pixel_wand_callback);
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "magickNewPixelWand add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
	}
}

/**
 * magickPixelSetColor模块，为PixelWand实例设置颜色，PixelWand实例在设置了颜色后，就可以作为其他接口的参数，用作绘图的色彩
 * 该模块函数的第一个参数p_wand必须是一个有效的PixelWand实例指针，第二个参数color是需要设置的颜色的字符串，例如：blue", "#0000ff"等
 * 例如：
 * use magick;
 * wand = magickNewWand();
 * p_wand = magickNewPixelWand();
 * magickPixelSetColor(p_wand, "white");
 * magickNewImage(wand, 85, 30, p_wand);
 * 上面脚本创建了一个宽85像素，高30像素，白色背景的图像
 * 该模块函数最终会通过PixelSetColor的API接口去执行具体的像素操作
 * 该接口的官方文档：https://www.imagemagick.org/api/pixel-wand.php#PixelSetColor
 */
ZL_EXP_VOID module_magick_pixel_set_color(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: magickPixelSetColor(p_wand, color): integer");
	MagickBooleanType retval;
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [p_wand] of magickPixelSetColor must be integer");
	}
	PixelWand * p_wand = (PixelWand *)arg.val.integer;
	st_assert_pixel_wand(VM_ARG, p_wand, "magickPixelSetColor");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [color] of magickPixelSetColor must be string");
	}
	char * color = arg.val.str;
	retval = PixelSetColor(p_wand, (const char *)color);
	if(retval == MagickFalse) {
		ExceptionType severity;
		char * description = PixelGetException(p_wand, &severity);
		write_to_server_log_pipe(WRITE_TO_PIPE, "PixelSetColor failed: %s\n", description);
		description=(char *) MagickRelinquishMemory(description);
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
	}
	else
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
}

/**
 * magickNewImage模块函数，在MagickWand实例中使用指定的尺寸和背景色，创建一个空白的图像画布
 * 该模块函数的第一个参数magick_wand必须是一个有效的MagickWand实例指针，第二个参数width表示创建画布的宽，
 * 第三个参数height表示画布的高，最后一个参数background必须是一个有效的PixelWand实例指针，表示需要创建的画布的背景色
 * 示例代码，参考magickPixelSetColor模块函数的示例代码
 * 该模块函数最终会通过MagickNewImage这个API接口去执行具体的操作
 * 该接口的官方文档：https://www.imagemagick.org/api/magick-image.php#MagickNewImage
 */
ZL_EXP_VOID module_magick_new_image(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 4)
		zenglApi_Exit(VM_ARG,"usage: magickNewImage(magick_wand, width, height, background): integer");
	MagickBooleanType retval;
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [magick_wand] of magickNewImage must be integer");
	}
	MagickWand * magick_wand = (MagickWand *)arg.val.integer;
	MAIN_DATA * my_data = st_assert_magick_wand(VM_ARG, magick_wand, "magickNewImage");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the second argument [width] of magickNewImage must be integer");
	}
	int width = arg.val.integer;
	if(width < 0) {
		width = 0;
	}
	zenglApi_GetFunArg(VM_ARG,3,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the third argument [height] of magickNewImage must be integer");
	}
	int height = arg.val.integer;
	if(height < 0) {
		height = 0;
	}
	zenglApi_GetFunArg(VM_ARG,4,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"The fourth argument [background] of magickNewImage must be integer");
	}
	PixelWand * p_wand = (PixelWand *)arg.val.integer;
	if(!st_is_valid_pixel_wand(&(my_data->resource_list), p_wand)) {
		zenglApi_Exit(VM_ARG,"magickNewImage runtime error: invalid pixel wand");
	}
	retval = MagickNewImage(magick_wand,width,height,p_wand);
	if(retval == MagickFalse) {
		ExceptionType severity;
		char * description=MagickGetException(magick_wand, &severity);
		write_to_server_log_pipe(WRITE_TO_PIPE, "MagickNewImage failed: %s\n", description);
		description=(char *) MagickRelinquishMemory(description);
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
	}
	else
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
}

/**
 * magickSetImageFormat模块函数，设置MagickWand中图像的格式
 * 该模块函数的第一个参数magick_wand必须是一个有效的MagickWand实例指针，第二个参数format表示需要设置的图像格式，例如：png，jpg等
 * 例如：
 * use builtin, magick, request;
 * wand = magickNewWand();
 * p_wand = magickNewPixelWand();
 * magickPixelSetColor(p_wand, "white");
 * magickNewImage(wand, 85, 30, p_wand);
 * magickSetImageFormat(wand, "jpg");
 * output = magickGetImageBlob(wand, &length); // 获取图像的二进制数据
 * rqtSetResponseHeader("Content-Type: image/" + magickGetImageFormat(wand));
 * bltOutputBlob(output, length); // 输出二进制数据
 * 上面代码中，创建了一个白色背景的图像，并将该图像设置为了jpg格式，
 * 最后，获取该图像的jpg格式的二进制数据，并将这些二进制数据输出给浏览器，从而可以在浏览器中看到jpg格式的图片
 * 该模块函数最终会通过MagickSetImageFormat这个接口去执行具体的操作
 * 该接口的官方文档：https://www.imagemagick.org/api/magick-image.php#MagickSetImageFormat
 */
ZL_EXP_VOID module_magick_set_image_format(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: magickSetImageFormat(magick_wand, format): integer");
	MagickBooleanType retval;
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [magick_wand] of magickSetImageFormat must be integer");
	}
	MagickWand * magick_wand = (MagickWand *)arg.val.integer;
	st_assert_magick_wand(VM_ARG, magick_wand, "magickSetImageFormat");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [format] of magickSetImageFormat must be string");
	}
	char * format = arg.val.str;
	retval = MagickSetImageFormat(magick_wand, (const char *)format);
	if(retval == MagickFalse) {
		ExceptionType severity;
		char * description=MagickGetException(magick_wand, &severity);
		write_to_server_log_pipe(WRITE_TO_PIPE, "MagickSetImageFormat failed: %s\n", description);
		description=(char *) MagickRelinquishMemory(description);
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
	}
	else
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
}

/**
 * magickGetImageBlob模块函数，获取图像在指定格式下(jpg, png等格式)的二进制数据
 * 该模块函数的第一个参数magick_wand必须是一个有效的MagickWand实例指针，第二个参数length表示返回的二进制数据的字节大小，必须是引用类型
 * 示例代码，参考magickSetImageFormat模块函数
 * 该模块函数最终会通过MagickGetImageBlob这个接口去执行底层的操作
 * 该接口的官方文档：https://www.imagemagick.org/api/magick-image.php#MagickGetImageBlob
 */
ZL_EXP_VOID module_magick_get_image_blob(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: magickGetImageBlob(magick_wand, &length): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [magick_wand] of magickGetImageBlob must be integer");
	}
	MagickWand * magick_wand = (MagickWand *)arg.val.integer;
	MAIN_DATA * my_data = st_assert_magick_wand(VM_ARG, magick_wand, "magickGetImageBlob");
	zenglApi_GetFunArgInfo(VM_ARG,2,&arg);
	switch(arg.type){
	case ZL_EXP_FAT_ADDR:
	case ZL_EXP_FAT_ADDR_LOC:
	case ZL_EXP_FAT_ADDR_MEMBLK:
		break;
	default:
		zenglApi_Exit(VM_ARG,"the second argument [length] of magickGetImageBlob must be address type");
		break;
	}
	size_t length;
	unsigned char * output = MagickGetImageBlob(magick_wand,&length);
	arg.type = ZL_EXP_FAT_INT;
	arg.val.integer = (ZL_EXP_LONG)length;
	zenglApi_SetFunArg(VM_ARG,2,&arg);
	if(output == NULL) {
		ExceptionType severity;
		char * description=MagickGetException(magick_wand, &severity);
		write_to_server_log_pipe(WRITE_TO_PIPE, "MagickGetImageBlob failed: %s\n", description);
		description=(char *) MagickRelinquishMemory(description);
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
	}
	else {
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] MagickGetImageBlob: %x\n", output); // debug
		int ret_code = resource_list_set_member(&(my_data->resource_list), output, st_magick_destroy_image_blob_callback);
		if(ret_code != 0) {
			zenglApi_Exit(VM_ARG, "magickGetImageBlob add resource to resource_list failed, resource_list_set_member error code:%d", ret_code);
		}
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)output, 0);
	}
}

/**
 * magickDrawSetFont模块函数，设置绘制文字所使用的字体
 * 该模块函数的第一个参数d_wand必须是有效的DrawingWand实例指针，
 * 第二个参数font_name表示需要设置的字体，可以是字体名，例如："Helvetica Regular"，也可以是某个字体文件的相对路径(相对于当前执行脚本的路径)，例如：xerox_serif_narrow.ttf
 * 示例：
 * use magick;
 * def TRUE 1;
 * def FALSE 0;
 * wand = magickNewWand();
 * p_wand = magickNewPixelWand();
 * magickPixelSetColor(p_wand, "white");
 * magickNewImage(wand, 85, 30, p_wand); // 创建一个白色背景的画布
 * d_wand = magickNewDrawingWand();      // 新建一个DrawingWand实例
 * magickDrawSetFont(d_wand, "xerox_serif_narrow.ttf"); // 设置字体
 * magickDrawSetFontSize(d_wand, 24);    // 设置字体大小
 * magickDrawSetTextAntialias(d_wand, TRUE); // 开启抗锯齿(默认情况下就是开启)
 * magickDrawAnnotation(d_wand, 4, 20, "Hello"); // 使用xerox_serif_narrow.ttf对应的字体绘制Hello
 * magickDrawImage(wand, d_wand);        // 将文字信息渲染到画布上
 *
 * 该模块函数最终会通过DrawSetFont这个接口去执行具体的操作
 * 该接口的官方文档：https://www.imagemagick.org/api/drawing-wand.php#DrawSetFont
 */
ZL_EXP_VOID module_magick_draw_set_font(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: magickDrawSetFont(d_wand, font_name): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [d_wand] of magickDrawSetFont must be integer");
	}
	DrawingWand * d_wand = (DrawingWand *)arg.val.integer;
	MAIN_DATA * my_data = st_assert_drawing_wand(VM_ARG, d_wand, "magickDrawSetFont");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [font_name] of magickDrawSetFont must be string");
	}
	char full_path[FULL_PATH_SIZE];
	char * font_name = arg.val.str;
	builtin_make_fullpath(full_path, font_name, my_data);
	struct stat filestatus;
	if ( stat(full_path, &filestatus) == 0) { // 如果存在字体文件，则使用指定的字体文件
		font_name = full_path;
	}
	MagickBooleanType retval;
	retval = DrawSetFont (d_wand, (const char *)font_name);
	if(retval == MagickFalse) {
		ExceptionType severity;
		char * description = DrawGetException(d_wand, &severity);
		write_to_server_log_pipe(WRITE_TO_PIPE, "DrawSetFont failed: %s\n", description);
		description=(char *) MagickRelinquishMemory(description);
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
	}
	else
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
}

/**
 * magickDrawSetFontSize模块函数，设置绘制文字时所使用的字体大小
 * 该模块函数的第一个参数d_wand必须是有效的DrawingWand实例指针，第二个参数pointsize表示需要设置的字体大小
 * 示例代码参考magickDrawSetFont模块函数
 * 该模块函数最终会通过DrawSetFontSize接口去执行具体的操作
 * 该接口的官方文档：https://www.imagemagick.org/api/drawing-wand.php#DrawSetFontSize
 */
ZL_EXP_VOID module_magick_draw_set_font_size(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: magickDrawSetFontSize(d_wand, pointsize): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [d_wand] of magickDrawSetFontSize must be integer");
	}
	DrawingWand * d_wand = (DrawingWand *)arg.val.integer;
	st_assert_drawing_wand(VM_ARG, d_wand, "magickDrawSetFontSize");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	double pointsize = 0;
	switch(arg.type)
	{
	case ZL_EXP_FAT_INT:
		pointsize = (double)arg.val.integer;
		break;
	case ZL_EXP_FAT_FLOAT:
		pointsize = arg.val.floatnum;
		break;
	default:
		zenglApi_Exit(VM_ARG,"the second argument [pointsize] of magickDrawSetFontSize must be integer or float");
		break;
	}
	DrawSetFontSize(d_wand, (const double)pointsize);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
}

/**
 * magickDrawSetTextAntialias模块函数，控制绘制的文本是否是抗锯齿的，默认情况下(没有使用该模块函数的情况下)，文本是抗锯齿的。
 * 该模块函数的第一个参数d_wand必须是有效的DrawingWand实例指针，第二个参数text_antialias是整数类型用于判断是否开启抗锯齿，如果text_antialias不等于0就开启抗锯齿，
 * 如果text_antialias等于0，则关闭抗锯齿。
 * 示例代码参考magickDrawSetFont模块函数
 *
 * magickDrawSetTextAntialias模块函数最终会通过DrawSetTextAntialias接口去执行具体的操作
 * 该接口的官方文档：https://www.imagemagick.org/api/drawing-wand.php#DrawSetTextAntialias
 */
ZL_EXP_VOID module_magick_draw_set_text_antialias(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: magickDrawSetTextAntialias(d_wand, text_antialias): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [d_wand] of magickDrawSetTextAntialias must be integer");
	}
	DrawingWand * d_wand = (DrawingWand *)arg.val.integer;
	st_assert_drawing_wand(VM_ARG, d_wand, "magickDrawSetTextAntialias");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the second argument [text_antialias] of magickDrawSetTextAntialias must be integer");
	}
	int text_antialias = arg.val.integer;
	if(text_antialias != 0) {
		DrawSetTextAntialias(d_wand,MagickTrue);
	}
	else
		DrawSetTextAntialias(d_wand,MagickFalse);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
}

/**
 * magickDrawAnnotation模块函数，绘制文本信息
 * 该模块函数的第一个参数d_wand必须是有效的DrawingWand实例指针，第二个参数x表示要绘制文本的横坐标，第三个参数y表示要绘制的纵坐标，最后一个参数text表示要绘制的文本
 * 例如：magickDrawAnnotation(d_wand, 4, 20, "Hello"); 表示在横坐标为4像素，纵坐标为20像素的位置处绘制文本Hello
 * 该模块函数最终会通过DrawAnnotation这个API接口去执行具体的操作，该接口的官方文档：https://www.imagemagick.org/api/drawing-wand.php#DrawAnnotation
 */
ZL_EXP_VOID module_magick_draw_annotation(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 4)
		zenglApi_Exit(VM_ARG,"usage: magickDrawAnnotation(d_wand, x, y, text): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [d_wand] of magickDrawAnnotation must be integer");
	}
	DrawingWand * d_wand = (DrawingWand *)arg.val.integer;
	st_assert_drawing_wand(VM_ARG, d_wand, "magickDrawAnnotation");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	double x = 0;
	switch(arg.type)
	{
	case ZL_EXP_FAT_INT:
		x = (double)arg.val.integer;
		break;
	case ZL_EXP_FAT_FLOAT:
		x = arg.val.floatnum;
		break;
	default:
		zenglApi_Exit(VM_ARG,"the second argument [x] of magickDrawAnnotation must be integer or float");
		break;
	}
	zenglApi_GetFunArg(VM_ARG,3,&arg);
	double y = 0;
	switch(arg.type)
	{
	case ZL_EXP_FAT_INT:
		y = (double)arg.val.integer;
		break;
	case ZL_EXP_FAT_FLOAT:
		y = arg.val.floatnum;
		break;
	default:
		zenglApi_Exit(VM_ARG,"the third argument [y] of magickDrawAnnotation must be integer or float");
		break;
	}
	zenglApi_GetFunArg(VM_ARG,4,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the fourth argument [text] of magickDrawAnnotation must be string");
	}
	char * text = arg.val.str;
	DrawAnnotation(d_wand, (const double)x, (const double)y, (const unsigned char *)text);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
}

/**
 * magickDrawImage模块函数，将DrawingWand实例中包含的矢量图像信息(例如文本信息等)渲染到MagickWand实例所对应的画布上
 * 该模块函数的第一个参数magick_wand必须是有效的MagickWand实例指针，第二个参数d_wand必须是有效的DrawingWand实例指针
 * 例如：
 * magickDrawAnnotation(d_wand, 4, 20, "Hello"); // 在d_wand中绘制矢量文本
 * magickDrawImage(wand, d_wand);                // 将d_wand包含的矢量文本渲染到wand对应的画布上
 *
 * 该模块函数最终会通过MagickDrawImage这个底层API接口去执行具体的操作，该接口的官方文档：https://www.imagemagick.org/api/magick-image.php#MagickDrawImage
 */
ZL_EXP_VOID module_magick_draw_image(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: magickDrawImage(magick_wand, d_wand): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [magick_wand] of magickDrawImage must be integer");
	}
	MagickWand * magick_wand = (MagickWand *)arg.val.integer;
	MAIN_DATA * my_data = st_assert_magick_wand(VM_ARG, magick_wand, "magickDrawImage");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the second argument [d_wand] of magickDrawImage must be integer");
	}
	DrawingWand * d_wand = (DrawingWand *)arg.val.integer;
	if(!st_is_valid_drawing_wand(&(my_data->resource_list), d_wand)) {
		zenglApi_Exit(VM_ARG,"magickDrawImage runtime error: invalid drawing wand");
	}
	MagickBooleanType retval;
	retval = MagickDrawImage(magick_wand,d_wand);
	if(retval == MagickFalse) {
		ExceptionType severity;
		char * description=MagickGetException(magick_wand, &severity);
		write_to_server_log_pipe(WRITE_TO_PIPE, "MagickDrawImage failed: %s\n", description);
		description=(char *) MagickRelinquishMemory(description);
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
	}
	else
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
}

/**
 * magickSwirlImage模块函数，围绕图像中心旋转像素
 * 该模块函数的第一个参数magick_wand必须是有效的MagickWand实例指针，第二个参数degrees表示旋转的度数，度数越大，旋转效果越明显。
 * 例如：
 * magickSwirlImage(wand, 20); // 将wand对应的画布，围绕中心旋转20度
 *
 * 该模块函数最终会通过底层的API接口MagickSwirlImage去执行具体的操作
 * 该接口的官方文档：https://www.imagemagick.org/api/magick-image.php#MagickSwirlImage
 * 官方文档中的MagickSwirlImage函数原型是ImageMagick 7.x中的版本，在ImageMagick 6.x中，是没有最后一个method参数的
 */
ZL_EXP_VOID module_magick_swirl_image(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: magickSwirlImage(magick_wand, degrees): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [magick_wand] of magickSwirlImage must be integer");
	}
	MagickWand * magick_wand = (MagickWand *)arg.val.integer;
	st_assert_magick_wand(VM_ARG, magick_wand, "magickSwirlImage");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	double degrees = 0;
	switch(arg.type)
	{
	case ZL_EXP_FAT_INT:
		degrees = (double)arg.val.integer;
		break;
	case ZL_EXP_FAT_FLOAT:
		degrees = arg.val.floatnum;
		break;
	default:
		zenglApi_Exit(VM_ARG,"the second argument [degrees] of magickSwirlImage must be integer or float");
		break;
	}
	MagickBooleanType retval;
	retval = MagickSwirlImage(magick_wand, (const double)degrees);
	if(retval == MagickFalse) {
		ExceptionType severity;
		char * description=MagickGetException(magick_wand, &severity);
		write_to_server_log_pipe(WRITE_TO_PIPE, "MagickSwirlImage failed: %s\n", description);
		description=(char *) MagickRelinquishMemory(description);
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
	}
	else
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
}

/**
 * magickClearDrawingWand模块函数，清理与DrawingWand实例相关的资源
 * 该模块函数的第一个参数d_wand必须是有效的DrawingWand实例指针
 * 例如：
 * magickDrawAnnotation(d_wand, 4, 20, "Hello"); // 在d_wand中绘制文本Hello
 * magickDrawImage(wand, d_wand);                // 将文本渲染到wand画布上
 * magickSwirlImage(wand, 20);                   // 将画布中心旋转20度像素，让文本产生扭曲效果
 * magickClearDrawingWand(d_wand);               // 清理d_wand中包含的文本信息
 * magickDrawLine(d_wand, 10, 10, 65, 25);       // 在d_wand中绘制线条
 * magickDrawImage(wand, d_wand);                // 将d_wand中包含的线条渲染到画布上
 * 上面脚本中先使用magickClearDrawingWand模块函数清理掉d_wand中包含的资源(包括之前绘制的文本)，这样，绘制线条时，就不会残留之前绘制的文本信息了
 * 该模块函数最终会通过底层的API接口ClearDrawingWand去执行具体的操作，接口官方文档：https://www.imagemagick.org/api/drawing-wand.php#ClearDrawingWand
 */
ZL_EXP_VOID module_magick_clear_drawing_wand(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: magickClearDrawingWand(d_wand): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [d_wand] of magickClearDrawingWand must be integer");
	}
	DrawingWand * d_wand = (DrawingWand *)arg.val.integer;
	st_assert_drawing_wand(VM_ARG, d_wand, "magickClearDrawingWand");
	ClearDrawingWand(d_wand);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
}

/**
 * magickDrawLine模块函数，根据指定的起始和结束位置，绘制一条直线
 * 该模块函数的第一个参数d_wand必须是有效的DrawingWand实例指针，第二个参数sx表示起始位置的横坐标，第三个参数sy表示起始位置的纵坐标，
 * 第四个参数ex表示结束位置的横坐标，最后一个参数ey表示结束位置的纵坐标
 * 例如：magickDrawLine(d_wand, 10, 10, 65, 25); 表示在(10,10)到(65,25)之间绘制一条直线
 * 该模块函数最终会通过底层API接口DrawLine去执行具体的操作，接口官方文档：https://www.imagemagick.org/api/drawing-wand.php#DrawLine
 */
ZL_EXP_VOID module_magick_draw_line(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 5)
		zenglApi_Exit(VM_ARG,"usage: magickDrawLine(d_wand, sx, sy, ex, ey): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [d_wand] of magickDrawLine must be integer");
	}
	DrawingWand * d_wand = (DrawingWand *)arg.val.integer;
	st_assert_drawing_wand(VM_ARG, d_wand, "magickDrawLine");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	double sx = 0;
	switch(arg.type)
	{
	case ZL_EXP_FAT_INT:
		sx = (double)arg.val.integer;
		break;
	case ZL_EXP_FAT_FLOAT:
		sx = arg.val.floatnum;
		break;
	default:
		zenglApi_Exit(VM_ARG,"the second argument [sx] of magickDrawLine must be integer or float");
		break;
	}
	zenglApi_GetFunArg(VM_ARG,3,&arg);
	double sy = 0;
	switch(arg.type)
	{
	case ZL_EXP_FAT_INT:
		sy = (double)arg.val.integer;
		break;
	case ZL_EXP_FAT_FLOAT:
		sy = arg.val.floatnum;
		break;
	default:
		zenglApi_Exit(VM_ARG,"the third argument [sy] of magickDrawLine must be integer or float");
		break;
	}
	zenglApi_GetFunArg(VM_ARG,4,&arg);
	double ex = 0;
	switch(arg.type)
	{
	case ZL_EXP_FAT_INT:
		ex = (double)arg.val.integer;
		break;
	case ZL_EXP_FAT_FLOAT:
		ex = arg.val.floatnum;
		break;
	default:
		zenglApi_Exit(VM_ARG,"the fourth argument [ex] of magickDrawLine must be integer or float");
		break;
	}
	zenglApi_GetFunArg(VM_ARG,5,&arg);
	double ey = 0;
	switch(arg.type)
	{
	case ZL_EXP_FAT_INT:
		ey = (double)arg.val.integer;
		break;
	case ZL_EXP_FAT_FLOAT:
		ey = arg.val.floatnum;
		break;
	default:
		zenglApi_Exit(VM_ARG,"the fifth argument [ey] of magickDrawLine must be integer or float");
		break;
	}
	DrawLine(d_wand, sx, sy, ex, ey);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
}

/**
 * magickReadImage模块函数，将指定的图像文件加载到MagickWand实例
 * 该模块函数的第一个参数magick_wand需要是一个有效的MagickWand实例指针，第二个参数filename表示需要加载的图像的文件名，该文件名是相对于当前执行脚本的相对路径
 * 例如：
 * use builtin, magick;
 * fun exit(err)
 *	print err;
 *	bltExit();
 * endfun
 * wand = magickNewWand();
 * if(!magickReadImage(wand, 'king.png'))
 *	exit('read king.png failed');
 * endif
 * 上面脚本先通过magickNewWand新建了一个wand实例，接着通过magickReadImage将king.png图像加载到wand实例
 * 接着就可以通过wand实例来操作图像了
 * magickReadImage模块函数在执行成功后会返回1，执行失败会返回0，通常执行失败的原因可能是图像文件不存在，或者加载的文件内容不是一个有效的图像格式，执行失败的具体原因会记录在日志中
 */
ZL_EXP_VOID module_magick_read_image(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: magickReadImage(magick_wand, filename): integer");
	MagickBooleanType status;
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [magick_wand] of magickReadImage must be integer");
	}
	MagickWand * magick_wand = (MagickWand *)arg.val.integer;
	MAIN_DATA * my_data = st_assert_magick_wand(VM_ARG, magick_wand, "magickReadImage");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [filename] of magickReadImage must be string");
	}
	char full_path[FULL_PATH_SIZE];
	char * filename = arg.val.str;
	builtin_make_fullpath(full_path, filename, my_data);
	status = MagickReadImage(magick_wand, full_path);
	if(status == MagickFalse) {
		ExceptionType severity;
		char * description=MagickGetException(magick_wand, &severity);
		write_to_server_log_pipe(WRITE_TO_PIPE, "MagickReadImage failed: %s\n", description);
		description=(char *) MagickRelinquishMemory(description);
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
	}
	else
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
}

/**
 * magickGetImageFormat模块函数，返回MagickWand实例所加载的图像的格式
 * 该模块函数的第一个参数magick_wand需要是一个有效的MagickWand实例指针
 * 例如：
 * use builtin, magick;
 * fun exit(err)
 *	print err;
 *	bltExit();
 * endfun
 * wand = magickNewWand();
 * if(!magickReadImage(wand, 'king.png'))
 *	exit('read king.png failed');
 * endif
 * print 'format: ' + magickGetImageFormat(wand) + '<br/>';
 * 上面脚本的执行结果如下：
 * format: PNG
 * 模块函数会将图像的格式以字符串的形式返回，上面png图像就返回了PNG，如果是jpg图像会返回JPEG等
 */
ZL_EXP_VOID module_magick_get_image_format(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: magickGetImageFormat(magick_wand): integer or string");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [magick_wand] of magickGetImageFormat must be integer");
	}
	MagickWand * magick_wand = (MagickWand *)arg.val.integer;
	st_assert_magick_wand(VM_ARG, magick_wand, "magickGetImageFormat");
	char * format = MagickGetImageFormat(magick_wand);
	if(format == NULL)
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
	else {
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, format, 0, 0);
		MagickRelinquishMemory(format);
	}
}

/**
 * magickGetImageWidth模块函数，返回图像的宽度
 * 该模块函数的第一个参数magick_wand需要是一个有效的MagickWand实例指针
 * 例如：
 * use builtin, magick;
 * fun exit(err)
 *	print err;
 *	bltExit();
 * endfun
 * wand = magickNewWand();
 * if(!magickReadImage(wand, 'king.png'))
 *	exit('read king.png failed');
 * endif
 * print 'width: ' + magickGetImageWidth(wand) + '<br/>';
 * 上面脚本的执行结果如下：
 * width: 450
 * 执行结果说明king.png图像的宽度是450像素
 */
ZL_EXP_VOID module_magick_get_image_width(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: magickGetImageWidth(magick_wand): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [magick_wand] of magickGetImageWidth must be integer");
	}
	MagickWand * magick_wand = (MagickWand *)arg.val.integer;
	st_assert_magick_wand(VM_ARG, magick_wand, "magickGetImageWidth");
	ZL_EXP_LONG width = MagickGetImageWidth(magick_wand);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, width, 0);
}

/**
 * magickGetImageHeight模块函数，返回图像的高度
 * 该模块函数的第一个参数magick_wand需要是一个有效的MagickWand实例指针
 * 例如：
 * use builtin, magick;
 * fun exit(err)
 *	print err;
 *	bltExit();
 * endfun
 * wand = magickNewWand();
 * if(!magickReadImage(wand, 'king.png'))
 *	exit('read king.png failed');
 * endif
 * print 'height: ' + magickGetImageHeight(wand) + '<br/>';
 * 上面脚本的执行结果如下：
 * height: 332
 * 执行结果说明king.png图像的高度是332像素
 */
ZL_EXP_VOID module_magick_get_image_height(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: magickGetImageHeight(magick_wand): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [magick_wand] of magickGetImageHeight must be integer");
	}
	MagickWand * magick_wand = (MagickWand *)arg.val.integer;
	st_assert_magick_wand(VM_ARG, magick_wand, "magickGetImageHeight");
	ZL_EXP_LONG height = MagickGetImageHeight(magick_wand);
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, height, 0);
}

/**
 * magickResizeImage模块函数，将图像缩放到所需的尺寸
 * 该模块函数的第一个参数magick_wand需要是一个有效的MagickWand实例指针，第二个参数width表示需要缩放的宽度，第三个参数height表示需要缩放的高度，
 * 第四个参数filter_type表示缩放操作时，需要使用的滤镜类型，不同的滤镜生成的图像质量和图像体积大小会有所区别
 * 例如：
 * use builtin, magick;
 * fun exit(err)
 *	print err;
 *	bltExit();
 * endfun
 * wand = magickNewWand();
 * if(!magickReadImage(wand, 'king.png'))
 *	exit('read king.png failed');
 * endif
 * if(!magickResizeImage(wand, 200, 150, "LanczosFilter"))
 *	exit('resize king.png failed');
 * endif
 * 上面脚本在执行时，会使用LanczosFilter滤镜将wand加载的图像缩放到200x150尺寸
 * 第四个参数可以是字符串形式的滤镜类型，底层会将字符串映射为同名的enum类型的滤镜值，也可以直接传enum对应的整数值，但是，不同的6.x版本中的enum类型对应的整数值是不同的
 * 传错了整数值，可能会发生段错误，因此，传字符串要保险点。字符串目前只支持通用滤镜类型，所谓通用滤镜类型，是指从6.2的低版本到6.9的高版本中都存在的滤镜类型，高版本中
 * 新增了很多低版本中没有的滤镜类型，要使用这些新增的非通用的滤镜类型，只能传整数值过来
 * 模块函数执行成功会返回整数1，失败则返回整数0，失败的原因会记录到日志中
 */
ZL_EXP_VOID module_magick_resize_image(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 4)
		zenglApi_Exit(VM_ARG,"usage: magickResizeImage(magick_wand, width, height, filter_type): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [magick_wand] of magickResizeImage must be integer");
	}
	MagickWand * magick_wand = (MagickWand *)arg.val.integer;
	st_assert_magick_wand(VM_ARG, magick_wand, "magickResizeImage");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the second argument [width] of magickResizeImage must be integer");
	}
	ZL_EXP_LONG width = arg.val.integer;
	zenglApi_GetFunArg(VM_ARG,3,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the third argument [height] of magickResizeImage must be integer");
	}
	ZL_EXP_LONG height = arg.val.integer;
	char * filter_types_str[] = {
			"UndefinedFilter", "PointFilter", "BoxFilter", "TriangleFilter", "HermiteFilter", "HanningFilter",
			"HammingFilter", "BlackmanFilter", "GaussianFilter", "QuadraticFilter", "CubicFilter", "CatromFilter",
			"MitchellFilter", "LanczosFilter", "BesselFilter", "SincFilter"
	};
	int filter_types_str_len = sizeof(filter_types_str)/sizeof(filter_types_str[0]);
	FilterTypes filter_types_enum[] = {
			UndefinedFilter, PointFilter, BoxFilter, TriangleFilter, HermiteFilter, HanningFilter,
			HammingFilter, BlackmanFilter, GaussianFilter, QuadraticFilter, CubicFilter, CatromFilter,
			MitchellFilter, LanczosFilter, BesselFilter, SincFilter
	};
	FilterTypes filter_type = LanczosFilter; // 默认值
	zenglApi_GetFunArg(VM_ARG,4,&arg);
	if(arg.type == ZL_EXP_FAT_STR) {
		for(int i=0; i < filter_types_str_len; i++) {
			if(filter_types_str[i][0] == arg.val.str[0] &&
				strlen(filter_types_str[i]) == strlen(arg.val.str) &&
				strcmp(filter_types_str[i], arg.val.str) == 0) {
				filter_type = (FilterTypes)filter_types_enum[i];
				break;
			}
		}
	}
	else if(arg.type == ZL_EXP_FAT_INT) {
		filter_type = (FilterTypes)arg.val.integer;
	}
	write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] filter type: %d\n", filter_type); // debug
	MagickBooleanType status = MagickResizeImage(magick_wand, width, height,filter_type,1.0);
	if(status == MagickFalse) {
		ExceptionType severity;
		char * description=MagickGetException(magick_wand, &severity);
		write_to_server_log_pipe(WRITE_TO_PIPE, "MagickResizeImage failed: %s\n", description);
		description=(char *) MagickRelinquishMemory(description);
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
	}
	else
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
}

/**
 * magickWriteImage模块函数，将MagickWand实例中存储的图像写入到指定的文件中
 * 该模块函数的第一个参数magick_wand需要是一个有效的MagickWand实例指针，第二个参数filename表示需要写入的文件名，该文件名是相对于当前执行脚本的路径
 * 例如：
 * use builtin, magick;
 * fun exit(err)
 *	print err;
 *	bltExit();
 * endfun
 * wand = magickNewWand();
 * if(!magickReadImage(wand, 'king.png'))
 *	exit('read king.png failed');
 * endif
 * if(!magickResizeImage(wand, 200, 150, "LanczosFilter"))
 *	exit('resize king.png failed');
 * endif
 * if(!magickWriteImage(wand, 'thumb.jpg'))
 *	exit('write to thumb.jpg failed');
 * endif
 * 上面在执行完缩放操作后，将wand中缩放以后的图像写入到thumb.jpg文件中，从而生成了king.png的缩略图
 * 该模块函数执行成功会返回整数1，执行失败返回整数0，并将失败的原因记录到日志中
 */
ZL_EXP_VOID module_magick_write_image(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 2)
		zenglApi_Exit(VM_ARG,"usage: magickWriteImage(magick_wand, filename): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [magick_wand] of magickWriteImage must be integer");
	}
	MagickWand * magick_wand = (MagickWand *)arg.val.integer;
	MAIN_DATA * my_data = st_assert_magick_wand(VM_ARG, magick_wand, "magickWriteImage");
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the second argument [filename] of magickWriteImage must be string");
	}
	char full_path[FULL_PATH_SIZE];
	char * filename = arg.val.str;
	builtin_make_fullpath(full_path, filename, my_data);
	MagickBooleanType status = MagickWriteImages(magick_wand, full_path, MagickTrue);
	if(status == MagickFalse) {
		ExceptionType severity;
		char * description=MagickGetException(magick_wand, &severity);
		write_to_server_log_pipe(WRITE_TO_PIPE, "magickWriteImage failed: %s\n", description);
		description=(char *) MagickRelinquishMemory(description);
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_FALSE, 0);
	}
	else
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, ZL_EXP_TRUE, 0);
}

/**
 * magickDestroyWand模块函数，注销掉不再使用的MagickWand实例，并释放该实例所占用的内存资源
 * 该模块函数的第一个参数magick_wand需要是一个有效的MagickWand实例指针
 * 当某个实例指针不再需要使用时，可以手动将其释放掉，如果忘了手动调用该模块函数执行释放操作的话，则在脚本结束时，zenglServer会自动根据资源列表将没释放掉的实例指针给释放掉。
 */
ZL_EXP_VOID module_magick_destroy_wand(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: magickDestroyWand(magick_wand): integer");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_INT) {
		zenglApi_Exit(VM_ARG,"the first argument [magick_wand] of magickDestroyWand must be integer");
	}
	MagickWand * magick_wand = (MagickWand *)arg.val.integer;
	MAIN_DATA * my_data = st_assert_magick_wand(VM_ARG, magick_wand, "magickDestroyWand");
	MagickWand * retval = DestroyMagickWand(magick_wand);
	write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] DestroyMagickWand: %x\n", magick_wand); // debug
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, (ZL_EXP_LONG)retval, 0);
	int ret_code = resource_list_remove_member(&(my_data->resource_list), magick_wand); // 将释放掉的实例指针从资源列表中移除
	if(ret_code != 0) {
		zenglApi_Exit(VM_ARG, "magickDestroyWand remove resource from resource_list failed, resource_list_remove_member error code:%d", ret_code);
	}
}

/**
 * magickWandTerminus模块函数，使用MagickWandTerminus接口来终止MagickWand环境
 * 如果初始化过MagickWand环境，那么在结束时，都需要使用MagickWandTerminus接口来终止环境，
 * 如果在脚本中忘了手动调用该模块函数的话，zenglServer会在脚本执行结束时，自动通过上面的export_magick_terminus()函数来执行终止操作
 * 如果模块函数执行了终止操作，则返回1，如果没有执行终止操作，则返回0。没执行终止操作的可能原因是没有初始化过，不需要终止，或者是资源列表中还有没有释放掉的实例指针
 */
ZL_EXP_VOID module_magick_wand_terminus(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	int res_count = resource_list_get_count_by_callback(&(my_data->resource_list), st_magick_destroy_wand_callback);
	if(st_is_magick_genesis == ZL_EXP_TRUE && res_count == 0) {
		MagickWandTerminus();
		st_is_magick_genesis = ZL_EXP_FALSE;
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] MagickWandTerminus \n"); // debug
		zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 1, 0);
		return;
	}
	if(res_count > 0) {
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] have %d wand resource in resource_list, skip MagickWandTerminus \n", res_count); // debug
	}
	else if(!st_is_magick_genesis) {
		write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] MagickWand not init, skip MagickWandTerminus \n", res_count); // debug
	}
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
}

/**
 * magick模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
 */
ZL_EXP_VOID module_magick_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickWandGenesis",module_magick_wand_genesis);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickNewWand",module_magick_new_wand);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickNewDrawingWand",module_magick_new_drawing_wand);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickNewPixelWand",module_magick_new_pixel_wand);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickPixelSetColor",module_magick_pixel_set_color);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickNewImage",module_magick_new_image);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickSetImageFormat",module_magick_set_image_format);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickGetImageBlob",module_magick_get_image_blob);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickDrawSetFont",module_magick_draw_set_font);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickDrawSetFontSize",module_magick_draw_set_font_size);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickDrawSetTextAntialias",module_magick_draw_set_text_antialias);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickDrawAnnotation",module_magick_draw_annotation);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickDrawImage",module_magick_draw_image);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickSwirlImage",module_magick_swirl_image);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickClearDrawingWand",module_magick_clear_drawing_wand);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickDrawLine",module_magick_draw_line);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickReadImage",module_magick_read_image);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickGetImageFormat",module_magick_get_image_format);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickGetImageWidth",module_magick_get_image_width);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickGetImageHeight",module_magick_get_image_height);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickResizeImage",module_magick_resize_image);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickWriteImage",module_magick_write_image);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickDestroyWand",module_magick_destroy_wand);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickWandTerminus",module_magick_wand_terminus);
}
