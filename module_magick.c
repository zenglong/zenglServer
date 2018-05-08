/*
 * module_magick.c
 *
 *  Created on: May 27, 2018
 *      Author: zengl
 */

#include "main.h"
#include "module_magick.h"
#include <string.h>
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
	MagickWand * magick_wand = (MagickWand *)ptr;
	DestroyMagickWand(magick_wand);
	write_to_server_log_pipe(WRITE_TO_PIPE, "[debug] DestroyMagickWand: %x\n", magick_wand); // debug
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
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickReadImage",module_magick_read_image);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickGetImageFormat",module_magick_get_image_format);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickGetImageWidth",module_magick_get_image_width);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickGetImageHeight",module_magick_get_image_height);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickResizeImage",module_magick_resize_image);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickWriteImage",module_magick_write_image);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickDestroyWand",module_magick_destroy_wand);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"magickWandTerminus",module_magick_wand_terminus);
}
