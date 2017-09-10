/*
 * module_builtin.c
 *
 *  Created on: 2017-7-16
 *      Author: zengl
 */

#include "main.h"
#include "module_builtin.h"
#include <string.h>
#include <stdio.h>

/**
 * bltIterArray模块函数，用于对数组成员进行迭代操作
 * 例如：
 * test['name'] = 'zengl';
 * test['job'] = 'programmer';
 * for(i=0;bltIterArray(test,&i,&k,&v);)
 * 		print k +": " + v + '<br/>';
 * endfor
 * 该脚本在浏览器中的输出结果就是(<br/>会被浏览器做换行处理)：
 * name: zengl
 * job: programmer
 *
 * 上面例子中，该模块函数的第一个参数test，是需要迭代的数组，
 * 第二个参数i是整数类型的变量的引用，用于表示需要访问的成员的索引值，
 * 该函数会将i索引位置处的名值对读取出来并分别设置到k，v参数中，所以k，v参数必须是引用，才能获取到值，
 * 如果i对应的成员是NONE类型(没有被赋予任何值)时，模块函数会跳过i，并自动往后去找有效的成员，
 * 第二个参数i之所以也是引用类型，是因为模块函数在结束时，会将下一次需要访问的索引值赋值给参数i
 *
 * 如果数组里的成员没有对应的key的话，第三个参数就会被设置为成员的整数索引值，例如：
 * test = bltArray('hello', 'world');
 * test[6] = "i'm end";
 * for(i=0;bltIterArray(test,&i,&k,&v);)
 * 		print k +": " + v + '<br/>';
 * endfor
 * 结果就是：
 * 0: hello
 * 1: world
 * 6: i'm end
 * 上面例子中hello成员的索引值为0，world的索引值为1，"i'm end"成员的索引值为6，模块函数会自动跳过索引值为2,3,4,5的成员，
 * 因为这些成员并没有被赋予具体的值，其成员类型是NONE类型
 *
 * 可以只设置三个参数，如果只设置三个参数的话，就只会将数组中的值迭代出来，例如：
 * test['name'] = 'zengl';
 * test['job'] = 'programmer';
 * for(i=0;bltIterArray(test,&i,&v);)
 * 		print v + '<br/>';
 * endfor
 * 结果会是：
 * zengl
 * programmer
 *
 * 当有成员可以进行迭代时，模块函数会返回整数1，否则返回整数0，因此，
 * 上面的for循环就可以根据，该模块函数的返回值来判断是否跳出循环，如果返回0，就跳出循环
 */
ZL_EXP_VOID module_builtin_iterate_array(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	ZL_EXP_BOOL no_index = ZL_EXP_FALSE;
	if(argcount == 3)
		no_index = ZL_EXP_TRUE;
	else if(argcount != 4)
		zenglApi_Exit(VM_ARG,"usage: bltIterArray(array, &index, &[key|curindex], &value) | bltIterArray(array, &index, &value)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	// 如果第一个参数不是数组之类的内存块，则无需迭代，直接返回0
	if(arg.type != ZL_EXP_FAT_MEMBLOCK) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		return;
	}
	ZENGL_EXPORT_MEMBLOCK memblock = {0};
	memblock = arg.val.memblock;

	zenglApi_GetFunArgInfo(VM_ARG,2,&arg);
	switch(arg.type){
	case ZL_EXP_FAT_ADDR:
	case ZL_EXP_FAT_ADDR_LOC:
	case ZL_EXP_FAT_ADDR_MEMBLK:
		break;
	default:
		zenglApi_Exit(VM_ARG,"second argument of bltIterArray must be address type");
		break;
	}

	zenglApi_GetFunArg(VM_ARG,2,&arg);
	if(arg.type != ZL_EXP_FAT_INT)
		zenglApi_Exit(VM_ARG,"second argument value of bltIterArray must be integer");
	ZL_EXP_INT index = (ZL_EXP_INT)arg.val.integer;
	ZENGL_EXPORT_MOD_FUN_ARG mblk_val = {ZL_EXP_FAT_NONE,{0}};
	ZL_EXP_INT size;
	zenglApi_GetMemBlockInfo(VM_ARG,&memblock,&size, ZL_EXP_NULL);
check_index:
	if(index < 0 || index >= size) {
		zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 0, 0);
		return;
	}
	mblk_val = zenglApi_GetMemBlock(VM_ARG,&memblock,index + 1);
	if(mblk_val.type == ZL_EXP_FAT_NONE) {
		index++;
		goto check_index;
	}

	zenglApi_GetFunArgInfo(VM_ARG,3,&arg);
	switch(arg.type){
	case ZL_EXP_FAT_ADDR:
	case ZL_EXP_FAT_ADDR_LOC:
	case ZL_EXP_FAT_ADDR_MEMBLK:
		break;
	default:
		zenglApi_Exit(VM_ARG,"the third argument of bltIterArray must be address type");
		break;
	}

	ZL_EXP_CHAR * key;
	if(no_index == ZL_EXP_FALSE) {
		zenglApi_GetMemBlockHashKey(VM_ARG,&memblock,index,&key);
		if(key != ZL_EXP_NULL) {
			arg.type = ZL_EXP_FAT_STR;
			arg.val.str = key;
			zenglApi_SetFunArg(VM_ARG,3,&arg);
		}
		else {
			arg.type = ZL_EXP_FAT_INT;
			arg.val.integer = index;
			zenglApi_SetFunArg(VM_ARG,3,&arg);
		}

		zenglApi_GetFunArgInfo(VM_ARG,4,&arg);
		switch(arg.type){
		case ZL_EXP_FAT_ADDR:
		case ZL_EXP_FAT_ADDR_LOC:
		case ZL_EXP_FAT_ADDR_MEMBLK:
			break;
		default:
			zenglApi_Exit(VM_ARG,"the forth argument of bltIterArray must be address type");
			break;
		}

		zenglApi_SetFunArg(VM_ARG,4,&mblk_val);
	}
	else {
		zenglApi_SetFunArg(VM_ARG,3,&mblk_val);
	}
	arg.type = ZL_EXP_FAT_INT;
	arg.val.integer = index + 1;
	zenglApi_SetFunArg(VM_ARG,2,&arg);
	zenglApi_SetRetVal(VM_ARG, ZL_EXP_FAT_INT, ZL_EXP_NULL, 1, 0);
}

/**
 * bltWriteFile模块函数，用于将字符串或者指针所指向的数据写入到指定的文件中
 * 例如：
 * body = rqtGetBody(&body_count, &body_source);
 * bltWriteFile('body.log', body);
 * bltWriteFile('body_source.log', body_source, body_count);
 * 该例子中，rqtGetBody会返回请求主体数据的字符串格式，同时将主体数据的字节数及指针值分别写入
 * 到body_count和body_source变量里，当然指针在zengl内部是以和指针长度一致的长整数的形式保存的，
 * 当请求主体数据中只包含字符串时，上面两个bltWriteFile写入文件的数据会是一样的，
 * 当主体数据中还包含了上传的文件时，两者就不一样了，body只会显示字符串能显示的开头的部分，直到被NULL字符阻止，
 * body_source配合body_count则可以将所有主体数据(包括上传的文件的二进制数据)都写入到文件中，
 * 从例子中可以看出，bltWriteFile模块函数既可以写入字符串，也可以写入指针指向的二进制数据，通过
 * 第三个参数可以限制数据写入的长度
 */
ZL_EXP_VOID module_builtin_write_file(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount != 3 && argcount != 2)
		zenglApi_Exit(VM_ARG,"usage: bltWriteFile(filename, [ptr|string], length) | bltWriteFile(filename, string)");
	zenglApi_GetFunArg(VM_ARG,1,&arg);
	if(arg.type != ZL_EXP_FAT_STR) {
		zenglApi_Exit(VM_ARG,"the first argument of bltWriteFile must be string");
	}
	char * filename = arg.val.str;
	zenglApi_GetFunArg(VM_ARG,2,&arg);
	void * ptr = ZL_EXP_NULL;
	char * string = ZL_EXP_NULL;
	if(arg.type == ZL_EXP_FAT_STR) {
		string = arg.val.str;
		ptr = string;
	}
	else if(arg.type == ZL_EXP_FAT_INT) {
		ptr = (void *)arg.val.integer;
	}
	else {
		zenglApi_Exit(VM_ARG,"the second argument of bltWriteFile must be integer or string");
	}
	int length = 0;
	if(argcount == 3) {
		zenglApi_GetFunArg(VM_ARG,3,&arg);
		if(arg.type != ZL_EXP_FAT_INT) {
			zenglApi_Exit(VM_ARG,"the third argument of bltWriteFile must be integer");
		}
		length = (int)arg.val.integer;
	}
	else if(string != ZL_EXP_NULL) {
		length = strlen(string);
	}
	else {
		zenglApi_Exit(VM_ARG,"the length needed by bltWriteFile can't be detected");
	}
	char full_path[FULL_PATH_SIZE];
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	char * right_slash = strrchr(my_data->full_path, '/');
	if(right_slash) {
		int append_length = right_slash - my_data->full_path + 1;
		strncpy(full_path, my_data->full_path, append_length);
		append_length += main_full_path_append(full_path, append_length, FULL_PATH_SIZE, filename);
		full_path[append_length] = '\0';
	}
	else {
		char * webroot = main_get_webroot();
		int append_length = 0;
		append_length += main_full_path_append(full_path, append_length, FULL_PATH_SIZE, webroot);
		if(filename[0] != '/')
			append_length += main_full_path_append(full_path, append_length, FULL_PATH_SIZE, "/");
		append_length += main_full_path_append(full_path, append_length, FULL_PATH_SIZE, filename);
		full_path[append_length] = '\0';
	}
	FILE * fp = fopen(full_path, "wb");
	fwrite(ptr, 1, length, fp);
	fclose(fp);
}

/**
 * builtin模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
 */
ZL_EXP_VOID module_builtin_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltArray",zenglApiBMF_array);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltIterArray",module_builtin_iterate_array);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltWriteFile",module_builtin_write_file);
}
