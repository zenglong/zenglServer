/*
 * module_builtin.c
 *
 *  Created on: 2017-7-16
 *      Author: zengl
 */

#include "main.h"
#include "module_builtin.h"
/**
 * zenglServer通过crustache第三方库来解析mustache模板
 * crustache的github地址：https://github.com/vmg/crustache
 * mustache模板：https://mustache.github.io/
 * mustache模板的基本语法：https://mustache.github.io/mustache.5.html
 * 作者对crustache库代码做了一些修改(包括修复其中的bug)
 */
#include "crustache/crustache.h"
#include "crustache/buffer.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

static int builtin_crustache__context_get(
		ZL_EXP_VOID * VM_ARG,
		builtin_mustache_context * new_context,
		crustache_var *var, void *ctx, const char *key, size_t key_size);

static int builtin_crustache__list_get(
		ZL_EXP_VOID * VM_ARG,
		builtin_mustache_context * new_context,
		crustache_var *var, void *list, size_t i);

static int builtin_crustache__partial(ZL_EXP_VOID * VM_ARG, crustache_template **partial, char * partial_name, size_t name_size);

/**
 * crustache第三方库在解析mustache模板时，会调用的回调函数(回调函数定义在builtin模块中)
 */
crustache_api builtin_crustache__default_api = {
	builtin_crustache__context_get, // 从哈希数组之类的上下文中根据字符串key来获取对应的值的回调函数
	builtin_crustache__list_get,    // 从非哈希数组中，根据整数索引值来获取对应的值的回调函数
	NULL,
	NULL,
	builtin_crustache__partial,     // 解析partial模板语法时，会调用的回调函数
	ZL_EXP_TRUE
};

/**
 * 根据当前执行脚本的目录路径，加上filename文件名，来生成可以被fopen等C库函数使用的路径
 */
static void builtin_make_fullpath(char * full_path, char * filename, MAIN_DATA * my_data)
{
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
}

/**
 * 根据full_path文件路径来获取文件的内容
 */
static char * builtin_get_file_content(ZL_EXP_VOID * VM_ARG, char * full_path, char * api_name, int * arg_file_size)
{
	struct stat filestatus;
	if ( stat(full_path, &filestatus) != 0)
		zenglApi_Exit(VM_ARG,"%s stat file \"%s\" failed [%d] %s",api_name, full_path, errno, strerror(errno));
	int file_size = filestatus.st_size;
	FILE * fp = fopen(full_path, "rb");
	if (fp == NULL)
		zenglApi_Exit(VM_ARG,"%s open file \"%s\" failed [%d] %s",api_name, full_path, errno, strerror(errno));
	char * file_contents = (char *)zenglApi_AllocMem(VM_ARG, file_size + 1);
	int nread = fread(file_contents, file_size, 1, fp);
	if ( nread != 1 ) {
		fclose(fp);
		zenglApi_Exit(VM_ARG,"%s error: Unable t read content of \"%s\"", api_name, full_path);
	}
	fclose(fp);
	file_contents[file_size] = '\0';
	if(arg_file_size != NULL) {
		(*arg_file_size) = file_size;
	}
	return file_contents;
}

/**
 * 通过crustache_new第三方库函数，新建一个crustache模板
 * crustache_new会根据file_contents模板文件的内容，对其进行模板语法解析
 * 如果crustache_new返回的error的值小于0，则说明有语法错误
 * 当有语法错误时，就通过crustache_error_syntaxline，crustache_strerror之类的库函数
 * 获取具体出错的行，以及出错的原因，再将这些错误信息写入到日志中，并退出脚本
 * 如果没有语法错误，就将创建的crustache_template结构体的指针返回
 * crustache_template结构体定义在crustache目录中的crustache.c文件中
 */
static crustache_template * builtin_crustache_new_template(
		ZL_EXP_VOID * VM_ARG,
		char * file_contents,
		char * api_name,
		int file_size,
		char * full_path)
{
	crustache_template * template;
	int error = crustache_new(
			VM_ARG,
			&template,
			&builtin_crustache__default_api,
			file_contents,
			file_size);
	if (error < 0)
	{
		const char *error_line;
		size_t line_len, line_n, col_n;
		error_line = crustache_error_syntaxline(&line_n, &col_n, &line_len, template);
		char * alloc_error_str = (char *)zenglApi_AllocMem(VM_ARG, line_len + 1);
		memcpy(alloc_error_str, error_line, line_len);
		alloc_error_str[line_len] = '\0';
		if(col_n > (line_len + 1))
			col_n = line_len + 1;
		if(col_n < 1)
			col_n = 1;
		crustache_free(template);
		//zenglApi_Exit(VM_ARG, "%s error: %s (line %d, col %d)\n\t%.*s\n\t%*s\n", api_name,
		zenglApi_Exit(VM_ARG, "%s [%s] error: %s (line %d, col %d)\n\t...%s\n\t%*s\n", api_name, full_path,
				(char *)crustache_strerror(error), (int)line_n, (int)col_n,
				&alloc_error_str[col_n-1],
				4, "^");
				//(int)line_len, alloc_error_str);
				//(int)col_n, "^");
	}
	return template;
}

/**
 * 从哈希数组之类的上下文中根据字符串key来获取对应的值的回调函数
 * 例如：
 * <p><b>score: {{ score }}</b></p>
 * <p><b>money: {{ money }}$</b></p>
 * crustache在渲染{{ score }}时
 * 会调用下面这个回调函数，从上下文对应的哈希数组中根据"score"这个key去获取对应的值，并将该值渲染出来
 * 渲染{{ money }}时，则根据"money"这个key去获取相应的值进行渲染
 */
static int builtin_crustache__context_get(
		ZL_EXP_VOID * VM_ARG,
		builtin_mustache_context * new_context,
		crustache_var *var,
		void *ctx,
		const char * key,
		size_t key_size)
{
	builtin_mustache_context * context = (builtin_mustache_context *)ctx;
	switch(context->ctx.type) {
	case ZL_EXP_FAT_MEMBLOCK: // 从哈希数组中根据key来获取对应的值
		{
			char * mblk_key = (char *)key;
			char tmp = mblk_key[key_size];
			mblk_key[key_size] = '\0';
			ZENGL_EXPORT_MOD_FUN_ARG mblk_value = zenglApi_GetMemBlockByHashKey(VM_ARG, &context->ctx.val.memblock, mblk_key);
			mblk_key[key_size] = tmp;
			switch(mblk_value.type){
			case ZL_EXP_FAT_STR:
				var->type = CRUSTACHE_VAR_STR;
				var->data = (void *)mblk_value.val.str;
				var->size = strlen(mblk_value.val.str);
				break;
			case ZL_EXP_FAT_INT:
				var->type = CRUSTACHE_VAR_INTEGER;
				var->data = (void *)(&mblk_value.val.integer);
				var->size = sizeof(mblk_value.val.integer);
				break;
			case ZL_EXP_FAT_FLOAT:
				var->type = CRUSTACHE_VAR_FLOAT;
				var->data = (void *)(&mblk_value.val.floatnum);
				var->size = sizeof(mblk_value.val.floatnum);
				break;
			case ZL_EXP_FAT_MEMBLOCK: // 如果值本身又是一个数组，则将该数组作为新的上下文，可以用于渲染模板中的section
				{
					ZL_EXP_INT size;
					ZL_EXP_INT nncount;
					zenglApi_GetMemBlockInfo(VM_ARG, &mblk_value.val.memblock, &size, ZL_EXP_NULL);
					nncount = zenglApi_GetMemBlockNNCount(VM_ARG, &mblk_value.val.memblock);
					if(new_context != NULL) {
						new_context->ctx = mblk_value;
						zenglApi_GetMemBlockHashKey(VM_ARG, &mblk_value.val.memblock, 0,&mblk_key);
						if(mblk_key != ZL_EXP_NULL)
							var->type = CRUSTACHE_VAR_CONTEXT; // 包含字符串key的哈希数组
						else
							var->type = CRUSTACHE_VAR_LIST; // 只包含整数索引值的数组
						var->data = (void *)new_context;
						var->size = size;
						var->nncount = nncount; // 记录数组中包含的非NONE成员的数量
						return 0;
					}
					else
						return -1;
				}
				break;
			default:
				return -1;
			}
		}
		break;
	case ZL_EXP_FAT_INT: // 如果上下文是整数，则将{{ . }}渲染为当前整数的值
		{
			if(key_size == 1 && key[0] == '.') {
				var->type = CRUSTACHE_VAR_INTEGER;
				var->data = (void *)(&context->ctx.val.integer);
				var->size = sizeof(context->ctx.val.integer);
			}
			else
				return -1;
		}
		break;
	case ZL_EXP_FAT_FLOAT: // 如果上下文是浮点数，则将{{ . }}渲染为当前浮点数的值
		{
			if(key_size == 1 && key[0] == '.') {
				var->type = CRUSTACHE_VAR_FLOAT;
				var->data = (void *)(&context->ctx.val.floatnum);
				var->size = sizeof(context->ctx.val.floatnum);
			}
			else
				return -1;
		}
		break;
	case ZL_EXP_FAT_STR: // 如果上下文是字符串，则将{{ . }}渲染为当前字符串的值
		{
			if(key_size == 1 && key[0] == '.') {
				var->type = CRUSTACHE_VAR_STR;
				var->data = (void *)context->ctx.val.str;
				var->size = strlen(context->ctx.val.str);
			}
			else
				return -1;
		}
		break;
	default:
		return -1;
	}
	return 0;
}

/**
 * 从非哈希数组中，根据整数索引值来获取对应的值的回调函数
 */
static int builtin_crustache__list_get(
	ZL_EXP_VOID * VM_ARG,
	builtin_mustache_context * new_context,
	crustache_var *var,
	void *list,
	size_t i)
{
	builtin_mustache_context * context = (builtin_mustache_context *)list;
	ZENGL_EXPORT_MOD_FUN_ARG mblk_val;
	mblk_val = zenglApi_GetMemBlock(VM_ARG, &context->ctx.val.memblock, i+1);
	// 将值封装为新的上下文，用于渲染section中的模板内容
	switch(mblk_val.type) {
	case ZL_EXP_FAT_INT:
	case ZL_EXP_FAT_FLOAT:
	case ZL_EXP_FAT_STR:
	case ZL_EXP_FAT_MEMBLOCK:
		{
			if(new_context != NULL) {
				new_context->ctx = mblk_val;
				var->type = CRUSTACHE_VAR_CONTEXT;
				var->data = (void *)new_context;
				return 0;
			}
		}
		break;
	}
	return -1;
}

/**
 * 解析partial模板语法时，会调用的回调函数
 * 例如：
 * {{> header.tpl}}
 * 在渲染时，就会调用下面这个回调函数，将header.tpl子模板的内容读取并解析出来
 */
static int builtin_crustache__partial(ZL_EXP_VOID * VM_ARG, crustache_template **partial, char * partial_name, size_t name_size)
{
	char full_path[FULL_PATH_SIZE];
	if(name_size == 0)
		return -1;
	char tmp = partial_name[name_size];
	char * api_name = "bltMustacheFileRender";
	int file_size;
	partial_name[name_size] = '\0';
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	builtin_make_fullpath(full_path, partial_name, my_data);
	partial_name[name_size] = tmp;
	char * file_contents = builtin_get_file_content(VM_ARG, full_path, api_name, &file_size);
	(*partial) = builtin_crustache_new_template(VM_ARG, file_contents, api_name, file_size, full_path);
	zenglApi_FreeMem(VM_ARG, file_contents);
	return 0;
}

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
	builtin_make_fullpath(full_path, filename, my_data);
	FILE * fp = fopen(full_path, "wb");
	fwrite(ptr, 1, length, fp);
	fclose(fp);
}

/*bltExit模块函数，直接退出zengl脚本*/
ZL_EXP_VOID module_builtin_exit(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount > 0)
	{
		zenglApi_GetFunArg(VM_ARG,1,&arg); //得到第一个参数
		if(arg.type != ZL_EXP_FAT_STR)
		{
			zenglApi_Exit(VM_ARG,"first argument of bltExit must be string");
		}
		zenglApi_Exit(VM_ARG,arg.val.str);
	}
	else
	{
		zenglApi_Stop(VM_ARG); //如果没有参数则直接停止脚本的执行，不会产生出错信息
		return;
	}
}

/**
 * bltMustacheFileRender模块函数，渲染mustache模板
 * filename参数表示模板文件名(可以是相对于当前执行脚本的相对路径)，可选的array参数表示需要在模板中渲染的数据(一个哈希数组)
 * 例如：
 * use builtin;
 * data["val"] = "my world!";
 * data["zl"] = "welcome to zengl!";
 * schools[] = '哈佛大学';
 * schools[] = '牛津大学';
 * schools[] = '家里蹲大学';
 * data['schools'] = schools;
 * print bltMustacheFileRender("test.tpl",data);
 * 假设模板文件test.tpl的内容如下：
 * <b>hello {{val}}!</b>
 * <h3>{{ zl }}</h3>
 * {{# schools}} {{! 循环将schools里的成员显示出来}}
 *	<p>{{ . }}</p>
 * {{/ schools}}
 * 那么执行的结果类似如下所示：
 * <b>hello my world!!</b>
 * <h3>welcome to zengl!</h3>
 * <p>哈佛大学</p>
 * <p>牛津大学</p>
 * <p>家里蹲大学</p>
 */
ZL_EXP_VOID module_builtin_mustache_file_render(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT argcount)
{
	ZENGL_EXPORT_MOD_FUN_ARG arg = {ZL_EXP_FAT_NONE,{0}};
	if(argcount < 1)
		zenglApi_Exit(VM_ARG,"usage: bltMustacheFileRender(filename[, array])");
	zenglApi_GetFunArg(VM_ARG,1,&arg); //得到第一个参数
	if(arg.type != ZL_EXP_FAT_STR)
		zenglApi_Exit(VM_ARG,"first argument filename of bltMustacheFileRender must be string");
	char * filename = arg.val.str;
	char full_path[FULL_PATH_SIZE];
	MAIN_DATA * my_data = zenglApi_GetExtraData(VM_ARG, "my_data");
	builtin_make_fullpath(full_path, filename, my_data);
	int file_size;
	char * api_name = "bltMustacheFileRender";
	char * file_contents = builtin_get_file_content(VM_ARG, full_path, api_name, &file_size);
	crustache_template *template = builtin_crustache_new_template(VM_ARG, file_contents, api_name, file_size, full_path);
	zenglApi_FreeMem(VM_ARG, file_contents);
	builtin_mustache_context context = {0};
	if(argcount >= 2) {
		zenglApi_GetFunArg(VM_ARG,2,&arg);
		if(arg.type == ZL_EXP_FAT_MEMBLOCK) {
			context.ctx = arg;
		}
	}
	if(context.ctx.val.memblock.ptr == NULL) {
		if(zenglApi_CreateMemBlock(VM_ARG,&context.ctx.val.memblock,0) == -1) {
			zenglApi_Exit(VM_ARG,zenglApi_GetErrorString(VM_ARG));
		}
	}
	crustache_var ctx;
	ctx.type = CRUSTACHE_VAR_CONTEXT;
	ctx.data = (void *)(&context);
	struct buf *output_buf = bufnew(128);
	int error = crustache_render(output_buf, template, &ctx);
	if (error < 0)
	{
		char error_node[256];
		crustache_error_rendernode(error_node, sizeof(error_node), template);
		crustache_free(template);
		bufrelease(output_buf);
		zenglApi_Exit(VM_ARG, "%s error: %s (%s)\n", api_name, (char *)crustache_strerror(error), error_node);
	}
	char * output_str = zenglApi_AllocMem(VM_ARG, output_buf->size + 1);
	memcpy(output_str, output_buf->data, output_buf->size);
	output_str[output_buf->size] = '\0';
	zenglApi_SetRetVal(VM_ARG,ZL_EXP_FAT_STR, output_str, 0, 0);
	crustache_free(template);
	bufrelease(output_buf);
	zenglApi_FreeMem(VM_ARG, output_str);
}

/**
 * builtin模块的初始化函数，里面设置了与该模块相关的各个模块函数及其相关的处理句柄
 */
ZL_EXP_VOID module_builtin_init(ZL_EXP_VOID * VM_ARG,ZL_EXP_INT moduleID)
{
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltArray",zenglApiBMF_array);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltIterArray",module_builtin_iterate_array);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltWriteFile",module_builtin_write_file);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltExit",module_builtin_exit);
	zenglApi_SetModFunHandle(VM_ARG,moduleID,"bltMustacheFileRender",module_builtin_mustache_file_render);
}
