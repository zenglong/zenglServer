#ifndef __CRUSTACHE_H__
#define __CRUSTACHE_H__

#include "buffer.h"
#include "stack.h"

#define CRUSTACHE_COMPILE_VERSION 1 // 版本号，当crustache相关源码改动时，修改此版本号，可以迫使外层的zenglServer重新编译，以使用新的改动

typedef enum {
	CRUSTACHE_OK = 0,

	CR_EPARSE_MISMATCHED_MUSTACHE = -1,
	CR_EPARSE_BAD_MUSTACHE_NAME = -2,
	CR_EPARSE_MISMATCHED_SECTION = -3,
	CR_EPARSE_BAD_DELIM = -4,
	CR_EPARSE_NOT_IMPLEMENTED = -5,

	CR_ERENDER_TOO_DEEP = -6,
	CR_ERENDER_WRONG_VARTYPE = -7,
	CR_ERENDER_INVALID_CONTEXT = -8,
	CR_ERENDER_NOT_FOUND = -9,
	CR_ERENDER_BAD_PARTIAL = -10,

	CR_ENOMEM = -11,
} crustache_error_t;

typedef enum {
	CRUSTACHE_VAR_FALSE,
	CRUSTACHE_VAR_STR,
	CRUSTACHE_VAR_LIST,
	CRUSTACHE_VAR_LAMBDA,
	CRUSTACHE_VAR_CONTEXT,
	CRUSTACHE_VAR_INTEGER,
	CRUSTACHE_VAR_FLOAT,
} crustache_var_t;

typedef struct {
	crustache_var_t type;
	void *data;
	size_t size;
	size_t nncount; // 用于表示zengl数组中包含的非NONE成员的数量
} crustache_var;

typedef struct crustache_template crustache_template;

typedef struct {
	int (*context_find)(void * vm, builtin_mustache_context * new_context, crustache_var *, void *context, const char *key, size_t key_size);
	int (*list_get)(void * vm, builtin_mustache_context * new_context, crustache_var *, void *list, size_t i);
	int (*lambda)(crustache_var *, void *lambda, const char *raw_template, size_t raw_size);
	void (*var_free)(crustache_var_t type, void *var);

	int (*partial)(void * vm, crustache_template **partial, char *partial_name, size_t name_size);
	int free_partials;
} crustache_api;


extern void
crustache_free(crustache_template *template);

extern int
crustache_new(void * vm, crustache_template **output, crustache_api *api, const char *raw_template, size_t raw_length);

extern int
crustache_render(struct buf *ob, crustache_template *template, crustache_var *context);

const char *
crustache_error_syntaxline(
	size_t *line_n,
	size_t *col_n,
	size_t *line_len,
	crustache_template *template);

extern void
crustache_error_rendernode(char *buffer, size_t size, crustache_template *template);

extern const char *
crustache_strerror(int error);

#endif
