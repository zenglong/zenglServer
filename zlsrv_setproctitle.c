/*
 * zlsrv_setproctitle.c
 *
 *  Created on: Dec 16, 2018
 *      Author: zengl
 */

#include "zlsrv_setproctitle.h"
#include <stdlib.h>
#include <string.h>

#define ZLSRV_ERR_ALLOC_FAILED "alloc failed for init setproctitle"

extern char **environ;

extern char ** zlsrv_main_argv;

static char * st_zlsrv_argv_last;

int zlsrv_init_setproctitle(char ** errorstr)
{
	int i;
	size_t size;
	char * p;

	size = 0;

	for (i = 0; environ[i]; i++) {
		size += strlen(environ[i]) + 1;
	}

	p = malloc(size);
	if(p == NULL) {
		(*errorstr) = ZLSRV_ERR_ALLOC_FAILED;
		return -1;
	}

	st_zlsrv_argv_last = zlsrv_main_argv[0];

	for (i = 0; zlsrv_main_argv[i]; i++) {
		if (st_zlsrv_argv_last == zlsrv_main_argv[i]) {
			st_zlsrv_argv_last = zlsrv_main_argv[i] + strlen(zlsrv_main_argv[i]) + 1;
		}
	}

	for (i = 0; environ[i]; i++) {
		if (st_zlsrv_argv_last == environ[i]) {
			size = strlen(environ[i]) + 1;
			st_zlsrv_argv_last = environ[i] + size;
			strncpy(p, environ[i], size);
			environ[i] = (char *) p;
			p += size;
		}
	}

	st_zlsrv_argv_last--;
	return 0;
}

void zlsrv_setproctitle(char * title)
{
	char * p;
	size_t size;

	zlsrv_main_argv[1] = NULL;
	p = zlsrv_main_argv[0];
	size = strlen(title);
	if(size > (st_zlsrv_argv_last - p))
		size = st_zlsrv_argv_last - p;
	strncpy(p, title, size);
	p += size;
	if(st_zlsrv_argv_last - p) {
		memset(p, '\0', (st_zlsrv_argv_last - p));
	}
}
