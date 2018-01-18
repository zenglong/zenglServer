CC = gcc
CFLAGS = -g3 -ggdb -O0 -std=c99
LIB_FLAG = -lpthread -lm
SRCS := main.c http_parser.c module_request.c module_builtin.c module_session.c dynamic_string.c multipart_parser.c resources.c client_socket_list.c json.c randutils.c md5.c
SRCS += main.h http_parser.h common_header.h module_request.h module_builtin.h module_session.h dynamic_string.h multipart_parser.h resources.h client_socket_list.h json.h randutils.h md5.h
ifeq ($(USE_MYSQL),yes)
	SRCS += module_mysql.c module_mysql.h 
	MYSQL_FLAG = -DUSE_MYSQL `mysql_config --cflags --libs` 
	MYSQL_OUTPUT_INFO = "mysql module is enabled!!!"
else
	MYSQL_OUTPUT_INFO = "*** notice: mysql module not enabled, you can use 'make USE_MYSQL=yes' to enable it, make sure you have mysql_config and mysql.h in your system! ***"
endif
SRCS += zengl/linux/zengl_exportfuns.h 

zenglServer: $(SRCS) zengl/linux/libzengl.a crustache/libcrustache.a
		$(CC) $(CFLAGS) $(SRCS) -o zenglServer zengl/linux/libzengl.a crustache/libcrustache.a $(LIB_FLAG) $(MYSQL_FLAG)
		@echo 
		@echo $(MYSQL_OUTPUT_INFO)

zengl/linux/libzengl.a:
	cd zengl/linux && $(MAKE) libzengl.a

crustache/libcrustache.a:
	cd crustache && $(MAKE) libcrustache.a

clean:
	rm -fv zenglServer
	rm -fv *.o
	rm -fv zengl/linux/*.o
	rm -fv zengl/linux/libzengl.a
	rm -fv crustache/*.o
	rm -fv crustache/libcrustache.a

all: zenglServer
