CC = gcc
CFLAGS = -g3 -ggdb -O0 -std=c99
LIB_FLAG = -lpthread
SRCS := main.c http_parser.c module_request.c module_builtin.c dynamic_string.c multipart_parser.c 
SRCS += main.h http_parser.h common_header.h module_request.h module_builtin.h dynamic_string.h multipart_parser.h 
SRCS += zengl/linux/zengl_exportfuns.h 

zenglServer: $(SRCS) zengl/linux/libzengl.a
		$(CC) $(CFLAGS) $(SRCS) -o zenglServer zengl/linux/libzengl.a $(LIB_FLAG)

zengl/linux/libzengl.a:
	cd zengl/linux && $(MAKE) libzengl.a

clean:
	rm -fv zenglServer
	rm -fv *.o
	rm -fv zengl/linux/*.o
	rm -fv zengl/linux/libzengl.a

all: zenglServer
