CC = gcc
CFLAGS = -g3 -ggdb -O0 -std=c99
LIB_FLAG = -lpthread -lm
SRCS := main.c http_parser.c module_request.c module_builtin.c module_session.c dynamic_string.c multipart_parser.c resources.c client_socket_list.c json.c randutils.c md5.c debug.c zlsrv_setproctitle.c pointer.c base64.c fatal_error_callback.c
SRCS += main.h http_parser.h common_header.h module_request.h module_builtin.h module_session.h dynamic_string.h multipart_parser.h resources.h client_socket_list.h json.h randutils.h md5.h debug.h zlsrv_setproctitle.h pointer.h base64.h fatal_error_callback.h
ifeq ($(USE_MYSQL),yes)
	SRCS += module_mysql.c module_mysql.h 
	MYSQL_FLAG = -DUSE_MYSQL `mysql_config --cflags --libs` 
	MYSQL_OUTPUT_INFO = "mysql module is enabled!!!"
else
	MYSQL_OUTPUT_INFO = "*** notice: mysql module not enabled, you can use 'make USE_MYSQL=yes' to enable it, make sure you have mysql_config and mysql.h in your system! ***"
endif

ifdef USE_MAGICK
	SRCS += module_magick.c module_magick.h
	ifeq ($(USE_MAGICK), 6)
		MAGICK_FLAG = -D USE_MAGICK=6 `pkg-config --cflags --libs Wand`
	else
		ERR = $(error invalid magick value!)
	endif
	MAGICK_OUTPUT_INFO = "magick module is enabled!!!"
else
	MAGICK_OUTPUT_INFO = "*** notice: magick module not enabled, you can use 'make USE_MAGICK=6' to enable it, make sure you have pkg-config and 'wand/MagickWand.h' in your system! ***"
endif

ifeq ($(USE_PCRE),yes)
	SRCS += module_pcre.c module_pcre.h
	PCRE_FLAG = -DUSE_PCRE `pcre-config --cflags --libs`
	PCRE_OUTPUT_INFO = "pcre module is enabled!!!"
else
	PCRE_OUTPUT_INFO = "*** notice: pcre module not enabled, you can use 'make USE_PCRE=yes' to enable it, make sure you have pcre-config and pcre.h in your system! ***"
endif

ifeq ($(USE_CURL),yes)
	SRCS += module_curl.c module_curl.h
	CURL_FLAG = -DUSE_CURL `curl-config --cflags --libs`
	CURL_OUTPUT_INFO = "curl module is enabled!!!"
else
	CURL_OUTPUT_INFO = "*** notice: curl module not enabled, you can use 'make USE_CURL=yes' to enable it, make sure you have curl-config and 'curl/curl.h' in your system! ***"
endif

ifeq ($(USE_REDIS),yes)
	SRCS += module_redis.c module_redis.h
	REDIS_FLAG = -DUSE_REDIS `pkg-config --cflags --libs hiredis`
	REDIS_OUTPUT_INFO = "redis module is enabled!!!"
else
	REDIS_OUTPUT_INFO = "*** notice: redis module not enabled, you can use 'make USE_REDIS=yes' to enable it, make sure you have pkg-config and hiredis.h in your system! ***"
endif

ifeq ($(USE_OPENSSL),yes)
	SRCS += module_openssl.c module_openssl.h
	OPENSSL_FLAG = -DUSE_OPENSSL `pkg-config --cflags --libs openssl`
	OPENSSL_OUTPUT_INFO = "openssl module is enabled!!!"
else
	OPENSSL_OUTPUT_INFO = "*** notice: openssl module not enabled, you can use 'make USE_OPENSSL=yes' to enable it, make sure you have pkg-config and 'openssl/rsa.h' in your system! ***"
endif

ifdef URL_PATH_SIZE
	URL_PATH_SIZE_FLAG = -D URL_PATH_SIZE=$(URL_PATH_SIZE)
endif

ifdef FULL_PATH_SIZE
	FULL_PATH_SIZE_FLAG = -D FULL_PATH_SIZE=$(FULL_PATH_SIZE)
endif

SRCS += zengl/linux/zengl_exportfuns.h 

zenglServer: $(SRCS) zengl/linux/libzengl.a crustache/libcrustache.a
		$(ERR)
		$(CC) $(CFLAGS) $(SRCS) -o zenglServer zengl/linux/libzengl.a crustache/libcrustache.a $(URL_PATH_SIZE_FLAG) $(FULL_PATH_SIZE_FLAG) $(LIB_FLAG) $(MYSQL_FLAG) $(MAGICK_FLAG) $(PCRE_FLAG) $(CURL_FLAG) $(REDIS_FLAG) $(OPENSSL_FLAG)
		@echo 
		@echo $(MYSQL_OUTPUT_INFO)
		@echo $(MAGICK_OUTPUT_INFO)
		@echo $(PCRE_OUTPUT_INFO)
		@echo $(CURL_OUTPUT_INFO)
		@echo $(REDIS_OUTPUT_INFO)
		@echo $(OPENSSL_OUTPUT_INFO)

zengl/linux/libzengl.a: zengl/linux/zengl_exportfuns.h
	cd zengl/linux && $(MAKE) libzengl.a

crustache/libcrustache.a: module_builtin.h common_header.h crustache/crustache.h crustache/buffer.h crustache/houdini.h crustache/html_unescape.h crustache/stack.h crustache/crustache.c crustache/buffer.c crustache/houdini_html.c crustache/stack.c
	cd crustache && $(MAKE) libcrustache.a

clean:
	rm -fv zenglServer
	rm -fv *.o
	rm -fv zengl/linux/*.o
	rm -fv zengl/linux/libzengl.a
	rm -fv crustache/*.o
	rm -fv crustache/libcrustache.a

all: zenglServer
