## 介绍

zenglServer是一个http server，它除了用于响应静态文件外，最主要的目的在于接受外部http请求，并执行zengl动态脚本，并将脚本执行的结果反馈给浏览器之类的客户端。目前只是实验项目，仅供学习研究为目的。

## 编译

zenglServer只能在linux系统中进行编译和测试。要编译的话，直接在根目录中输入make命令即可：

```
zengl@zengl-ubuntu:~/zenglServer$ make
cd zengl/linux && make libzengl.a
make[1]: Entering directory '/home/zengl/zenglServer/zengl/linux'
gcc -D ZL_LANG_EN_WITH_CH -g3 -ggdb -O0 -std=c99 -fvisibility=hidden -fPIC -c zengl_main.c zengl_parser.c zengl_symbol.c zengl_locals.c zengl_assemble.c zengl_ld.c zenglrun_main.c zenglrun_func.c zenglrun_hash_array.c zenglApi.c zenglApi_BltModFuns.c zenglDebug.c
ar rc libzengl.a zengl_main.o zengl_parser.o zengl_symbol.o zengl_locals.o zengl_assemble.o zengl_ld.o zenglrun_main.o zenglrun_func.o zenglrun_hash_array.o zenglApi.o zenglApi_BltModFuns.o zenglDebug.o
make[1]: Leaving directory '/home/zengl/zenglServer/zengl/linux'
cd crustache && make libcrustache.a
make[1]: Entering directory '/home/zengl/zenglServer/crustache'
gcc -g3 -ggdb -O0 -std=c99 -fvisibility=hidden -fPIC -c buffer.c crustache.c houdini_html.c stack.c
ar rc libcrustache.a buffer.o crustache.o houdini_html.o stack.o
make[1]: Leaving directory '/home/zengl/zenglServer/crustache'
gcc -g3 -ggdb -O0 -std=c99 main.c http_parser.c module_request.c module_builtin.c module_session.c dynamic_string.c multipart_parser.c resources.c client_socket_list.c json.c randutils.c md5.c debug.c zlsrv_setproctitle.c pointer.c base64.c main.h http_parser.h common_header.h module_request.h module_builtin.h module_session.h dynamic_string.h multipart_parser.h resources.h client_socket_list.h json.h randutils.h md5.h debug.h zlsrv_setproctitle.h pointer.h base64.h zengl/linux/zengl_exportfuns.h  -o zenglServer zengl/linux/libzengl.a crustache/libcrustache.a -lpthread -lm    

*** notice: mysql module not enabled, you can use 'make USE_MYSQL=yes' to enable it, make sure you have mysql_config and mysql.h in your system! ***
*** notice: magick module not enabled, you can use 'make USE_MAGICK=6' to enable it, make sure you have pkg-config and 'wand/MagickWand.h' in your system! ***
*** notice: pcre module not enabled, you can use 'make USE_PCRE=yes' to enable it, make sure you have pcre-config and pcre.h in your system! ***
*** notice: curl module not enabled, you can use 'make USE_CURL=yes' to enable it, make sure you have curl-config and 'curl/curl.h' in your system! ***
*** notice: redis module not enabled, you can use 'make USE_REDIS=yes' to enable it, make sure you have pkg-config and hiredis.h in your system! ***
zengl@zengl-ubuntu:~/zenglServer$ 
```

第一次编译时，它会先进入zengl/linux目录，编译生成libzengl.a的静态库文件，该静态库主要用于执行zengl脚本。

如果要删除编译生成的文件的话，直接输入make clean即可。每次git pull拉取新的zenglServer版本时，最好都make clean一下，然后再make，这样可以确保修改的代码能够被及时编译，尤其是当zenglServer所依赖的libzengl.a和libcrustache.a的相关源码发生改变时。

从v0.4.0版本开始，zenglServer使用epoll来处理请求，因此，需要先确定linux支持epoll，epoll的API是从linux kernel 2.5.44开始引入的

### 开启mysql模块

从v0.3.0版本开始，在编译时，可以添加mysql模块，从而可以进行相关的mysql数据库操作，只要在make命令后面加入USE_MYSQL=yes即可：

```
zengl@zengl-ubuntu:~/zenglServer$ make USE_MYSQL=yes
cd zengl/linux && make libzengl.a
make[1]: Entering directory '/home/zengl/zenglServer/zengl/linux'
gcc -D ZL_LANG_EN_WITH_CH -g3 -ggdb -O0 -std=c99 -fvisibility=hidden -fPIC -c zengl_main.c zengl_parser.c zengl_symbol.c zengl_locals.c zengl_assemble.c zengl_ld.c zenglrun_main.c zenglrun_func.c zenglrun_hash_array.c zenglApi.c zenglApi_BltModFuns.c zenglDebug.c
ar rc libzengl.a zengl_main.o zengl_parser.o zengl_symbol.o zengl_locals.o zengl_assemble.o zengl_ld.o zenglrun_main.o zenglrun_func.o zenglrun_hash_array.o zenglApi.o zenglApi_BltModFuns.o zenglDebug.o
make[1]: Leaving directory '/home/zengl/zenglServer/zengl/linux'
cd crustache && make libcrustache.a
make[1]: Entering directory '/home/zengl/zenglServer/crustache'
gcc -g3 -ggdb -O0 -std=c99 -fvisibility=hidden -fPIC -c buffer.c crustache.c houdini_html.c stack.c
ar rc libcrustache.a buffer.o crustache.o houdini_html.o stack.o
make[1]: Leaving directory '/home/zengl/zenglServer/crustache'
gcc -g3 -ggdb -O0 -std=c99 main.c http_parser.c module_request.c module_builtin.c module_session.c dynamic_string.c multipart_parser.c resources.c client_socket_list.c json.c randutils.c md5.c debug.c zlsrv_setproctitle.c pointer.c base64.c main.h http_parser.h common_header.h module_request.h module_builtin.h module_session.h dynamic_string.h multipart_parser.h resources.h client_socket_list.h json.h randutils.h md5.h debug.h zlsrv_setproctitle.h pointer.h base64.h module_mysql.c module_mysql.h  zengl/linux/zengl_exportfuns.h  -o zenglServer zengl/linux/libzengl.a crustache/libcrustache.a -lpthread -lm -DUSE_MYSQL `mysql_config --cflags --libs`    

mysql module is enabled!!!
*** notice: magick module not enabled, you can use 'make USE_MAGICK=6' to enable it, make sure you have pkg-config and 'wand/MagickWand.h' in your system! ***
*** notice: pcre module not enabled, you can use 'make USE_PCRE=yes' to enable it, make sure you have pcre-config and pcre.h in your system! ***
*** notice: curl module not enabled, you can use 'make USE_CURL=yes' to enable it, make sure you have curl-config and 'curl/curl.h' in your system! ***
*** notice: redis module not enabled, you can use 'make USE_REDIS=yes' to enable it, make sure you have pkg-config and hiredis.h in your system! ***
zengl@zengl-ubuntu:~/zenglServer$ 
```

- 注意：在加入mysql模块前，请确保你的系统中包含了mysql_config程式和mysql.h开发头文件，如果没有的话，如果是ubuntu系统，可以通过sudo apt-get install libmysqlclient-dev来添加开发mysql客户端所需要的文件，如果是centos系统，则可以通过yum install mysql-devel来加入开发所需的文件。

### 开启magick模块

从v0.11.0版本开始，在编译时，还可以添加magick模块，从而可以进行图像相关的操作，例如：缩放图像等。只要在make命令后面加入USE_MAGICK=6即可，由于操作图像使用的是ImageMagick，而ImageMagick有6.x和7.x的版本，目前只支持6.x的版本，因此USE_MAGICK后面跟随的是数字6，如果以后支持7.x的话，还可以跟随7。

当然，要使用ImageMagick，前提是系统中安装了底层的开发库。

如果是ubuntu系统，可以通过sudo apt-get install imagemagick libmagickcore-dev libmagickwand-dev来安装ImageMagick相关的库和开发头文件。

如果是centos系统，则可以通过yum install ImageMagick ImageMagick-devel来安装相关的底层库。可以通过convert --version命令来查看系统安装的是哪个版本的ImageMagick

如果是centos 8.x系统，上面的yum安装ImageMagick的方式可能会失败，此时，可以通过以下命令来安装：
```
dnf install -y epel-release
dnf config-manager --set-enabled PowerTools (如果命令执行失败，提示No matching repo to modify: PowerTools.的错误时，可以尝试使用小写形式执行：sudo dnf config-manager --set-enabled powertools 也就是将PowerTools改成powertools小写的形式来执行)
dnf install -y ImageMagick ImageMagick-devel
```

要同时使用mysql和magick模块，可以使用make USE_MYSQL=yes USE_MAGICK=6命令：

```
zengl@zengl-ubuntu:~/zenglServer$ make USE_MYSQL=yes USE_MAGICK=6
cd zengl/linux && make libzengl.a
make[1]: Entering directory `/home/zengl/zenglServer/zengl/linux'
gcc -D ZL_LANG_EN_WITH_CH -g3 -ggdb -O0 -std=c99 -fvisibility=hidden -fPIC -c zengl_main.c zengl_parser.c zengl_symbol.c zengl_locals.c zengl_assemble.c zengl_ld.c zenglrun_main.c zenglrun_func.c zenglrun_hash_array.c zenglApi.c zenglApi_BltModFuns.c zenglDebug.c
ar rc libzengl.a zengl_main.o zengl_parser.o zengl_symbol.o zengl_locals.o zengl_assemble.o zengl_ld.o zenglrun_main.o zenglrun_func.o zenglrun_hash_array.o zenglApi.o zenglApi_BltModFuns.o zenglDebug.o
make[1]: Leaving directory `/home/zengl/zenglServer/zengl/linux'
cd crustache && make libcrustache.a
make[1]: Entering directory `/home/zengl/zenglServer/crustache'
gcc -g3 -ggdb -O0 -std=c99 -fvisibility=hidden -fPIC -c buffer.c crustache.c houdini_html.c stack.c
ar rc libcrustache.a buffer.o crustache.o houdini_html.o stack.o
make[1]: Leaving directory `/home/zengl/zenglServer/crustache'
gcc -g3 -ggdb -O0 -std=c99 main.c http_parser.c module_request.c module_builtin.c module_session.c dynamic_string.c multipart_parser.c resources.c client_socket_list.c json.c randutils.c md5.c debug.c zlsrv_setproctitle.c pointer.c base64.c main.h http_parser.h common_header.h module_request.h module_builtin.h module_session.h dynamic_string.h multipart_parser.h resources.h client_socket_list.h json.h randutils.h md5.h debug.h zlsrv_setproctitle.h pointer.h base64.h module_mysql.c module_mysql.h  module_magick.c module_magick.h zengl/linux/zengl_exportfuns.h  -o zenglServer zengl/linux/libzengl.a crustache/libcrustache.a -lpthread -lm -DUSE_MYSQL `mysql_config --cflags --libs`  -D USE_MAGICK=6 `pkg-config --cflags --libs Wand`  

mysql module is enabled!!!
magick module is enabled!!!
*** notice: pcre module not enabled, you can use 'make USE_PCRE=yes' to enable it, make sure you have pcre-config and pcre.h in your system! ***
*** notice: curl module not enabled, you can use 'make USE_CURL=yes' to enable it, make sure you have curl-config and 'curl/curl.h' in your system! ***
*** notice: redis module not enabled, you can use 'make USE_REDIS=yes' to enable it, make sure you have pkg-config and hiredis.h in your system! ***
zengl@zengl-ubuntu:~/zenglServer$ 
```

### 开启pcre模块

从v0.14.0版本开始，在编译时，可以添加pcre正则表达式模块，从而可以进行正则匹配，正则替换相关的操作。只要在make命令后面加入USE_PCRE=yes即可。

当然，要使用pcre模块，前提是系统中安装了底层的pcre开发库。

如果是ubuntu系统，可以通过 sudo apt-get install libpcre3 libpcre3-dev 来安装pcre相关的库和开发头文件等。

如果是centos系统，则可以通过 yum install pcre pcre-devel 来安装相关的底层库。

要同时使用mysql，magick和pcre模块，可以使用 make USE_MYSQL=yes USE_MAGICK=6 USE_PCRE=yes 命令：

```
zengl@zengl-ubuntu:~/zenglServer$ make USE_MYSQL=yes USE_MAGICK=6 USE_PCRE=yes
...................................................
gcc -g3 -ggdb -O0 -std=c99 main.c http_parser.c module_request.c module_builtin.c module_session.c dynamic_string.c multipart_parser.c resources.c client_socket_list.c json.c randutils.c md5.c debug.c zlsrv_setproctitle.c pointer.c base64.c main.h http_parser.h common_header.h module_request.h module_builtin.h module_session.h dynamic_string.h multipart_parser.h resources.h client_socket_list.h json.h randutils.h md5.h debug.h zlsrv_setproctitle.h pointer.h base64.h module_mysql.c module_mysql.h  module_magick.c module_magick.h module_pcre.c module_pcre.h zengl/linux/zengl_exportfuns.h  -o zenglServer zengl/linux/libzengl.a crustache/libcrustache.a -lpthread -lm -DUSE_MYSQL `mysql_config --cflags --libs`  -D USE_MAGICK=6 `pkg-config --cflags --libs Wand` -DUSE_PCRE `pcre-config --cflags --libs` 

mysql module is enabled!!!
magick module is enabled!!!
pcre module is enabled!!!
*** notice: curl module not enabled, you can use 'make USE_CURL=yes' to enable it, make sure you have curl-config and 'curl/curl.h' in your system! ***
*** notice: redis module not enabled, you can use 'make USE_REDIS=yes' to enable it, make sure you have pkg-config and hiredis.h in your system! ***
zengl@zengl-ubuntu:~/zenglServer$ 
```

### 开启curl模块

从v0.15.0版本开始，在编译时，可以添加curl模块，从而可以执行抓取数据相关的操作。只要在make命令后面加入USE_CURL=yes即可。

当然，要使用curl模块，前提是系统中安装了底层的curl开发库。

如果是ubuntu系统，可以通过 sudo apt-get install curl libcurl3 libcurl3-dev 来安装curl相关的库和开发头文件等（如果没有libcurl3，则可以尝试使用sudo apt-get install curl libcurl4 libcurl4-openssl-dev 来安装curl相关的库和开发头文件）。

如果是centos系统，则可以通过 yum install curl curl-devel 来安装相关的底层库。

要同时使用mysql，magick，pcre，以及curl模块，可以使用 make USE_MYSQL=yes USE_MAGICK=6 USE_PCRE=yes USE_CURL=yes 命令：

```
[parallels@localhost zenglServerTest]$ make USE_MYSQL=yes USE_MAGICK=6 USE_PCRE=yes USE_CURL=yes
...................................................
gcc -g3 -ggdb -O0 -std=c99 main.c http_parser.c module_request.c module_builtin.c module_session.c dynamic_string.c multipart_parser.c resources.c client_socket_list.c json.c randutils.c md5.c debug.c zlsrv_setproctitle.c pointer.c base64.c main.h http_parser.h common_header.h module_request.h module_builtin.h module_session.h dynamic_string.h multipart_parser.h resources.h client_socket_list.h json.h randutils.h md5.h debug.h zlsrv_setproctitle.h pointer.h base64.h module_mysql.c module_mysql.h  module_magick.c module_magick.h module_pcre.c module_pcre.h module_curl.c module_curl.h zengl/linux/zengl_exportfuns.h  -o zenglServer zengl/linux/libzengl.a crustache/libcrustache.a -lpthread -lm -DUSE_MYSQL `mysql_config --cflags --libs`  -D USE_MAGICK=6 `pkg-config --cflags --libs Wand` -DUSE_PCRE `pcre-config --cflags --libs` -DUSE_CURL `curl-config --cflags --libs`

mysql module is enabled!!!
magick module is enabled!!!
pcre module is enabled!!!
curl module is enabled!!!
*** notice: redis module not enabled, you can use 'make USE_REDIS=yes' to enable it, make sure you have pkg-config and hiredis.h in your system! ***
[parallels@localhost zenglServerTest]$
```

### 开启redis模块

从v0.19.0版本开始，在编译时，可以添加redis模块，从而可以执行redis缓存相关的工作。只要在make命令后面加入USE_REDIS=yes即可。

当然，要使用redis模块，前提是系统中安装了hiredis的底层库。

如果是ubuntu系统，可以通过 sudo apt-get install libhiredis-dev 来安装hiredis相关的库和开发头文件等。

如果是centos系统，则可以通过 yum install hiredis-devel 来安装相关的底层库。在centos 8.x中使用yum命令安装hiredis-devel时，可能需要安装epel仓库，可以使用 yum -y install epel-release 命令来安装epel仓库。

还可以使用源码编译方式来安装hiredis库：

```
curl -L -o hiredis.zip https://github.com/redis/hiredis/archive/v0.13.3.zip
unzip -d ./hiredis hiredis.zip
cd hiredis/hiredis-0.13.3/
make -j
sudo make install
sudo ldconfig
```

使用源码编译安装时，还需要通过PKG_CONFIG_PATH环境变量来指定make install时，安装的hiredis.pc的位置(下面假设该文件位于/usr/local/lib/pkgconfig/目录中)：

```
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/
```

要同时使用mysql，magick，pcre，curl，以及redis模块，可以使用 make USE_MYSQL=yes USE_MAGICK=6 USE_PCRE=yes USE_CURL=yes USE_REDIS=yes 命令。

```
[root@localhost zenglServerTest]# make USE_MYSQL=yes USE_MAGICK=6 USE_PCRE=yes USE_CURL=yes USE_REDIS=yes
............................................................
gcc -g3 -ggdb -O0 -std=c99 main.c http_parser.c module_request.c module_builtin.c module_session.c dynamic_string.c multipart_parser.c resources.c client_socket_list.c json.c randutils.c md5.c debug.c zlsrv_setproctitle.c pointer.c base64.c main.h http_parser.h common_header.h module_request.h module_builtin.h module_session.h dynamic_string.h multipart_parser.h resources.h client_socket_list.h json.h randutils.h md5.h debug.h zlsrv_setproctitle.h pointer.h base64.h module_mysql.c module_mysql.h  module_magick.c module_magick.h module_pcre.c module_pcre.h module_curl.c module_curl.h module_redis.c module_redis.h zengl/linux/zengl_exportfuns.h  -o zenglServer zengl/linux/libzengl.a crustache/libcrustache.a   -lpthread -lm -DUSE_MYSQL `mysql_config --cflags --libs`  -D USE_MAGICK=6 `pkg-config --cflags --libs Wand` -DUSE_PCRE `pcre-config --cflags --libs` -DUSE_CURL `curl-config --cflags --libs` -DUSE_REDIS `pkg-config --cflags --libs hiredis`

mysql module is enabled!!!
magick module is enabled!!!
pcre module is enabled!!!
curl module is enabled!!!
redis module is enabled!!!
[root@localhost zenglServerTest]# 
```

### 开启openssl模块

从v0.20.0版本开始，在编译时，可以添加openssl模块，从而可以执行RSA加密，解密，签名，验签之类的操作。只要在make命令后面加入USE_OPENSSL=yes即可。

当然，要使用openssl模块，前提是系统中安装了底层的openssl开发库。

如果是ubuntu系统，可以通过 sudo apt-get install openssl libssl-dev 来安装openssl相关的库和开发头文件等。

如果是centos系统，则可以通过 yum install openssl openssl-devel 来安装相关的底层库。

要同时使用mysql，magick，pcre，curl，redis，以及openssl模块，可以使用 make USE_MYSQL=yes USE_MAGICK=6 USE_PCRE=yes USE_CURL=yes USE_REDIS=yes USE_OPENSSL=yes 命令：

```
[root@localhost zenglServerTest]# make USE_MYSQL=yes USE_MAGICK=6 USE_PCRE=yes USE_CURL=yes USE_REDIS=yes USE_OPENSSL=yes
............................................................
gcc -g3 -ggdb -O0 -std=c99 main.c http_parser.c module_request.c module_builtin.c module_session.c dynamic_string.c multipart_parser.c resources.c client_socket_list.c json.c randutils.c md5.c debug.c zlsrv_setproctitle.c pointer.c base64.c main.h http_parser.h common_header.h module_request.h module_builtin.h module_session.h dynamic_string.h multipart_parser.h resources.h client_socket_list.h json.h randutils.h md5.h debug.h zlsrv_setproctitle.h pointer.h base64.h module_mysql.c module_mysql.h  module_magick.c module_magick.h module_pcre.c module_pcre.h module_curl.c module_curl.h module_redis.c module_redis.h module_openssl.c module_openssl.h zengl/linux/zengl_exportfuns.h  -o zenglServer zengl/linux/libzengl.a crustache/libcrustache.a   -lpthread -lm -DUSE_MYSQL `mysql_config --cflags --libs`  -D USE_MAGICK=6 `pkg-config --cflags --libs Wand` -DUSE_PCRE `pcre-config --cflags --libs` -DUSE_CURL `curl-config --cflags --libs` -DUSE_REDIS `pkg-config --cflags --libs hiredis` -DUSE_OPENSSL `pkg-config --cflags --libs openssl`

mysql module is enabled!!!
magick module is enabled!!!
pcre module is enabled!!!
curl module is enabled!!!
redis module is enabled!!!
openssl module is enabled!!!
[root@localhost zenglServerTest]# 
```

### 自定义URL_PATH_SIZE和FULL_PATH_SIZE宏对应的值

从v0.17.0版本开始，在编译时，可以自定义main.h头文件中的URL_PATH_SIZE和FULL_PATH_SIZE宏对应的值，只要在make命令后面加入URL_PATH_SIZE=xxx和FULL_PATH_SIZE=xxx即可(xxx表示需要自定义的数值)：

```
[parallels@localhost zenglServerTest]$ make URL_PATH_SIZE=200 FULL_PATH_SIZE=300 USE_MYSQL=yes USE_MAGICK=6 USE_PCRE=yes USE_CURL=yes
...................................................
gcc -g3 -ggdb -O0 -std=c99 main.c http_parser.c .....  -o zenglServer zengl/linux/libzengl.a crustache/libcrustache.a -D URL_PATH_SIZE=200 -D FULL_PATH_SIZE=300 -lpthread -lm -DUSE_MYSQL `mysql_config --cflags --libs`  -D USE_MAGICK=6 `pkg-config --cflags --libs Wand` -DUSE_PCRE `pcre-config --cflags --libs` -DUSE_CURL `curl-config --cflags --libs`

mysql module is enabled!!!
magick module is enabled!!!
pcre module is enabled!!!
curl module is enabled!!!
[parallels@localhost zenglServerTest]$ 
```

当处于详细日志模式时(当配置文件中的verbose为TRUE时)，可以在日志中看到每个请求的url_path和full_path，URL_PATH_SIZE可以控制url_path所允许的最大长度(最多可以容纳多少个字符)，FULL_PATH_SIZE则可以控制full_path所允许的最大长度，此外，很多模块函数中也是用FULL_PATH_SIZE作为文件路径的最大长度。

如果没有在make命令中自定义URL_PATH_SIZE和FULL_PATH_SIZE的话，URL_PATH_SIZE的默认值会是120，FULL_PATH_SIZE的默认值则是200。在自定义这两个宏值时，自定义的值必须大于30，且小于等于4096。

## 使用

在根目录中，有一个config.zl的默认配置文件(使用zengl脚本语法编写)，该配置文件里定义了zenglServer需要绑定的端口号，需要启动的进程数等：

```
def TRUE 1;
def FALSE 0;
def KBYTE 1024;

debug_mode = TRUE;
//debug_mode = FALSE;
// zl_debug_log = "zl_debug.log"; // zengl脚本的调试日志，可以输出相关的虚拟汇编指令

port = 8083; // 绑定的端口

if(!debug_mode)
	process_num = 3; // 进程数
else
	print '*** config is in debug mode ***';
	process_num = 1; // 进程数
endif

webroot = "my_webroot"; // web根目录

session_dir = "my_sessions"; // 会话目录
session_expire = 1440; // 会话默认超时时间(以秒为单位)
session_cleaner_interval = 3600; // 会话文件清理进程的清理时间间隔(以秒为单位)

remote_debug_enable = FALSE; // 是否开启远程调试，默认为FALSE即不开启，设置为TRUE可以开启远程调试
remote_debugger_ip = '127.0.0.1'; // 远程调试器的ip地址
remote_debugger_port = 9999; // 远程调试器的端口号

zengl_cache_enable = FALSE; // 是否开启zengl脚本的编译缓存，默认为FALSE即不开启，设置为TRUE可以开启编译缓存

shm_enable = FALSE; // 是否将zengl脚本的编译缓存放入共享内存
shm_min_size = 300 * KBYTE; // 需要放进共享内存的缓存的最小大小，只有超过这个大小的缓存才放入共享内存中，以字节为单位

verbose = TRUE; // 使用详细日志模式，还是精简日志模式，默认是TRUE即详细日志模式，设置为FALSE可以切换到精简日志模式，在详细日志模式中，会将每个请求的请求头和响应头都记录到日志中

request_body_max_size = 200 * KBYTE; // 设置每个请求的主体数据所允许的最大字节值
request_header_max_size = 5 * KBYTE; // 设置请求头所允许的最大字节值
request_url_max_size = 1024; // 设置url资源路径(包括请求参数在内)所允许的最大字符数

backlog = 10; // 设置TCP连接队列中可以等待的连接数(backlog的值只是建议值，不同的系统会根据这个值设置不同的等待连接数，例如linux 2.4.7中当backlog为1时，实际可以等待的连接数会是4等)，当队列中等待连接的数量满了时，新请求的连接就会报连接被拒绝的错误

timezone = 'Asia/Shanghai'; // 设置时区

pidfile = "zenglServer.pid"; // 设置记录主进程的进程ID的文件名(该文件名可以是相对于当前工作目录的路径)

```

在编译成功后，直接运行生成好的zenglServer可执行文件即可(从v0.4.0版本开始，zenglServer默认以守护进程模式启动，并采用epoll方式来处理请求)：

```
zengl@zengl-ubuntu:~/zenglServer$ ./zenglServer 
zengl@zengl-ubuntu:~/zenglServer$ ps -aux | grep zenglServer
zengl      300  0.0  0.0  26440  2124 ?        Ss   19:08   0:00 zenglServer: master[8083] cwd:/home/zengl/zenglServer -c config.zl -l logfile
zengl      301  0.0  0.0  42832   528 ?        Sl   19:08   0:00 zenglServer: child(0) ppid:300
zengl      302  0.0  0.0  26440   528 ?        S    19:08   0:00 zenglServer: cleaner  ppid:300
zengl@zengl-ubuntu:~/zenglServer$ cat logfile
create master process for daemon [pid:300]
use default config: config.zl
*** config is in debug mode ***
run config.zl complete, config:
port: 8083 process_num: 1
webroot: my_webroot
session_dir: my_sessions session_expire: 1440 cleaner_interval: 3600
remote_debug_enable: False remote_debugger_ip: 127.0.0.1 remote_debugger_port: 9999 zengl_cache_enable: False shm_enable: False shm_min_size: 307200
verbose: True request_body_max_size: 204800, request_header_max_size: 5120 request_url_max_size: 1024
URL_PATH_SIZE: 120 FULL_PATH_SIZE: 200
pidfile: zenglServer.pid
bind done
accept sem initialized.
process_max_open_fd_num: 1024
Master: Spawning child(0) [pid 301]
Master: Spawning cleaner [pid 302]
epoll max fd count : 896
------------ cleaner sleep begin: 1515236908
zengl@zengl-ubuntu:~/zenglServer$ 
```

默认绑定的端口号为：8083，打开你的浏览器，输入 http://[your ip address]:8083，[your ip address]表示zenglServer所在的linux系统的ip地址，假设为：10.7.20.220，那么输入 http://10.7.20.220:8083 应该可以看到Hello World!静态页面，可以在日志文件logfile中查看到相关信息：

```
zengl@zengl-ubuntu:~/zenglServer$ tail -f logfile 
-----------------------------------
Sat Jan  6 19:16:33 2018
recv [client_socket_fd:9] [lst_idx:0] [pid:301] [tid:304]:

request header: Host: 10.7.20.220:8083 | Connection: keep-alive | User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36 | Upgrade-Insecure-Requests: 1 | Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8 | Accept-Encoding: gzip, deflate | Accept-Language: zh-CN,zh;q=0.8 | 

url: /
url_path: /
full_path: my_webroot/index.html
status: 200, content length: 90
response header: HTTP/1.1 200 OK
Cache-Control: public, max-age=600
Content-Type: text/html
Last-Modified: Sun, 04 Jun 2017 06:28:50 GMT
Content-Length: 90
Connection: Closed
Server: zenglServer
free socket_list[0]/list_cnt:0 epoll_fd_add_count:1 pid:301 tid:304
-----------------------------------
Sat Jan  6 19:16:33 2018
recv [client_socket_fd:10] [lst_idx:0] [pid:301] [tid:304]:

request header: Host: 10.7.20.220:8083 | Connection: keep-alive | User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36 | Accept: image/webp,image/apng,image/*,*/*;q=0.8 | Referer: http://10.7.20.220:8083/ | Accept-Encoding: gzip, deflate | Accept-Language: zh-CN,zh;q=0.8 | 

url: /favicon.ico
url_path: /favicon.ico
full_path: my_webroot/favicon.ico
status: 200, content length: 67646
response header: HTTP/1.1 200 OK
Cache-Control: public, max-age=600
Content-Type: image/x-icon
Last-Modified: Mon, 21 Nov 2016 05:58:13 GMT
Content-Length: 67646
Connection: Closed
Server: zenglServer
free socket_list[0]/list_cnt:0 epoll_fd_add_count:0 pid:301 tid:304
```

可以看到请求头信息，请求的url资源路径，处理该请求的pid(进程ID)等，从v0.5.0版本开始，还可以看到完整的response header(响应头)信息

在浏览器中输入测试用的表单地址：http://10.7.20.220:8083/form.html 在表单中随便填些东西，点击Submit提交按钮，交由test.zl测试脚本去处理，处理后会返回类似如下的测试结果：

```
a is 20 end
user agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36
other_headers, user agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36
request body: title=hello&description=world&content=zengl+program&sb=Submit
```

test.zl测试脚本中，获取了当前浏览器的UA信息，以及请求的body(主体数据)。

还可以直接在浏览器地址中输入test.zl并附加一些查询字符串，脚本会将查询字符串自动解析为哈希数组：
在浏览器中输入：http://10.7.20.220:8083/test.zl?name=zengl&job=programmer
反馈结果如下：

```
a is 20 end
user agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36
other_headers, user agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36
query string: name=zengl&job=programmer
querys['name']: zengl
querys['job']: programmer
```

要退出zenglServer，需要kill掉主进程，也就是名称为zenglServer: master...的进程，主进程名中还可以看到端口号，例如下面例子中的master[8083]表示使用的是8083的端口，还能看到zenglServer执行时的cwd即当前工作目录，以及所使用的配置文件和日志文件。

注意：如果只kill子进程的话，主进程会自动重启子进程，所以需要kill主进程，在kill主进程时，主进程会自动终止所有的子进程，下面的进程列表中，子进程的名称的末尾会包含ppid:...，也就是该子进程所属的父进程的pid(进程ID)，当启动了多个zenglServer时，就可以知道哪些子进程是属于哪个zenglServer的了：

```
zengl@zengl-ubuntu:~/zenglServer$ ps aux | grep zenglServer
zengl      300  0.0  0.0  26440  2124 ?        Ss   19:08   0:00 zenglServer: master[8083] cwd:/home/zengl/zenglServer -c config.zl -l logfile
zengl      301  0.0  0.0 108368   528 ?        Sl   19:08   0:00 zenglServer: child(0) ppid:300
zengl      302  0.0  0.0  26440   528 ?        S    19:08   0:00 zenglServer: cleaner  ppid:300
zengl@zengl-ubuntu:~/zenglServer$ kill 300
zengl@zengl-ubuntu:~/zenglServer$ ps aux | grep zenglServer
zengl@zengl-ubuntu:~/zenglServer$ tail -f logfile 
free socket_list[0]/list_cnt:0 epoll_fd_add_count:1 pid:301 tid:304
 **** warning: 0 data length occured 0[0]
free socket_list[0]/list_cnt:0 epoll_fd_add_count:0 pid:301 tid:304
Termination signal received! Killing children
All children reaped, shutting down.
closed accept_sem
shutdowned server socket
closed server socket
===================================
```

可以在logfile中看到Killing children以及shutting down之类的退出信息。

从v0.17.0版本开始，增加了pidfile配置，可以指定用于存储主进程的进程ID的文件，config.zl中pidfile默认的值为zenglServer.pid，可以在kill主进程时，直接使用该文件，这样就不用去手动查询和输入主进程的ID了：

```
zengl@zengl-ubuntu:~/zenglServer$ kill `cat zenglServer.pid`
```

zenglServer有几个可选的命令行参数，可以使用-h查看帮助信息：

```
zengl@zengl-ubuntu:~/zenglServer$ ./zenglServer -h
usage: ./zenglServer [options]
-v                  show version
-c <config file>    set config file
-l <logfile>        set logfile
-h                  show this help
zengl@zengl-ubuntu:~/zenglServer$ 
```

通过-v可以查看zenglServer的版本号以及所使用的zengl脚本语言的版本号，-c可以指定需要加载的配置文件(配置文件必须使用zengl脚本语法编写)：

```
zengl@zengl-ubuntu:~/zenglServer$ ./zenglServer -v
zenglServer version: v0.17.0
zengl language version: v1.8.2
zengl@zengl-ubuntu:~/zenglServer$ ./zenglServer -c config.zl
zengl@zengl-ubuntu:~/zenglServer$ tail -f logfile 
use config: config.zl
*** config is in debug mode ***
run config.zl complete, config: 
port: 8083 process_num: 1
webroot: my_webroot
session_dir: my_sessions session_expire: 1440 cleaner_interval: 3600
remote_debug_enable: False remote_debugger_ip: 127.0.0.1 remote_debugger_port: 9999 zengl_cache_enable: False shm_enable: False shm_min_size: 307200
bind done
accept sem initialized.
process_max_open_fd_num: 1024 
Master: Spawning child(0) [pid 673] 
Master: Spawning cleaner [pid 674] 
epoll max fd count : 896
------------ cleaner sleep begin: 1515237890
```

通过-l命令行参数可以指定日志文件的文件名(文件名可以是相对于当前执行的zenglServer的文件路径):

```
zengl@zengl-ubuntu:~/zenglServer$ ./zenglServer -c config.zl -l logfile_test
zengl@zengl-ubuntu:~/zenglServer$ ps aux | grep zenglServer
zengl      9939  0.0  0.0  26440  2124 ?        Ss   19:08   0:00 zenglServer: master[8083] cwd:/home/zengl/zenglServer -c config.zl -l logfile_test
zengl      9940  0.0  0.0 108368   528 ?        Sl   19:08   0:00 zenglServer: child(0) ppid:9939
zengl      9943  0.0  0.0  26440   528 ?        S    19:08   0:00 zenglServer: cleaner  ppid:9939
zengl@zengl-ubuntu:~/zenglServer$ tail -n 50 logfile_test
create master process for daemon [pid:9939] 
use config: config.zl
......................................
zengl@zengl-ubuntu:~/zenglServer$ 
```

## 精简日志模式

从v0.17.0版本开始，可以使用精简日志模式，只需将配置文件中的verbose设置为FALSE即可：

```
def TRUE 1;
def FALSE 0;
def KBYTE 1024;

....................................................

verbose = FALSE; // 使用详细日志模式，还是精简日志模式，默认是TRUE即详细日志模式，设置为FALSE可以切换到精简日志模式，在详细日志模式中，会将每个请求的请求头和响应头都记录到日志中

....................................................

```

在精简日志模式下，日志中只会记录每个请求的url之类的路径信息，不会去记录每个请求的请求头和响应头信息：

```
zengl@zengl-ubuntu:~/zenglServer$ tail -n 30 logfile
....................................................
create master process for daemon [pid:7159] 
use default config: config.zl
*** config is in debug mode ***
run config.zl complete, config: 
port: 8083 process_num: 1
webroot: my_webroot
session_dir: my_sessions session_expire: 1440 cleaner_interval: 3600
remote_debug_enable: False remote_debugger_ip: 127.0.0.1 remote_debugger_port: 9999 zengl_cache_enable: False shm_enable: False shm_min_size: 307200
verbose: False request_body_max_size: 204800, request_header_max_size: 5120 request_url_max_size: 1024
URL_PATH_SIZE: 200 FULL_PATH_SIZE: 300
pidfile: zenglServer.pid
bind done
accept sem initialized.
process_max_open_fd_num: 1024 
Master: Spawning child(0) [pid 7160] 
Master: Spawning cleaner [pid 7163] 
2019/01/12 16:27:31 fd:8 idx:0 pid:7160 tid:7162 | url: /v0_15_0/test.zl | full_path: my_webroot/v0_15_0/test.zl | status: 200, length: 1367 | free [0]/0 epoll:1 pid:7160 tid:7162
2019/01/12 16:27:33 fd:9 idx:0 pid:7160 tid:7162 | url: /favicon.ico | full_path: my_webroot/favicon.ico | status: 200, length: 67646 | free [0]/0 epoll:0 pid:7160 tid:7162
2019/01/12 16:27:34 fd:10 idx:0 pid:7160 tid:7162 | url: /v0_5_0/show_header.zl | full_path: my_webroot/v0_5_0/show_header.zl | status: 200, length: 647 | free [0]/0 epoll:1 pid:7160 tid:7162
2019/01/12 16:27:34 fd:8 idx:0 pid:7160 tid:7162 | url: /favicon.ico | full_path: my_webroot/favicon.ico | status: 200, length: 67646 | free [0]/0 epoll:0 pid:7160 tid:7162
2019/01/12 16:28:52 fd:9 idx:0 pid:7160 tid:7162 | url: /v0_5_0/show_header.zl | full_path: my_webroot/v0_5_0/show_header.zl | status: 200, length: 626 | free [0]/0 epoll:1 pid:7160 tid:7162
zengl@zengl-ubuntu:~/zenglServer$ 
```

## 设置允许上传的文件大小

从v0.17.0版本开始，在配置文件中增加了request_body_max_size的配置，该配置用于设置每个请求的主体数据所允许的最大字节值。

当需要上传较大的文件时，就需要调整该配置值，例如，假设配置值是200K，但是上传文件的大小是300K，那么上传就会失败。因为上传文件的请求对应的主体数据的字节大小大于设置的200K，此时，就需要将此配置根据情况调大，例如调到400K等，这样就可以上传较大的文件了。

配置文件中的request_body_max_size的默认值是200K字节：

```
def TRUE 1;
def FALSE 0;
def KBYTE 1024;

.......................................................

request_body_max_size = 200 * KBYTE; // 设置每个请求的主体数据所允许的最大字节值
.......................................................
```

## 设置请求头允许的最大字节值

从v0.17.0版本开始，在配置文件中增加了request_header_max_size的配置，该配置用于设置请求头所允许的最大字节值，当请求中可能包含较大的请求头时，就需要调整该配置的值。

例如，当请求头中包含很多Cookie信息时，就会导致请求头比较大，此时就需要适当的调大该配置的值，这样，服务端才能记录到完整的请求头信息。

配置文件中的request_header_max_size的默认值是5K字节：

```
def TRUE 1;
def FALSE 0;
def KBYTE 1024;

.......................................................
request_header_max_size = 5 * KBYTE; // 设置请求头所允许的最大字节值
.......................................................
```

## 远程调试

从v0.9.0版本开始，zenglServer可以使用python进行远程调试。在根目录中新建了pydebugger目录，在该目录内新增了TCPServer.py的python脚本，需要通过python3来运行本脚本。该脚本在运行时，默认会监听9999端口(可以给脚本传递参数来改变绑定的端口号)，当python脚本接收到zenglServer的调试连接时，就会等待用户输入调试命令，并将这些命令发送给zenglServer，再由zenglServer执行调试命令和返回调试结果，最后python会将结果显示到用户终端上。

要开启远程调试，还需要将zenglServer的config.zl中的remote_debug_enable设置为TRUE：

```
def TRUE 1;
def FALSE 0;

.................................

remote_debug_enable = FALSE; // 是否开启远程调试，默认为FALSE即不开启，设置为TRUE可以开启远程调试
remote_debugger_ip = '127.0.0.1'; // 远程调试器的ip地址
remote_debugger_port = 9999; // 远程调试器的端口号
```

在开启远程调试并重启zenglServer后，就可以运行python脚本。当zenglServer执行zengl脚本时，就会向python脚本发送调试连接，从而进行远程调试：

```
zengl@zengl-ubuntu:~/zenglServer$ python3 pydebugger/TCPServer.py
listen connection [port:9999]...
127.0.0.1 connected:
file:my_webroot/v0_8_0/test.zl,line:1,breakIndex:0
1    use builtin;

zl debug >>> h
 p 调试变量信息 usage:p express
 b 设置断点 usage:b filename lineNumber[ count] | b lineNumber[ count]
 B 查看断点列表 usage:B
 T 查看脚本函数的堆栈调用信息 usage:T
 d 删除某断点 usage:d breakIndex
 D 禁用某断点 usage:D breakIndex
 C 设置条件断点 usage:C breakIndex condition-express
 L 设置日志断点 usage:L breakIndex log-express
 N 设置断点次数 usage:N breakIndex count
 s 单步步入 usage:s
 S 单步步过 usage:S
 r 执行到返回 usage:r
 c 继续执行 usage:c
 l 显示源码 usage:l filename [lineNumber[ offset]] | l [lineNumber[ offset]]
 u 执行到指定的行 usage:u filename lineNumber | u lineNumber
 h 显示帮助信息

zl debug >>> l 9 10
current run line:1 [my_webroot/v0_8_0/test.zl]
1    use builtin;    <<<---[ current line] ***
2
3    def TRUE 1;
4    def FALSE 0;
5    def MD5_LOWER_CASE 1;
6    def MD5_UPPER_CASE 0;
7    def MD5_32BIT 1;
8    def MD5_16BIT 0;
9
10    print '<!Doctype html>
11    <html>
12    <head><meta http-equiv="content-type" content="text/html;charset=utf-8" />
13    <title>json编解码测试</title>
14    </head>
15    <body>';
16
17    json = '{"hello": "world!!", "name": "zengl", "val": "programmer", "arr":[1,2,3]}';
18
19    json = bltJsonDecode(json);

zl debug >>> u 19
file:my_webroot/v0_8_0/test.zl,line:19,breakIndex:1
19    json = bltJsonDecode(json);

zl debug >>> p json
json :string:{"hello": "world!!", "name": "zengl", "val": "programmer", "arr":[1,2,3]}

zl debug >>> c
listen connection...
^Cexcept...
zengl@zengl-ubuntu:~/zenglServer$
```

通过给python脚本传递参数，可以改变绑定的端口号：

```
zengl@zengl-ubuntu:~/zenglServer$ python3 pydebugger/TCPServer.py 8989
listen connection [port:8989]...
^Cexcept...
zengl@zengl-ubuntu:~/zenglServer$ 
```

在zenglServer的logfile日志中也会记录下用户输入的调试命令：

```
-----------------------------------
Thu Mar  1 09:21:33 2018
recv [client_socket_fd:9] [lst_idx:0] [pid:4664] [tid:4667]:

request header: Host: 127.0.0.1:8083 | User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:55.0) Gecko/20100101 Firefox/55.0 | Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 | Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3 | Accept-Encoding: gzip, deflate | Cookie: __uvt=; uvts=6l2bv2GQOomwZIup | Connection: keep-alive | Upgrade-Insecure-Requests: 1 | Cache-Control: max-age=0 |

url: /v0_8_0/test.zl
url_path: /v0_8_0/test.zl
full_path: my_webroot/v0_8_0/test.zl
zl debug info: Socket created [12]
zl debug info: connecting to 127.0.0.1:9999... connected
zl debug info: debugger command: l test.zl
zl debug info: debugger command: h
zl debug info: debugger command: u 19
zl debug info: debugger command: p json
zl debug info: debugger command: c
zl debug info: close socket [12]
status: 200, content length: 917
response header: HTTP/1.1 200 OK

Content-Type: text/html

Content-Length: 917

Connection: Closed

Server: zenglServer

free socket_list[0]/list_cnt:0 epoll_fd_add_count:0 pid:4664 tid:4667
Termination signal received! Killing children..
All children reaped, shutting down.
closed accept_sem
shutdowned server socket
closed server socket
===================================
```

## 开启编译缓存

从v0.10.0版本开始，可以开启脚本的编译缓存，需要在配置文件中将zengl_cache_enable设置为TRUE：

```
def TRUE 1;
def FALSE 0;

.................................

zengl_cache_enable = FALSE; // 是否开启zengl脚本的编译缓存，默认为FALSE即不开启，设置为TRUE可以开启编译缓存
```

在将zengl_cache_enable设置为TRUE并重启zenglServer后，第一次执行脚本时，会生成该脚本的编译缓存，之后再次执行相同的脚本时，就会使用编译缓存来跳过编译过程。可以在logfile日志文件中查看到相关信息：

```
-----------------------------------
Thu Mar 29 14:33:00 2018
recv [client_socket_fd:9] [lst_idx:0] [pid:5942] [tid:5945]:

request header: Host: 127.0.0.1:8083 | User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:55.0) Gecko/20100101 Firefox/55.0 | Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 | Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3 | Accept-Encoding: gzip, deflate | Connection: keep-alive | Upgrade-Insecure-Requests: 1 | 

url: /v0_8_0/test.zl
url_path: /v0_8_0/test.zl
full_path: my_webroot/v0_8_0/test.zl
can not stat cache file: "zengl/caches/1_8_0_8_68bf762f1d8a4e321fe71affb3b681ab", maybe no such cache file [recompile]
write zengl cache to file "zengl/caches/1_8_0_8_68bf762f1d8a4e321fe71affb3b681ab" success 
status: 200, content length: 918
response header: HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 918
Connection: Closed
Server: zenglServer
free socket_list[0]/list_cnt:0 epoll_fd_add_count:0 pid:5942 tid:5945
-----------------------------------
Thu Mar 29 14:33:05 2018
recv [client_socket_fd:9] [lst_idx:0] [pid:5942] [tid:5945]:

request header: Host: 127.0.0.1:8083 | User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:55.0) Gecko/20100101 Firefox/55.0 | Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 | Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3 | Accept-Encoding: gzip, deflate | Connection: keep-alive | Upgrade-Insecure-Requests: 1 | Cache-Control: max-age=0 | 

url: /v0_8_0/test.zl
url_path: /v0_8_0/test.zl
full_path: my_webroot/v0_8_0/test.zl
reuse cache file: "zengl/caches/1_8_0_8_68bf762f1d8a4e321fe71affb3b681ab" mtime:1522305180
status: 200, content length: 918
response header: HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 918
Connection: Closed
Server: zenglServer
free socket_list[0]/list_cnt:0 epoll_fd_add_count:0 pid:5942 tid:5945
```

编译缓存文件会生成在zengl/caches目录中

从v0.11.0版本开始，可以将编译缓存写入共享内存，需要在配置文件中将shm_enable设置为TRUE(前提是zengl_cache_enable也设置为了TRUE)：

```
def TRUE 1;
def FALSE 0;
def KBYTE 1024;

.................................

shm_enable = FALSE; // 是否将zengl脚本的编译缓存放入共享内存
shm_min_size = 300 * KBYTE; // 需要放进共享内存的缓存的最小大小，只有超过这个大小的缓存才放入共享内存中，以字节为单位

.................................
```

上面还有个配置shm_min_size是需要放入共享内存的缓存的最小大小，默认是300K字节，也就是当编译缓存的大小超过300K时，才会放入共享内存，小于300K的还是使用文件缓存的方式。如果某个缓存使用了共享内存，那么在日志中可以看到和共享内存相关的信息：

```
...................................
[shm:0x1004b2c] reuse cache file: "zengl/caches/1_8_1_8_b8e97748cc5c6b580238f0ee59ad7843" mtime:1529307908
...................................
```

上面的shm:0x1004b2c表示当前缓存所使用的共享内存的key是0x1004b2c，可以通过ipcs -m命令看到系统中有哪些共享内存，并通过这个key找到对应的编译缓存所使用的共享内存。当zenglServer执行结束时，会根据缓存的key自动移除共享内存，在日志中可以看到进程结束时清理的共享内存信息：

```
Termination signal received! Killing children
All children reaped, shutting down.
************ remove shm key: 0x1004b2c [cache_file: 1_8_1_8_b8e97748cc5c6b580238f0ee59ad7843]
------------ remove shm number: 1
closed accept_sem
shutdowned server socket
closed server socket
===================================
```

## 日志分割

从v0.17.0版本开始，增加了对SIGUSR1信号的处理，在主进程接收到该信号时，会重新打开日志文件，同时增加了log_backup.sh脚本，该脚本就利用SIGUSR1信号来实现日志分割：

```
zengl@zengl-ubuntu:~/zenglServer$ ./log_backup.sh
usage: ./log_backup.sh logfile_name pidfile_name
zengl@zengl-ubuntu:~/zenglServer$ ./log_backup.sh logfile zenglServer.pid
zengl@zengl-ubuntu:~/zenglServer$ ls -l log_backup
总用量 0
-rw-r--r--. 1 zengl zengl 10909 1月  12 16:03 logfile_20190112.log
zengl@zengl-ubuntu:~/zenglServer$ 
```

log_backup.sh脚本后面需要跟随日志文件名，例如上面的logfile，然后还要跟随pidfile对应的文件名，例如上面的zenglServer.pid，该脚本会将logfile备份到log_backup目录中。

同时通过SIGUSR1信号让主进程重新打开一个新的日志文件。可以将脚本加入计划任务，从而实现按天来分割日志：

```
zengl@zengl-ubuntu:~/zenglServer$ crontab -l
18 16 * * * cd /home/zengl/zenglServer && ./log_backup.sh logfile zenglServer.pid
zengl@zengl-ubuntu:~/zenglServer$ 
```

### 在命令行中直接运行脚本(v0.18.0版本新增功能)

从v0.18.0版本开始，增加了-r选项，该选项后面可以跟随需要执行的脚本的相对路径和参数，使用该选项后，zenglServer就会以单进程的方式直接在命令行中执行脚本。例如：

```
[root@localhost zenglServerTest]# ./zenglServer -r "/v0_18_0/test_cmd.zl?maxsec=3&name=zl"
now in cmd
name: zl
I'll sleep for 1 seconds
I'll sleep for 2 seconds
I'll sleep for 3 seconds
[root@localhost zenglServerTest]# 
```

通过命令行方式执行脚本时，脚本中通过print指令输出的信息会直接显示到命令行终端。

-r选项还可以配合其他选项一起使用，例如，配合-c选项来指定配置文件等：

```
[root@localhost zenglServerTest]# ./zenglServer -c config.zl -r "/v0_18_0/test_cmd.zl?maxsec=3&name=zl"
now in cmd
name: zl
I'll sleep for 1 seconds
I'll sleep for 2 seconds
^C
[root@localhost zenglServerTest]# 
```

- zenglServer 在CentOS 5.8, 6.x, 7.x, 8.2，以及 Ubuntu 18.04，Ubuntu 20.04中进行了测试。

- zenglServer的C源代码中，加入了必要的注释信息，读者可以通过阅读源码的相关注释来理解代码。

## 官网

更多内容参考官网：http://www.zengl.com

