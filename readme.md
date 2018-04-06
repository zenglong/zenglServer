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
gcc -g3 -ggdb -O0 -std=c99 main.c http_parser.c module_request.c module_builtin.c module_session.c dynamic_string.c multipart_parser.c resources.c client_socket_list.c json.c randutils.c md5.c debug.c main.h http_parser.h common_header.h module_request.h module_builtin.h module_session.h dynamic_string.h multipart_parser.h resources.h client_socket_list.h json.h randutils.h md5.h debug.h zengl/linux/zengl_exportfuns.h  -o zenglServer zengl/linux/libzengl.a crustache/libcrustache.a -lpthread -lm 

*** notice: mysql module not enabled, you can use 'make USE_MYSQL=yes' to enable it, make sure you have mysql_config and mysql.h in your system! ***
zengl@zengl-ubuntu:~/zenglServer$ 
```

第一次编译时，它会先进入zengl/linux目录，编译生成libzengl.a的静态库文件，该静态库主要用于执行zengl脚本。

如果要删除编译生成的文件的话，直接输入make clean即可。每次git pull拉取新的zenglServer版本时，最好都make clean一下，然后再make，这样可以确保修改的代码能够被及时编译，尤其是当zenglServer所依赖的libzengl.a和libcrustache.a的相关源码发生改变时。

从v0.4.0版本开始，zenglServer使用epoll来处理请求，因此，需要先确定linux支持epoll，epoll的API是从linux kernel 2.5.44开始引入的

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
gcc -g3 -ggdb -O0 -std=c99 main.c http_parser.c module_request.c module_builtin.c module_session.c dynamic_string.c multipart_parser.c resources.c client_socket_list.c json.c randutils.c md5.c debug.c main.h http_parser.h common_header.h module_request.h module_builtin.h module_session.h dynamic_string.h multipart_parser.h resources.h client_socket_list.h json.h randutils.h md5.h debug.h module_mysql.c module_mysql.h  zengl/linux/zengl_exportfuns.h  -o zenglServer zengl/linux/libzengl.a crustache/libcrustache.a -lpthread -lm -DUSE_MYSQL `mysql_config --cflags --libs` 

mysql module is enabled!!!
zengl@zengl-ubuntu:~/zenglServer$ 
```

- 注意：在加入mysql模块前，请确保你的系统中包含了mysql_config程式和mysql.h开发头文件，如果没有的话，如果是ubuntu系统，可以通过sudo apt-get install libmysqlclient-dev来添加开发mysql客户端所需要的文件，如果是centos系统，则可以通过yum install mysql-devel来加入开发所需的文件。

## 使用

在根目录中，有一个config.zl的默认配置文件(使用zengl脚本语法编写)，该配置文件里定义了zenglServer需要绑定的端口号，需要启动的进程数等：

```
def TRUE 1;
def FALSE 0;

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
```

在编译成功后，直接运行生成好的zenglServer可执行文件即可(从v0.4.0版本开始，zenglServer默认以守护进程模式启动，并采用epoll方式来处理请求)：

```
zengl@zengl-ubuntu:~/zenglServer$ ./zenglServer 
zengl@zengl-ubuntu:~/zenglServer$ ps -aux | grep zenglServer
zengl      300  0.0  0.0  26440  2124 ?        Ss   19:08   0:00 zenglServer: master
zengl      301  0.0  0.0  42832   528 ?        Sl   19:08   0:00 zenglServer: child(0)
zengl      302  0.0  0.0  26440   528 ?        S    19:08   0:00 zenglServer: cleaner
zengl@zengl-ubuntu:~/zenglServer$ cat logfile
create master process for daemon [pid:300]
use default config: config.zl
*** config is in debug mode ***
run config.zl complete, config:
port: 8083 process_num: 1
webroot: my_webroot
session_dir: my_sessions session_expire: 1440 cleaner_interval: 3600
remote_debug_enable: False remote_debugger_ip: 127.0.0.1 remote_debugger_port: 9999 zengl_cache_enable: False
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

要退出zenglServer，需要kill掉主进程(名称为zenglServer: master的进程)，注意：kill子进程的话，主进程会自动重启子进程：

```
zengl@zengl-ubuntu:~/zenglServer$ ps aux | grep zenglServer
zengl      300  0.0  0.0  26440  2124 ?        Ss   19:08   0:00 zenglServer: master
zengl      301  0.0  0.0 108368   528 ?        Sl   19:08   0:00 zenglServer: child(0)
zengl      302  0.0  0.0  26440   528 ?        S    19:08   0:00 zenglServer: cleaner
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

zenglServer有几个可选的命令行参数，可以使用-h查看帮助信息：

```
zengl@zengl-ubuntu:~/zenglServer$ ./zenglServer -h
usage: ./zenglServer [options]
-v                  show version
-c <config file>    set config file
-h                  show this help
zengl@zengl-ubuntu:~/zenglServer$ 
```

通过-v可以查看zenglServer的版本号以及所使用的zengl脚本语言的版本号，-c可以指定需要加载的配置文件(配置文件必须使用zengl脚本语法编写)：

```
zengl@zengl-ubuntu:~/zenglServer$ ./zenglServer -v
zenglServer version: v0.10.1
zengl language version: v1.8.1
zengl@zengl-ubuntu:~/zenglServer$ ./zenglServer -c config.zl
zengl@zengl-ubuntu:~/zenglServer$ tail -f logfile 
use config: config.zl
*** config is in debug mode ***
run config.zl complete, config: 
port: 8083 process_num: 1
webroot: my_webroot
session_dir: my_sessions session_expire: 1440 cleaner_interval: 3600
remote_debug_enable: False remote_debugger_ip: 127.0.0.1 remote_debugger_port: 9999 zengl_cache_enable: False
bind done
accept sem initialized.
process_max_open_fd_num: 1024 
Master: Spawning child(0) [pid 673] 
Master: Spawning cleaner [pid 674] 
epoll max fd count : 896
------------ cleaner sleep begin: 1515237890
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

- zenglServer是在Ubuntu 16.04 LTS x86-64(GCC版本号为：5.4.0)，Ubuntu 17.04 x86-64(GCC版本号为：6.3.0)中进行的开发测试，并在CentOS 5.8, 6.x, 7.x中进行了简单的测试。

- zenglServer的C源代码中，加入了必要的注释信息，读者可以通过阅读源码的相关注释来理解代码。

## 官网

更多内容参考官网：http://www.zengl.com

