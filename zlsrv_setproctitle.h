/*
 * zlsrv_setproctitle.h
 *
 *  Created on: Dec 16, 2018
 *      Author: zengl
 */

#ifndef ZLSRV_SETPROCTITLE_H_
#define ZLSRV_SETPROCTITLE_H_

/**
 * 设置进程名称的初始化操作，在设置进程名称之前，需要先将环境变量拷贝到新建的堆空间中，
 * 并将environ数组中包含的旧的环境变量指针指向新的堆空间，在将环境变量拷贝出去后，
 * 就可以设置很长的进程名称了，设置进程名称的原理是将进程main函数的argv[0]指向的字符串进行修改，
 * 但是argv[0]指向的原字符串可能很短，这样当设置较长的进程名称时，就会溢出，
 * 而进程main函数的argv参数列表后面紧跟的是环境变量，因此就会将环境变量给破坏掉，
 * 所以在设置新的进程名称之前，需要先将环境变量拷贝一份，并将环境变量指针指向拷贝数据
 *
 * 函数代码参考自nginx的代码，参考地址：https://github.com/firebase/nginx/blob/master/src/os/unix/ngx_setproctitle.c
 */
int zlsrv_init_setproctitle(char ** errorstr);

/**
 * 在执行了上面的初始化操作后，就可以使用下面这个函数来设置当前进程的名称，
 * 设置进程名称时，只需将新的进程名称，拷贝到进程main函数的argv[0]所指向的内存空间中即可，
 * 在设置了新的进程名称后，还将进程名称之后的原有的残留数据给清空了(包括参数列表后的环境变量，环境变量已经在初始化时拷贝出去了，所以没有影响)，
 * 防止ps在显示进程名称时，将进程名之后的原来残留的数据当作参数列表给显示出来。
 */
void zlsrv_setproctitle(char * title);

#endif /* ZLSRV_SETPROCTITLE_H_ */
