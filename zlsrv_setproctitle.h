/*
 * zlsrv_setproctitle.h
 *
 *  Created on: Dec 16, 2018
 *      Author: zengl
 */

#ifndef ZLSRV_SETPROCTITLE_H_
#define ZLSRV_SETPROCTITLE_H_

int zlsrv_init_setproctitle(char ** errorstr);

void zlsrv_setproctitle(char * title);

#endif /* ZLSRV_SETPROCTITLE_H_ */
