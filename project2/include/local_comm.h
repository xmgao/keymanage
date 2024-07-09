/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:19:08
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-09 11:34:53
 * @FilePath: \c\keymanage\project2\include\local_comm.h
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */
#ifndef LOCAL_COMM_H
#define LOCAL_COMM_H

#include "sa_management.h"
#include "external_comm.h"

#include <sys/un.h>

void init_local_comm();

int init_listen_local(int epfd);

bool con_unixserv(int *fd);

void handler_conreq_unix(int fd, int epfd);

static void discon(int fd, int epfd);

void handler_recdata_unix(int fd, int epfd);

void getsharedkey_handle(const char *keylen, int fd);

void getsk_handle(const char *spi, const char *keylen, const char *syn, const char *key_type, int fd);

void getotpk_handle(const char *spi, const char *syn, const char *key_type, int fd);

void spiregister_handle(const char *spi, const char *inbound);

void *reactor_local_socket();

#endif // LOCAL_COMM_H