/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:19:23
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-09 11:34:28
 * @FilePath: \c\keymanage\project2\include\external_comm.h
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */
#ifndef EXTERNAL_COMM_H
#define EXTERNAL_COMM_H

#include "sa_management.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <netinet/in.h>

extern int SERV_PORT;	   // 服务器监听端口
extern char remote_ip[32]; // 记录远程ip地址

typedef struct HandleData
{
	char method[32 + 1];
	char arg1[16 + 1];
	char arg2[16 + 1];
	char arg3[16 + 1];
	char arg4[16 + 1];
} HandleData;

void init_external_comm();

void create_hmac_packet(const char *method, const char data[][17], int data_count, unsigned char *packet);

int verify_hmac_packet(const unsigned char *packet);

int init_listen_external(int port, int epfd);

bool con_tcpserv(int *fd, const char *dest, int port);

void handler_conreq_tcp(int fd, int epfd);

static void discon(int fd, int epfd);

void handler_recdata_tcp(int fd, int epfd);

bool encflag_sync(SpiParams *local_spi);

bool IKESAkey_sync();

bool key_index_sync(SpiParams *local_spi);

bool derive_sync(SpiParams *local_spi);

bool eM_sync(SpiParams *local_spi);

void encflag_handle(const char *spi, const char *remote_flag, int fd);

void SAkey_sync_handle(const char *remote_index, int fd);

void keysync_handle(const char *spi, const char *global_index, int fd);

void desync_handle(const char *spi, const char *key_d, int fd);

void eMsync_handle(const char *spi, const char *tmp_eM, int fd);

void *reactor_external_socket();

#endif // EXTERNAL_COMM_H