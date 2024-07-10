/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:19:23
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-10 15:52:17
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

bool init_tcp_con(int *fd, const char *dest, int port);

void handler_conreq_tcp(int fd, int epfd);

void discon(int fd, int epfd);

void handler_recdata_tcp(int fd, int epfd);

bool CHILDSA_inbound_sync(SpiParams *local_spi);

bool IKESA_keyindex_sync();

bool CHILDSA_keyindex_sync(SpiParams *local_spi);

bool derive_para_sync(SpiParams *local_spi);

bool key_threshold_sync(SpiParams *local_spi);

void encflag_handle(const char *spi, const char *remote_flag, int fd);

void IKESA_keyindex_sync_handle(const char *remote_index, int fd);

void CHILDSA_keyindex_sync_handle(const char *spi, const char *global_index, int fd);

void derive_para_sync_handle(const char *spi, const char *key_d, int fd);

void key_threshold_sync_handle(const char *spi, const char *tmp_eM, int fd);

void *thread_reactor_external();

#endif // EXTERNAL_COMM_H