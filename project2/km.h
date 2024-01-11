/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2023-12-24 14:57:56
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-01-11 16:49:36
 * @FilePath: \c\keymanage\project2\km.h
 * @Description:
 *
 * Copyright (c) 2023 by ${git_name_email}, All Rights Reserved.
 */

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <error.h>
#include <dirent.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

// ���������������г���
#define MAX_QUEUE_SIZE 1000
#define OTPTH 128 // OTPԭʼ��Կ�Ͻ�128�ֽ�

typedef struct
{
	int data[MAX_QUEUE_SIZE];
	int front;
	int rear;
} Queue;

// ��ʼ������
void initializeQueue(Queue *queue)
{
	queue->front = -1;
	queue->rear = -1;
}

// �������Ƿ�Ϊ��
int isEmpty(Queue *queue)
{
	return (queue->front == -1 && queue->rear == -1);
}

// �������Ƿ�����
int isFull(Queue *queue)
{
	return ((queue->rear + 1) % MAX_QUEUE_SIZE == queue->front);
}

// ���
/**
 * @description:
 * @param {Queue} *queue
 * @param {int} value
 * @return {*}
 */
void enqueue(Queue *queue, int value)
{
	if (isFull(queue))
	{
		perror("Queue is full. Cannot enqueue.\n");
		return;
	}
	else if (isEmpty(queue))
	{
		queue->front = 0;
		queue->rear = 0;
	}
	else
	{
		queue->rear = (queue->rear + 1) % MAX_QUEUE_SIZE;
	}
	queue->data[queue->rear] = value;
}

// ����
int dequeue(Queue *queue)
{
	int value;
	if (isEmpty(queue))
	{
		perror("Queue is empty. Cannot dequeue.\n");
		return -1; // �������ʧ��
	}
	else if (queue->front == queue->rear)
	{
		value = queue->data[queue->front];
		queue->front = -1;
		queue->rear = -1;
	}
	else
	{
		value = queue->data[queue->front];
		queue->front = (queue->front + 1) % MAX_QUEUE_SIZE;
	}
	return value;
}

// ����OTP����Կ��ṹ��
typedef struct
{
	char key[OTPTH + 1];
	int size;
} Keyblock;

// �ṹ�嶨�壬�洢��ÿ��SPI��صĲ���
typedef struct SpiParams
{
	int spi;												   // SPIֵ�������ֱ�ʾ
	bool in_bound;											   // true�������վSPI
	char keyfile[100];										   // spi��Ӧ����Կ���ļ���
	bool key_sync_flag;										   // ��Կ����ͬ����־
	int delkeyindex, keyindex;								   // ��Կ����������ɾ��������Կ����ʶ��ǰ����Կ
	int encrypt_flag;										   // ������Կ�Լ�������Կ�Ķ�Ӧ��ϵ��0��ʶ���ܣ�1��ʶ����
	int cur_ekeyd;											   // ��¼��ǰ�ļ�����Կ��������
	char raw_ekey[64 + 1], raw_dkey[64 + 1], old_dkey[64 + 1]; // ��¼ԭʼ������Կ
	Queue myQueue;											   // ���ܲ������У�otp��sk����
	int eM;													   // ������Կ��ֵ��������Կ��ֵ���ڶ�����
	Keyblock *ekeybuff, *dkeybuff, *olddkeybuff;
	int ekey_rw, dkey_lw, dkey_rw; // �����Ҵ��ڣ������󴰿ڣ������Ҵ���
	pthread_rwlock_t rwlock;	   // ��д������
	pthread_mutex_t mutex;		   // ����������
	struct timeval pre_t, cur_t;   // ����ʱ�����
} SpiParams;

typedef struct HandleData
{
	char method[32];
	char arg1[16];
	char arg2[16];
	char arg3[16];
	char arg4[16];
	int fd;
} HandleData;

int init_listen_local(int epfd);

int init_listen_external(int port, int epfd);

bool con_tcpserv(int *fd, const char *dest, int port);

bool con_unixserv(int *fd);

void handler_conreq_tcp(int fd, int epfd);

void handler_conreq_unix(int fd, int epfd);

void discon(int fd, int epfd);

void handler_recdata_unix(int fd, int epfd);

void handler_recdata_tcp(int fd, int epfd);

bool encflag_sync(SpiParams *local_spi);

bool SAkey_sync();

bool key_index_sync(SpiParams *local_spi);

bool derive_sync(SpiParams *local_spi);

bool eM_sync(SpiParams *local_spi);

void renewkey(SpiParams *local_spi);

void readFilesInFolder(const char *folderPath, FILE *fp);

void *thread_writeSAkey(void *args);

void *thread_writesharedkey(void *args);

void readsharedkey(char *const buf, int len);

void readSAkey(SpiParams *local_spi, char *const buf, int len);

void getsharedkey_handle(const char *keylen, int fd);

void getsk_handle(const char *spi, const char *keylen, const char *syn, const char *key_type, int fd);

void getotpk_handle(const char *spi, const char *syn, const char *key_type, int fd);

void spiregister_handle(const char *spi, const char *inbound, int fd);

void encflag_handle(const char *spi, const char *remote_flag, int fd);

void SAkey_sync_handle(const char *remote_index, int fd);

void keysync_handle(const char *spi, const char *global_index, int fd);

void desync_handle(const char *spi, const char *key_d, int fd);

void eMsync_handle(const char *spi, const char *tmp_eM, int fd);

void *reactor_local_socket();

void *reactor_external_socket();
