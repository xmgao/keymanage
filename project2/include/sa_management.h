/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:19:24
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-10 16:10:43
 * @FilePath: \c\keymanage\project2\include\sa_management.h
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */
#ifndef SA_MANAGEMENT_H
#define SA_MANAGEMENT_H

#include "queue.h"
#include <sys/time.h>
#include <stdbool.h>
#include <pthread.h>

#define OTPTH 128				  // OTPԭʼ��Կ�Ͻ�128�ֽ�
#define MAX_DYNAMIC_SPI_COUNT 100 // ���ͬʱ����SPI����

typedef struct SpiParams SpiParams;

extern SpiParams *dynamicSPI[MAX_DYNAMIC_SPI_COUNT];
extern int IKEkeyindex;		 // ���ڱ�ʶ����SA��Կ��������
extern bool SAkey_sync_flag; // ��Կͬ����־�����ڹ�ӦsaЭ��
extern int spiCount;		 // ��ǰSPI����

// ����OTP����Կ��ṹ��
typedef struct Keyblock
{
	char key[OTPTH + 1];
	int size;
} Keyblock;

// �ṹ�嶨�壬�洢��ÿ��SPI��صĲ���
struct SpiParams
{
	int spi;												   // SPIֵ�������ֱ�ʾ,net�ֽ���
	int encalg;												   // ��ǰ�����㷨ֵ�������ֱ�ʾ��0��ʾ���ޣ�1��ʾ��̬������2��ʾһ��һ��
	int encalg_keysize;										   // ��ǰ�����㷨ֵ��Կ����
	bool in_bound;											   // true�������վSPI
	char keyfile[100];										   // spi��Ӧ����Կ���ļ���
	bool key_sync_flag;										   // ��Կ����ͬ����־
	int delkeyindex, keyindex;								   // ��Կ����������ɾ��������Կ����ʶ��ǰ����Կ
	int cur_ekeyd;											   // ��¼��ǰ�ļ�����Կ��������
	char raw_ekey[64 + 1], raw_dkey[64 + 1], old_dkey[64 + 1]; // ��¼ԭʼ������Կ
	Queue *myQueue;											   // ���ܲ������У�otp��sk����
	int eM;													   // ������Կ��ֵ��������Կ��ֵ���ڶ�����
	Keyblock *ekeybuff, *dkeybuff, *olddkeybuff;
	int ekey_rw, dkey_lw, dkey_rw; // �����Ҵ��ڣ������󴰿ڣ������Ҵ���
	pthread_rwlock_t rwlock;	   // ��д������
	struct timeval pre_t, cur_t;   // ����ʱ�����
	bool is_destory;  //�жϵ�ǰspi�Ƿ�����
};

void init_sa_management();

void create_sa(int newSPI, int newinbound);

void delete_sa(int delSPI);

#endif // SA_MANAGEMENT_H