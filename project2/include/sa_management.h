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

#define OTPTH 128				  // OTP原始密钥上界128字节
#define MAX_DYNAMIC_SPI_COUNT 100 // 最多同时存在SPI个数

typedef struct SpiParams SpiParams;

extern SpiParams *dynamicSPI[MAX_DYNAMIC_SPI_COUNT];
extern int IKEkeyindex;		 // 用于标识本地SA密钥池索引。
extern bool SAkey_sync_flag; // 密钥同步标志，用于供应sa协商
extern int spiCount;		 // 当前SPI个数

// 用于OTP的密钥块结构体
typedef struct Keyblock
{
	char key[OTPTH + 1];
	int size;
} Keyblock;

// 结构体定义，存储与每个SPI相关的参数
struct SpiParams
{
	int spi;												   // SPI值，用数字表示,net字节序
	int encalg;												   // 当前加密算法值，用数字表示，0表示暂无，1表示动态派生，2表示一次一密
	int encalg_keysize;										   // 当前加密算法值密钥长度
	bool in_bound;											   // true如果是入站SPI
	char keyfile[100];										   // spi对应的密钥池文件名
	bool key_sync_flag;										   // 密钥索引同步标志
	int delkeyindex, keyindex;								   // 密钥索引，用于删除过期密钥，标识当前的密钥
	int cur_ekeyd;											   // 记录当前的加密密钥派生参数
	char raw_ekey[64 + 1], raw_dkey[64 + 1], old_dkey[64 + 1]; // 记录原始量子密钥
	Queue *myQueue;											   // 解密参数队列，otp和sk复用
	int eM;													   // 加密密钥阈值，解密密钥阈值存在队列里
	Keyblock *ekeybuff, *dkeybuff, *olddkeybuff;
	int ekey_rw, dkey_lw, dkey_rw; // 加密右窗口，解密左窗口，解密右窗口
	pthread_rwlock_t rwlock;	   // 读写锁变量
	struct timeval pre_t, cur_t;   // 更新时间变量
	bool is_destory;  //判断当前spi是否被销毁
};

void init_sa_management();

void create_sa(int newSPI, int newinbound);

void delete_sa(int delSPI);

#endif // SA_MANAGEMENT_H