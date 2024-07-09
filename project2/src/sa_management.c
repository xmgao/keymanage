/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:20:13
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-09 15:58:42
 * @FilePath: \c\keymanage\project2\src\sa_management.c
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */
#include "sa_management.h"
#include "key_management.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INIT_KEYD 100		   // 初始密钥派生参数
#define INIT_KEYM 16		   // 初始OTP密钥块阈值16字节
#define keypool_path "keypool" // 定义本地密钥池文件夹

int spiCount = 0; // 当前SPI个数
SpiParams *dynamicSPI[MAX_DYNAMIC_SPI_COUNT];

void init_sa_management()
{
	// 初始化 SA 管理
	printf("Initializing SA management...\n");
}

void create_sa(int newSPI, int newinbound)
{
	// 创建 SA
	printf("Creating SA...\n");
	dynamicSPI[spiCount] = (SpiParams *)malloc(sizeof(SpiParams));
	char hexStr[64];											// 足够大的字符数组来存储转换后的字符串
	sprintf(hexStr, "%s/%x", keypool_path, newSPI);				// 将数字转换为十六进制字符串
	strcpy(dynamicSPI[spiCount]->keyfile, hexStr);				// 用SPI初始化密钥池名字
	pthread_rwlock_init(&(dynamicSPI[spiCount]->rwlock), NULL); // 初始化读写锁
	if (dynamicSPI[spiCount] != NULL)
	{
		dynamicSPI[spiCount]->spi = newSPI;
		// 初始化其他与SPI相关的参数
		dynamicSPI[spiCount]->encalg = 0;										   // 初始无法知道加密算法
		dynamicSPI[spiCount]->key_sync_flag = false;							   // 密钥索引同步标志设置为false
		dynamicSPI[spiCount]->delkeyindex = 0, dynamicSPI[spiCount]->keyindex = 0; // 初始化密钥偏移
		dynamicSPI[spiCount]->ekeybuff = NULL;
		dynamicSPI[spiCount]->dkeybuff = NULL;
		dynamicSPI[spiCount]->olddkeybuff = NULL;
		dynamicSPI[spiCount]->ekey_rw = 0;
		dynamicSPI[spiCount]->dkey_lw = 0;
		dynamicSPI[spiCount]->dkey_rw = 0;
		// 如果是入站SPI，需要初始化解密参数
		if (newinbound)
		{
			dynamicSPI[spiCount]->in_bound = 1;
			dynamicSPI[spiCount]->myQueue = (Queue *)malloc(sizeof(Queue));
			init_queue(dynamicSPI[spiCount]->myQueue); // 初始化解密密钥派生参数队列
		}
		else
		{
			dynamicSPI[spiCount]->in_bound = 0;
			dynamicSPI[spiCount]->cur_ekeyd = INIT_KEYD; // 初始化加密密钥派生参数
			dynamicSPI[spiCount]->eM = INIT_KEYM;
		}
		// 生成密钥线程
		generate_SAkey(spiCount);
		spiCount++; // 更新计数器
		printf("Memory allocation successed for new SPI.\n");
	}
	else
	{
		printf("Memory allocation failed for new SPI.\n");
	}
}

void delete_sa()
{
	// 删除 SA
	printf("Deleting SA...\n");
}
