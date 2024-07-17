/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:20:13
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-17 15:49:02
 * @FilePath: \c\keymanage\project2\src\key_management.c
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */
#include "key_management.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>

pthread_rwlock_t keywr;		// 共享密钥池的读写锁
int key_creat_rate = 16000; // 初始化速率16kBps,密钥产生速率全局变量

void init_key_management()
{
	pthread_rwlock_init(&keywr, NULL); // 初始化读写锁
	pthread_t writethread[3];
	pthread_create(&writethread[0], NULL, thread_IKESA_key_write, NULL); // 密钥写入线程启动
	pthread_detach(writethread[0]);										 // 线程分离
	// 探测线程等待1s再启动
	sleep(1);
	// pthread_create(&writethread[1], NULL, thread_key_lifecycle_manage, NULL); // 密钥管理线程启动
	// pthread_detach(writethread[1]);
	pthread_create(&writethread[2], NULL, thread_keyrate_detection, NULL); // 密钥速率探测线程启动
	pthread_detach(writethread[2]);										   // 线程分离
	// 初始化密钥管理
	printf("Initializing key management...\n");
}

// 传入参数为当前spi的位置,从0开始
void init_CHILDSA_key_generate(int index)
{
	pthread_t thread_id;
	int *thread_arg = (int *)malloc(sizeof(int));
	if (thread_arg == NULL)
	{
		perror("strdup");
		return;
	}
	*thread_arg = index; // 将 int 赋值给 int *
	// 创建子线程
	if (pthread_create(&thread_id, NULL, thread_CHILDSA_key_write, thread_arg) != 0)
	{
		perror("pthread_create");
		free(thread_arg); // 确保在失败时释放内存
		return;
	}
	// 线程分离
	if (pthread_detach(thread_id) != 0)
	{
		perror("pthread_detach");
		return;
	}
	printf("Thread created and detached\n");
}

void store_key(const char *key)
{
	// 存储密钥
	printf("Storing key: %s\n", key);
}

void retrieve_key(char *buffer, int length)
{
	// 检索密钥
	snprintf(buffer, length, "Retrieved key");
}

/**
 * @description:  更新密钥池，更新删除密钥索引
 * @param {SpiParams *} local_spi 本地spi参数的指针
 * @return {*}
 */
void renewSAkey(SpiParams *local_spi)
{
	int delindex = local_spi->keyindex; // 要删除的密钥的索引
	if (delindex == 0)
	{
		return;
	}
	pthread_rwlock_wrlock(&local_spi->rwlock); // 上写锁

	FILE *fp = fopen(local_spi->keyfile, "rb");
	FILE *fp2 = fopen(TEMPKEY_FILE, "wb+");
	if (fp == NULL || fp2 == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	else
	{
		fseek(fp, delindex * 1, SEEK_SET); // 文件指针偏移到指定位置
		char buffer[512];
		size_t bytesRead;
		while ((bytesRead = fread(buffer, 1, 512, fp)) > 0)
		{
			fwrite(buffer, 1, bytesRead, fp2);
		}
		fclose(fp);
		fclose(fp2);
	}
	remove(local_spi->keyfile);
	if (rename(TEMPKEY_FILE, local_spi->keyfile) == 0)
	{
		local_spi->delkeyindex += delindex;
		local_spi->keyindex = 0;
		printf("key pool renewed...\n SPI:%x delkeyindex:%d  keyindex:%d  \n", local_spi->spi, local_spi->delkeyindex, local_spi->keyindex);
	}
	else
	{
		perror("rename error!");
	}
	pthread_rwlock_unlock(&local_spi->rwlock); // 解锁
}

void *thread_key_lifecycle_manage(void *args)
{
	// 模拟不断写入密钥到密钥池文件
	while (1)
	{
		sleep(30);					// 等待30s
		int delindex = IKEkeyindex; // 要删除的密钥的索引
		if (delindex == 0)
		{
			continue;
		}
		pthread_rwlock_wrlock(&keywr); // 上锁
		printf("Expired key cleanup starting...\n");
		FILE *fp = fopen(KEY_FILE, "rb"); // 定位到文件末
		FILE *fp2 = fopen(TEMPKEY_FILE, "wb+");
		if (fp == NULL || fp2 == NULL)
		{
			perror("open keyfile error!\n");
			exit(1);
		}
		else
		{
			fseek(fp, delindex * 1, SEEK_SET); // 文件指针偏移到指定位置
			char buffer[512];
			size_t bytesRead;
			while ((bytesRead = fread(buffer, 1, 512, fp)) > 0)
			{
				fwrite(buffer, 1, bytesRead, fp2);
			}
			fclose(fp);
			fclose(fp2);
		}
		remove(KEY_FILE);
		if (rename(TEMPKEY_FILE, KEY_FILE) == 0)
		{
			IKEkeyindex = 0;
			printf("IKE key pool renew success! \n");
		}
		else
		{
			perror("rename error!");
		}
		pthread_rwlock_unlock(&keywr); // 解锁
		for (int i = 0; i < spiCount; i++)
		{
			renewSAkey(dynamicSPI[i]);
		}
	}
}

// 密钥速率探测
void *thread_keyrate_detection(void *args)
{
	printf("key_rate_detection starting...\n");
	// 首先定义文件指针：fp
	FILE *fp;
	int prefilelen = 0;
	int nextfilelen = 0;
	int detetctime = 2000000; // 探测时间，单位us
	while (1)
	{
		pthread_rwlock_rdlock(&keywr); // 上读锁
		fp = fopen(KEY_FILE, "rb");
		fseek(fp, 0, SEEK_END);	 // 定位到文件末
		nextfilelen = ftell(fp); // 文件长度
		fclose(fp);
		pthread_rwlock_unlock(&keywr); // 解锁
		if (prefilelen == 0)
		{
			prefilelen = nextfilelen;
		}
		else
		{
			// 此时探测密钥速率
			key_creat_rate = (int)((nextfilelen - prefilelen) / 2); // kBps
			// printf("key_creat_rate: %d kbps\n", key_creat_rate*8);
			prefilelen = nextfilelen;
		}
		usleep(detetctime); // 等待2s
	}
	pthread_exit(0);
}

// 密钥重放器
void *thread_CHILDSA_key_write(void *args)
{
	int *index_ptr = (int *)args;
	int index = *index_ptr;
	sleep(1);
	printf("CHILDSAkey supply starting \t Thread is processing the SAindex: %d\n", index);
	FILE *file = fopen("rawkeyfile.kf", "rb"); // 格式化的密钥重放文件
	if (file == NULL)
	{
		perror("Error opening file");
		pthread_exit(0);
	}
	unsigned char block[522]; // 8字节时间戳+2字节密钥长度(512)+512字节密钥
	time_t prevTimestamp = 0;
	while (fread(block, sizeof(char), sizeof(block), file) == sizeof(block))
	{
		// 提取时间戳
		time_t currentTimestamp;
		memcpy(&currentTimestamp, block, sizeof(uint64_t));
		if (prevTimestamp != 0)
		{
			// 单位纳秒
			time_t interval = currentTimestamp - prevTimestamp;
			unsigned char key[512];
			memcpy(key, block + sizeof(uint64_t) + 2, 512);
			// 为SA写密钥
			pthread_rwlock_wrlock(&dynamicSPI[index]->rwlock); // 上写锁
			FILE *fp2 = fopen(dynamicSPI[index]->keyfile, "ab+");
			fseek(fp2, 0, SEEK_END); // 定位到文件末
			fwrite(key, sizeof(unsigned char), 512, fp2);
			fclose(fp2);
			pthread_rwlock_unlock(&dynamicSPI[index]->rwlock); // 解锁
			// 按照指定间隔暂停程序执行,微妙
			usleep((int)(interval / 1000));
		}
		prevTimestamp = currentTimestamp;
		if (dynamicSPI[index]->is_destory)
			break;
	}
	fclose(file);
	free(index_ptr); // 确保释放分配的内存
}

// 密钥重放器
void *thread_IKESA_key_write(void *args)
{
	printf("sharedkey supply starting...\n");
	FILE *file = fopen("rawkeyfile.kf", "rb"); // 格式化的密钥重放文件
	if (file == NULL)
	{
		perror("Error opening file");
		pthread_exit(0);
	}
	unsigned char block[522]; // 8字节时间戳+2字节密钥长度(512字节)+512字节密钥
	time_t prevTimestamp = 0;
	while (fread(block, sizeof(char), sizeof(block), file) == sizeof(block))
	{
		// 提取时间戳
		time_t currentTimestamp;
		memcpy(&currentTimestamp, block, sizeof(uint64_t));
		if (prevTimestamp != 0)
		{
			// 单位纳秒
			time_t interval = currentTimestamp - prevTimestamp;
			// 执行操作，暂停指定间隔
			// printf("Performing operation with interval: %.2f mseconds\n", (float)interval/ 1000000);
			unsigned char key[512];
			memcpy(key, block + sizeof(uint64_t) + 2, 512);
			pthread_rwlock_wrlock(&keywr); // 上锁
			// 首先定义文件指针：fp
			FILE *fp = fopen(KEY_FILE, "ab+");
			fseek(fp, 0, SEEK_END);	  // 定位到文件末
			int nFileLen = ftell(fp); // 文件长度
			if (nFileLen < MAX_KEYFILE_SIZE)
			{
				fwrite(key, sizeof(unsigned char), 512, fp);
			}
			fclose(fp);
			pthread_rwlock_unlock(&keywr); // 解锁
			// 按照指定间隔暂停程序执行,微妙
			usleep((int)(interval / 1000));
		}
		prevTimestamp = currentTimestamp;
	}
	fclose(file);

	pthread_exit(0);
}

/**
 * @description: 读取DH密钥和预共享密钥，为他们单独提供一个密钥池
 * @param {char} *buf	保存密钥的缓存数组
 * @param {int} len		需要密钥的长度
 * @return {*}
 */
void IKESA_key_read(char *const buf, int len)
{
	char *pb = buf;
	pthread_rwlock_rdlock(&keywr); // 上读锁
	FILE *fp = fopen(KEY_FILE, "rb");
	if (fp == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	while (1)
	{
		fseek(fp, IKEkeyindex, SEEK_SET); // 将文件指针偏移到指定位置
		int bytes_read = fread(pb, sizeof(char), len, fp);
		// 在 buffer 中有 bytes_read 个字节的数据，其中可能包含空字符
		if (bytes_read == len)
		{
			break;
		}
		else
		{
			printf("key supply empty!\n");
			pthread_rwlock_unlock(&keywr); // 解锁
			sleep(1);
			pthread_rwlock_rdlock(&keywr); // 上读锁
			printf("key require try again!\n");
		}
	}
	IKEkeyindex += len;
	fclose(fp);
	pthread_rwlock_unlock(&keywr); // 解锁
}

/**
 * @description:  读取本地SA会话密钥
 * @param {SpiParams *} local_spi 本地spi参数的指针
 * @param {char} *buf 保存密钥的缓存数组
 * @param {int} len 需要密钥的长度
 * @return {*}
 */
void CHILDSA_key_read(SpiParams *local_spi, char *const buf, int len)
{
	char *pb = buf;
	pthread_rwlock_rdlock(&(local_spi->rwlock)); // 上读锁
	FILE *fp = fopen(local_spi->keyfile, "rb");
	if (fp == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	int keyindex = local_spi->keyindex;
	while (1)
	{
		fseek(fp, keyindex, SEEK_SET); // 将文件指针偏移到指定位置
		int bytes_read = fread(pb, sizeof(char), len, fp);
		if (bytes_read == len)
		{
			// 在 buffer 中有 bytes_read 个字节的数据，其中可能包含空字符
			break;
		}
		else
		{
			printf("key supply empty!\n");
			pthread_rwlock_unlock(&local_spi->rwlock); // 解锁
			sleep(1);
			pthread_rwlock_rdlock(&local_spi->rwlock); // 上读锁
			printf("key require try again!\n");
		}
	}
	keyindex += len;
	local_spi->keyindex = keyindex;
	fclose(fp);
	pthread_rwlock_unlock(&local_spi->rwlock); // 解锁
}