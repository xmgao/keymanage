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

pthread_rwlock_t keywr;		// ������Կ�صĶ�д��
int key_creat_rate = 16000; // ��ʼ������16kBps,��Կ��������ȫ�ֱ���

void init_key_management()
{
	pthread_rwlock_init(&keywr, NULL); // ��ʼ����д��
	pthread_t writethread[3];
	pthread_create(&writethread[0], NULL, thread_IKESA_key_write, NULL); // ��Կд���߳�����
	pthread_detach(writethread[0]);										 // �̷߳���
	// ̽���̵߳ȴ�1s������
	sleep(1);
	// pthread_create(&writethread[1], NULL, thread_key_lifecycle_manage, NULL); // ��Կ�����߳�����
	// pthread_detach(writethread[1]);
	pthread_create(&writethread[2], NULL, thread_keyrate_detection, NULL); // ��Կ����̽���߳�����
	pthread_detach(writethread[2]);										   // �̷߳���
	// ��ʼ����Կ����
	printf("Initializing key management...\n");
}

// �������Ϊ��ǰspi��λ��,��0��ʼ
void init_CHILDSA_key_generate(int index)
{
	pthread_t thread_id;
	int *thread_arg = (int *)malloc(sizeof(int));
	if (thread_arg == NULL)
	{
		perror("strdup");
		return;
	}
	*thread_arg = index; // �� int ��ֵ�� int *
	// �������߳�
	if (pthread_create(&thread_id, NULL, thread_CHILDSA_key_write, thread_arg) != 0)
	{
		perror("pthread_create");
		free(thread_arg); // ȷ����ʧ��ʱ�ͷ��ڴ�
		return;
	}
	// �̷߳���
	if (pthread_detach(thread_id) != 0)
	{
		perror("pthread_detach");
		return;
	}
	printf("Thread created and detached\n");
}

void store_key(const char *key)
{
	// �洢��Կ
	printf("Storing key: %s\n", key);
}

void retrieve_key(char *buffer, int length)
{
	// ������Կ
	snprintf(buffer, length, "Retrieved key");
}

/**
 * @description:  ������Կ�أ�����ɾ����Կ����
 * @param {SpiParams *} local_spi ����spi������ָ��
 * @return {*}
 */
void renewSAkey(SpiParams *local_spi)
{
	int delindex = local_spi->keyindex; // Ҫɾ������Կ������
	if (delindex == 0)
	{
		return;
	}
	pthread_rwlock_wrlock(&local_spi->rwlock); // ��д��

	FILE *fp = fopen(local_spi->keyfile, "rb");
	FILE *fp2 = fopen(TEMPKEY_FILE, "wb+");
	if (fp == NULL || fp2 == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	else
	{
		fseek(fp, delindex * 1, SEEK_SET); // �ļ�ָ��ƫ�Ƶ�ָ��λ��
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
	pthread_rwlock_unlock(&local_spi->rwlock); // ����
}

void *thread_key_lifecycle_manage(void *args)
{
	// ģ�ⲻ��д����Կ����Կ���ļ�
	while (1)
	{
		sleep(30);					// �ȴ�30s
		int delindex = IKEkeyindex; // Ҫɾ������Կ������
		if (delindex == 0)
		{
			continue;
		}
		pthread_rwlock_wrlock(&keywr); // ����
		printf("Expired key cleanup starting...\n");
		FILE *fp = fopen(KEY_FILE, "rb"); // ��λ���ļ�ĩ
		FILE *fp2 = fopen(TEMPKEY_FILE, "wb+");
		if (fp == NULL || fp2 == NULL)
		{
			perror("open keyfile error!\n");
			exit(1);
		}
		else
		{
			fseek(fp, delindex * 1, SEEK_SET); // �ļ�ָ��ƫ�Ƶ�ָ��λ��
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
		pthread_rwlock_unlock(&keywr); // ����
		for (int i = 0; i < spiCount; i++)
		{
			renewSAkey(dynamicSPI[i]);
		}
	}
}

// ��Կ����̽��
void *thread_keyrate_detection(void *args)
{
	printf("key_rate_detection starting...\n");
	// ���ȶ����ļ�ָ�룺fp
	FILE *fp;
	int prefilelen = 0;
	int nextfilelen = 0;
	int detetctime = 2000000; // ̽��ʱ�䣬��λus
	while (1)
	{
		pthread_rwlock_rdlock(&keywr); // �϶���
		fp = fopen(KEY_FILE, "rb");
		fseek(fp, 0, SEEK_END);	 // ��λ���ļ�ĩ
		nextfilelen = ftell(fp); // �ļ�����
		fclose(fp);
		pthread_rwlock_unlock(&keywr); // ����
		if (prefilelen == 0)
		{
			prefilelen = nextfilelen;
		}
		else
		{
			// ��ʱ̽����Կ����
			key_creat_rate = (int)((nextfilelen - prefilelen) / 2); // kBps
			// printf("key_creat_rate: %d kbps\n", key_creat_rate*8);
			prefilelen = nextfilelen;
		}
		usleep(detetctime); // �ȴ�2s
	}
	pthread_exit(0);
}

// ��Կ�ط���
void *thread_CHILDSA_key_write(void *args)
{
	int *index_ptr = (int *)args;
	int index = *index_ptr;
	sleep(1);
	printf("CHILDSAkey supply starting \t Thread is processing the SAindex: %d\n", index);
	FILE *file = fopen("rawkeyfile.kf", "rb"); // ��ʽ������Կ�ط��ļ�
	if (file == NULL)
	{
		perror("Error opening file");
		pthread_exit(0);
	}
	unsigned char block[522]; // 8�ֽ�ʱ���+2�ֽ���Կ����(512)+512�ֽ���Կ
	time_t prevTimestamp = 0;
	while (fread(block, sizeof(char), sizeof(block), file) == sizeof(block))
	{
		// ��ȡʱ���
		time_t currentTimestamp;
		memcpy(&currentTimestamp, block, sizeof(uint64_t));
		if (prevTimestamp != 0)
		{
			// ��λ����
			time_t interval = currentTimestamp - prevTimestamp;
			unsigned char key[512];
			memcpy(key, block + sizeof(uint64_t) + 2, 512);
			// ΪSAд��Կ
			pthread_rwlock_wrlock(&dynamicSPI[index]->rwlock); // ��д��
			FILE *fp2 = fopen(dynamicSPI[index]->keyfile, "ab+");
			fseek(fp2, 0, SEEK_END); // ��λ���ļ�ĩ
			fwrite(key, sizeof(unsigned char), 512, fp2);
			fclose(fp2);
			pthread_rwlock_unlock(&dynamicSPI[index]->rwlock); // ����
			// ����ָ�������ͣ����ִ��,΢��
			usleep((int)(interval / 1000));
		}
		prevTimestamp = currentTimestamp;
		if (dynamicSPI[index]->is_destory)
			break;
	}
	fclose(file);
	free(index_ptr); // ȷ���ͷŷ�����ڴ�
}

// ��Կ�ط���
void *thread_IKESA_key_write(void *args)
{
	printf("sharedkey supply starting...\n");
	FILE *file = fopen("rawkeyfile.kf", "rb"); // ��ʽ������Կ�ط��ļ�
	if (file == NULL)
	{
		perror("Error opening file");
		pthread_exit(0);
	}
	unsigned char block[522]; // 8�ֽ�ʱ���+2�ֽ���Կ����(512�ֽ�)+512�ֽ���Կ
	time_t prevTimestamp = 0;
	while (fread(block, sizeof(char), sizeof(block), file) == sizeof(block))
	{
		// ��ȡʱ���
		time_t currentTimestamp;
		memcpy(&currentTimestamp, block, sizeof(uint64_t));
		if (prevTimestamp != 0)
		{
			// ��λ����
			time_t interval = currentTimestamp - prevTimestamp;
			// ִ�в�������ָͣ�����
			// printf("Performing operation with interval: %.2f mseconds\n", (float)interval/ 1000000);
			unsigned char key[512];
			memcpy(key, block + sizeof(uint64_t) + 2, 512);
			pthread_rwlock_wrlock(&keywr); // ����
			// ���ȶ����ļ�ָ�룺fp
			FILE *fp = fopen(KEY_FILE, "ab+");
			fseek(fp, 0, SEEK_END);	  // ��λ���ļ�ĩ
			int nFileLen = ftell(fp); // �ļ�����
			if (nFileLen < MAX_KEYFILE_SIZE)
			{
				fwrite(key, sizeof(unsigned char), 512, fp);
			}
			fclose(fp);
			pthread_rwlock_unlock(&keywr); // ����
			// ����ָ�������ͣ����ִ��,΢��
			usleep((int)(interval / 1000));
		}
		prevTimestamp = currentTimestamp;
	}
	fclose(file);

	pthread_exit(0);
}

/**
 * @description: ��ȡDH��Կ��Ԥ������Կ��Ϊ���ǵ����ṩһ����Կ��
 * @param {char} *buf	������Կ�Ļ�������
 * @param {int} len		��Ҫ��Կ�ĳ���
 * @return {*}
 */
void IKESA_key_read(char *const buf, int len)
{
	char *pb = buf;
	pthread_rwlock_rdlock(&keywr); // �϶���
	FILE *fp = fopen(KEY_FILE, "rb");
	if (fp == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	while (1)
	{
		fseek(fp, IKEkeyindex, SEEK_SET); // ���ļ�ָ��ƫ�Ƶ�ָ��λ��
		int bytes_read = fread(pb, sizeof(char), len, fp);
		// �� buffer ���� bytes_read ���ֽڵ����ݣ����п��ܰ������ַ�
		if (bytes_read == len)
		{
			break;
		}
		else
		{
			printf("key supply empty!\n");
			pthread_rwlock_unlock(&keywr); // ����
			sleep(1);
			pthread_rwlock_rdlock(&keywr); // �϶���
			printf("key require try again!\n");
		}
	}
	IKEkeyindex += len;
	fclose(fp);
	pthread_rwlock_unlock(&keywr); // ����
}

/**
 * @description:  ��ȡ����SA�Ự��Կ
 * @param {SpiParams *} local_spi ����spi������ָ��
 * @param {char} *buf ������Կ�Ļ�������
 * @param {int} len ��Ҫ��Կ�ĳ���
 * @return {*}
 */
void CHILDSA_key_read(SpiParams *local_spi, char *const buf, int len)
{
	char *pb = buf;
	pthread_rwlock_rdlock(&(local_spi->rwlock)); // �϶���
	FILE *fp = fopen(local_spi->keyfile, "rb");
	if (fp == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	int keyindex = local_spi->keyindex;
	while (1)
	{
		fseek(fp, keyindex, SEEK_SET); // ���ļ�ָ��ƫ�Ƶ�ָ��λ��
		int bytes_read = fread(pb, sizeof(char), len, fp);
		if (bytes_read == len)
		{
			// �� buffer ���� bytes_read ���ֽڵ����ݣ����п��ܰ������ַ�
			break;
		}
		else
		{
			printf("key supply empty!\n");
			pthread_rwlock_unlock(&local_spi->rwlock); // ����
			sleep(1);
			pthread_rwlock_rdlock(&local_spi->rwlock); // �϶���
			printf("key require try again!\n");
		}
	}
	keyindex += len;
	local_spi->keyindex = keyindex;
	fclose(fp);
	pthread_rwlock_unlock(&local_spi->rwlock); // ����
}