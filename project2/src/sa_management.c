/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:20:13
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-17 16:46:47
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

#define INIT_KEYD 100		   // ��ʼ��Կ��������
#define INIT_KEYM 16		   // ��ʼOTP��Կ����ֵ16�ֽ�
#define keypool_path "keypool" // ���屾����Կ���ļ���

int spiCount = 0; // ��ǰSPI����
SpiParams *dynamicSPI[MAX_DYNAMIC_SPI_COUNT];

void init_sa_management()
{
	// ��ʼ�� SA ����
	printf("Initializing SA management...\n");
}

void create_sa(int newSPI, int newinbound)
{
	// ���� SA
	printf("Creating SA...\n");
	dynamicSPI[spiCount] = (SpiParams *)malloc(sizeof(SpiParams));
	char hexStr[64];											// �㹻����ַ��������洢ת������ַ���
	sprintf(hexStr, "%s/%x", keypool_path, newSPI);				// ������ת��Ϊʮ�������ַ���
	strcpy(dynamicSPI[spiCount]->keyfile, hexStr);				// ��SPI��ʼ����Կ������
	pthread_rwlock_init(&(dynamicSPI[spiCount]->rwlock), NULL); // ��ʼ����д��
	if (dynamicSPI[spiCount] != NULL)
	{
		dynamicSPI[spiCount]->spi = newSPI;
		// ��ʼ��������SPI��صĲ���
		dynamicSPI[spiCount]->encalg = 0;										   // ��ʼ�޷�֪�������㷨
		dynamicSPI[spiCount]->encalg_keysize = 0;								   // ��ʼ�޷�֪�������㷨��Կ����
		dynamicSPI[spiCount]->key_sync_flag = false;							   // ��Կ����ͬ����־����Ϊfalse
		dynamicSPI[spiCount]->delkeyindex = 0, dynamicSPI[spiCount]->keyindex = 0; // ��ʼ����Կƫ��
		dynamicSPI[spiCount]->ekeybuff = NULL;
		dynamicSPI[spiCount]->dkeybuff = NULL;
		dynamicSPI[spiCount]->olddkeybuff = NULL;
		dynamicSPI[spiCount]->ekey_rw = 0;
		dynamicSPI[spiCount]->dkey_lw = 0;
		dynamicSPI[spiCount]->dkey_rw = 0;
		dynamicSPI[spiCount]->is_destory = false;
		// �������վSPI����Ҫ��ʼ�����ܲ���
		if (newinbound)
		{
			dynamicSPI[spiCount]->in_bound = 1;
			dynamicSPI[spiCount]->myQueue = (Queue *)malloc(sizeof(Queue));
			init_queue(dynamicSPI[spiCount]->myQueue); // ��ʼ��������Կ������������
		}
		else
		{
			dynamicSPI[spiCount]->in_bound = 0;
			dynamicSPI[spiCount]->cur_ekeyd = INIT_KEYD; // ��ʼ��������Կ��������
			dynamicSPI[spiCount]->eM = INIT_KEYM;
		}
		// ������Կ�߳�
		init_CHILDSA_key_generate(spiCount);
		spiCount++; // ���¼�����
		printf("Memory allocation successed for new SPI.\n");
	}
	else
	{
		printf("Memory allocation failed for new SPI.\n");
	}
}

void delete_sa(int delSPI)
{
	// ɾ�� SA
	printf("Deleting SA...\n");
	int i = 0;
	while (dynamicSPI[i]->spi != delSPI && i < spiCount)
	{
		i++;
	}
	if (i >= spiCount)
	{
		return;
	}
	SpiParams *del_spi = dynamicSPI[i];
	// ������destory��־���������ʱ���ͷ���Դ
	del_spi->is_destory = true;
}
