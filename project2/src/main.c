/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:20:38
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-09 16:30:15
 * @FilePath: \c\keymanage\project2\src\main.c
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */

// ���� sudo ./qki remoteip >testlog 2> errlog

#include "local_comm.h"
#include "external_comm.h"
#include "key_management.h"
#include "sa_management.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#define EXTERNAL_PORT 50001 // Ĭ�Ϸ������ⲿ�����˿�

int SERV_PORT;				  // �����������˿�
char remote_ip[32];			  // ��¼Զ��ip��ַ
int IKEkeyindex = 0;		  // ���ڱ�ʶ����SA��Կ��������
bool SAkey_sync_flag = false; // ��Կͬ����־�����ڹ�ӦsaЭ��

// ��������ᱻ�µ��߳�ִ��
void *print_variable()
{

	while (1)
	{
		system("clear");
		printf("\033[1H"); // ����궨λ����1��
		FILE *fp;
		fp = fopen(KEY_FILE, "rb");
		fseek(fp, 0, SEEK_END);	  // ��λ���ļ�ĩ
		int nFileLen = ftell(fp); // �ļ�����
		fclose(fp);
		printf("ikekeypoolsize: %08d \tBytes\n", nFileLen);
		printf("keycreatrate: %6d \tkbps\n", key_creat_rate * 8);
		printf("ikekeyuse: %08d \t Bytes\n", IKEkeyindex);

		printf("ipsecsatables: %2d \t SAs\n", spiCount);
		for (int i = 0; i < spiCount; i++)
		{
			printf("\nSPI: %x \t enc_flag:%d\n", dynamicSPI[i]->spi, dynamicSPI[i]->in_bound);
			FILE *fp = fopen(dynamicSPI[i]->keyfile, "rb");
			if (fp == NULL)
			{
				printf("Failed to open file: %s\n", dynamicSPI[i]->keyfile);
				// ������Ը��������Ҫ����������緵�ش���������˳�����
			}
			else
			{
				fseek(fp, 0, SEEK_END);
				int nSAFileLen = ftell(fp); // �ļ�����
				printf("keypoolsize: %08d \tBytes \t SAkeyuse: %08d \t Bytes\n", nSAFileLen, dynamicSPI[i]->keyindex);
				fclose(fp);
			}
			if (dynamicSPI[i]->encalg == 1)
			{
				printf("Encryption Mode: Dynamic Key Update\n");
				if (!dynamicSPI[i]->in_bound)
				{
					printf(" Current key derivation parameters:%d \t  Current encryption qkey:%s\n", dynamicSPI[i]->cur_ekeyd, dynamicSPI[i]->raw_ekey);
				}
				else
				{
					printf(" current decryption quantum key:%s\n", dynamicSPI[i]->raw_dkey);
				}
			}
			else if (dynamicSPI[i]->encalg == 2)
			{
				printf("Encryption Mode: Adaptive OTP\n");
				if (!dynamicSPI[i]->in_bound)
				{
					printf(" Current Encryption Key Window:(0,%d] \t Current key threshold:%d \n", dynamicSPI[i]->ekey_rw, dynamicSPI[i]->eM);
				}
				else
				{
					printf(" Current decryption key window:(%d,%d] \n", dynamicSPI[i]->dkey_lw, dynamicSPI[i]->dkey_rw);
				}
			}
		}
		// ��ͣһ��ʱ�䣬�Ա�۲����
		sleep(2);
	}
	return NULL;
}

int main(int argc, char *argv[])
{

	// �������߼�
	printf("Main processing...\n");
	// ��������
	char buf[1024], client_ip[1024];
	if (argc < 2)
	{
		perror("Missing parameter\n");
		exit(1);
	}
	else if (argc < 3)
	{
		strcpy(remote_ip, argv[1]);
		// Ĭ�Ϸ������ⲿ�����˿�
		SERV_PORT = EXTERNAL_PORT;
	}
	else
	{
		strcpy(remote_ip, argv[1]);
		SERV_PORT = atoi(argv[2]);
	}

	// // ɾ���ļ����ڵ��ļ�
	// char command[256];
	// snprintf(command, sizeof(command), "rm -rf %s", keypool_path);
	// system(command);
	// // �����ļ���
	// if (mkdir(keypool_path, 777) != 0)
	// {
	// 	perror("mkdir");
	// 	exit(EXIT_FAILURE);
	// }

	// ���Ƴ��ɵ���Կ�ļ�
	remove(KEY_FILE);

	// ��ʼ������ģ��
	init_local_comm();
	init_external_comm();
	init_key_management();
	init_sa_management();

	sleep(1);
	pthread_t thread_front_end;
	// ����һ���µ��̣߳�����̻߳�ִ��print_variable����
	pthread_create(&thread_front_end, NULL, print_variable, NULL);
	// �ȴ��µ��߳̽���
	pthread_join(thread_front_end, NULL);

	// �����˳�ʱ�ͷ���Դ
	pthread_rwlock_destroy(&keywr); // ���ٶ�д��
	for (int i = 0; i < spiCount; ++i)
	{ // �ͷ��ڴ�
		free(dynamicSPI[i]->ekeybuff);
		free(dynamicSPI[i]->dkeybuff);
		free(dynamicSPI[i]->olddkeybuff);
		pthread_rwlock_destroy(&(dynamicSPI[i]->rwlock));
		free(dynamicSPI[i]);
	}

	return 0;
}
