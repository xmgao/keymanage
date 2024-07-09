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

// 运行 sudo ./qki remoteip >testlog 2> errlog

#include "local_comm.h"
#include "external_comm.h"
#include "key_management.h"
#include "sa_management.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#define EXTERNAL_PORT 50001 // 默认服务器外部监听端口

int SERV_PORT;				  // 服务器监听端口
char remote_ip[32];			  // 记录远程ip地址
int IKEkeyindex = 0;		  // 用于标识本地SA密钥池索引。
bool SAkey_sync_flag = false; // 密钥同步标志，用于供应sa协商

// 这个函数会被新的线程执行
void *print_variable()
{

	while (1)
	{
		system("clear");
		printf("\033[1H"); // 将光标定位到第1行
		FILE *fp;
		fp = fopen(KEY_FILE, "rb");
		fseek(fp, 0, SEEK_END);	  // 定位到文件末
		int nFileLen = ftell(fp); // 文件长度
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
				// 这里可以根据你的需要处理错误，例如返回错误码或者退出程序
			}
			else
			{
				fseek(fp, 0, SEEK_END);
				int nSAFileLen = ftell(fp); // 文件长度
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
		// 暂停一段时间，以便观察输出
		sleep(2);
	}
	return NULL;
}

int main(int argc, char *argv[])
{

	// 主处理逻辑
	printf("Main processing...\n");
	// 参数处理
	char buf[1024], client_ip[1024];
	if (argc < 2)
	{
		perror("Missing parameter\n");
		exit(1);
	}
	else if (argc < 3)
	{
		strcpy(remote_ip, argv[1]);
		// 默认服务器外部监听端口
		SERV_PORT = EXTERNAL_PORT;
	}
	else
	{
		strcpy(remote_ip, argv[1]);
		SERV_PORT = atoi(argv[2]);
	}

	// // 删除文件夹内的文件
	// char command[256];
	// snprintf(command, sizeof(command), "rm -rf %s", keypool_path);
	// system(command);
	// // 创建文件夹
	// if (mkdir(keypool_path, 777) != 0)
	// {
	// 	perror("mkdir");
	// 	exit(EXIT_FAILURE);
	// }

	// 先移除旧的密钥文件
	remove(KEY_FILE);

	// 初始化各个模块
	init_local_comm();
	init_external_comm();
	init_key_management();
	init_sa_management();

	sleep(1);
	pthread_t thread_front_end;
	// 创建一个新的线程，这个线程会执行print_variable函数
	pthread_create(&thread_front_end, NULL, print_variable, NULL);
	// 等待新的线程结束
	pthread_join(thread_front_end, NULL);

	// 程序退出时释放资源
	pthread_rwlock_destroy(&keywr); // 销毁读写锁
	for (int i = 0; i < spiCount; ++i)
	{ // 释放内存
		free(dynamicSPI[i]->ekeybuff);
		free(dynamicSPI[i]->dkeybuff);
		free(dynamicSPI[i]->olddkeybuff);
		pthread_rwlock_destroy(&(dynamicSPI[i]->rwlock));
		free(dynamicSPI[i]);
	}

	return 0;
}
