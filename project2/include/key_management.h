/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:19:24
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-10 15:43:49
 * @FilePath: \c\keymanage\project2\include\key_management.h
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */
#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

#include "sa_management.h"

#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>

#define MAX_KEYFILE_SIZE 200 * 1024 * 1024     // 最大密钥文件大小，当密钥文件大于最大限制时，不再填充密钥 200M
#define KEY_FILE "keypool/keyfile.kf"         // dh,psk密钥文件
#define TEMPKEY_FILE "keypool/tempkeyfile.kf" // 临时密钥文件

extern int key_creat_rate; // 密钥产生速率全局变量
extern pthread_rwlock_t keywr;		// 共享密钥池的读写锁

void init_key_management();

void store_key(const char *key);
void retrieve_key(char *buffer, int length);

void init_CHILDSA_key_generate(int index);

void *thread_keyrate_detection(void *args);

void *thread_CHILDSA_key_write(void *args);

void *thread_key_lifecycle_manage(void *args);

void *thread_IKESA_key_write(void *args);

void CHILDSA_key_read(SpiParams *local_spi, char *const buf, int len);

void IKESA_key_read(char *const buf, int len);

#endif // KEY_MANAGEMENT_H