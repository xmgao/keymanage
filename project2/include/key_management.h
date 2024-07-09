/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:19:24
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-09 12:03:08
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

#define MAX_KEYFILE_SIZE 200 * 1024 * 1024     // �����Կ�ļ���С������Կ�ļ������������ʱ�����������Կ 200M
#define KEY_FILE "keypool/keyfile.kf"         // dh,psk��Կ�ļ�
#define TEMPKEY_FILE "keypool/tempkeyfile.kf" // ��ʱ��Կ�ļ�

extern int key_creat_rate; // ��Կ��������ȫ�ֱ���
extern pthread_rwlock_t keywr;		// ������Կ�صĶ�д��

void init_key_management();
void generate_SAkey(int index);
void store_key(const char *key);
void retrieve_key(char *buffer, int length);

void *thread_keyradetection(void *args);

void *thread_writeSAkey(void *args);

void *thread_keyschedule(void *args);

void *thread_writesharedkey(void *args);

void readSAkey(SpiParams *local_spi, char *const buf, int len);

void readsharedkey(char *const buf, int len);

#endif // KEY_MANAGEMENT_H