/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:20:13
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-17 19:24:22
 * @FilePath: \c\keymanage\project2\src\local_comm.c
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */
#include "local_comm.h"
#include "key_management.h"

#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>

#define MAX_EVENTS 10000			 // ����������
#define BUFFER_SIZE 512				 // ��ͨ���ݰ���������󳤶�
#define socket_path "/tmp/my_socket" // ���屾���׽���·��
#define WINSIZE 4096				 // ��Կ���ڴ�С

#define DEBUG_LEVEL 1

void init_local_comm()
{
	pthread_t thread_local;
	// ������������������ʼ������Կ����
	pthread_create(&thread_local, NULL, thread_reactor_local, NULL);
	if (pthread_detach(thread_local) != 0)
	{
		perror("pthread_detach");
		return;
	}
}

/**
 * @description: ���ؼ�����ʼ����ʹ��AF_UNIX
 * @param {int} epfd epoll�ļ�������
 * @return {int} ���ؼ������׽��ֵ�ַ
 */
int init_listen_local(int epfd)
{
	int unix_sock, ret;
	struct epoll_event tep;

	struct sockaddr_un serv_addr;

	// ���� UNIX ���׽���
	unix_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (unix_sock < 0)
	{
		perror("socket create error!\n");
		exit(1);
	}
	// �����׽��ֵ�ַ��Ϣ
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sun_family = AF_UNIX;
	strncpy(serv_addr.sun_path, socket_path, sizeof(serv_addr.sun_path) - 1);

	// ��bind֮ǰ�������ѡ���Ե�ɾ���Ѵ��ڵ��׽����ļ�
	unlink(socket_path); // ɾ���Ѵ��ڵ��ļ�
	// �� UNIX ���׽���
	ret = bind(unix_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (ret < 0)
	{
		perror("bind error!\n");
		exit(1);
	}

	listen(unix_sock, 128);

	tep.events = EPOLLIN;
	tep.data.fd = unix_sock;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, unix_sock, &tep);
	if (ret == -1)
	{
		perror("epoll_ctl_add error!\n");
		exit(1);
	}

	return unix_sock;
}

/**
 * @description: ���� UNIX ���׽�������
 * @param {int} *fd ����soket�ļ��������ĵ�ַ
 * @return {*} true if ���ӳɹ�
 */
bool init_unix_con(int *fd)
{
	int ret, cr;
	*fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (*fd < 0)
	{
		perror("socket error!\n");
		return false;
	}

	struct sockaddr_un serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sun_family = AF_UNIX;
	strncpy(serv_addr.sun_path, socket_path, sizeof(serv_addr.sun_path) - 1);

	cr = connect(*fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)); // ���ӶԷ��׽��ֵ�ַ
	if (cr < 0)
	{
		perror("connect error!\n");
		return false;
	}
	return true;
}

/**
 * @description:  ���� UNIX ���׽�����������
 * @param {int} fd �������ļ�������
 * @param {int} epfd epoll�ļ�������
 * @return {*}
 */
void handler_conreq_unix(int fd, int epfd)
{
	struct sockaddr_un cli_addr;
	int ret;
	struct epoll_event tep;
	socklen_t client_addr_size = sizeof(struct sockaddr_un);
	int ar = accept(fd, (struct sockaddr *)&cli_addr, &client_addr_size);
	if (ar == -1)
	{
		perror("accept unix error");
		// �������
	}

	// ���� ar socket ������
	int flag = fcntl(ar, F_GETFL);
	flag |= O_NONBLOCK;
	fcntl(ar, F_SETFL, flag);

	// �¼���ֵ
	tep.events = EPOLLIN;
	tep.data.fd = ar;

	// �¼�����
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, ar, &tep);
	if (ret == -1)
	{
		perror("epoll_ctl_add error!\n");
		exit(1);
	}
}

/**
 * @description: ���� UNIX ���׽�����Կ��ע������
 * @param {int} fd
 * @param {int} epfd
 * @return {*}
 */
void handler_recdata_unix(int fd, int epfd)
{
	char buffer[BUFFER_SIZE];
	// ��ջ�����
	memset(buffer, 0, BUFFER_SIZE);
	ssize_t bytesRead = read(fd, buffer, BUFFER_SIZE);
	if (bytesRead == -1)
	{
		perror("Failed to read data from socket");
		exit(EXIT_FAILURE);
	}
	else if (bytesRead == 0)
	{
		// ���ӹرգ�������Ӧ����
		discon(fd, epfd);
	}
	else
	{
		// �����ﴦ��� UNIX ���׽����ж�ȡ������
		// ���Ը�������Զ�ȡ�������ݽ��д���
		// ��ȡ���ݺ󣬼�鲢ȥ�����з�
		if (buffer[bytesRead - 1] == '\n')
		{
			buffer[bytesRead - 1] = '\0'; // �����з��滻Ϊ�ַ���������
		}
		if (DEBUG_LEVEL == 1)
		{
			printf("Received data from socket: %s\n", buffer);
		}
		//  ��Ӧ��child_sa_register arg1==spi, arg2=inbound
		//  ��Ӧ��getsharedkey  arg1=keylen(�ֽ�)
		//  ��Ӧ��getsk  arg1==spi, arg2=keylen(�ֽ�), arg3=syn,arg4=keytype(0���ܣ�1����)
		//  ��Ӧ��getotpk arg1==spi, arg2=syn,arg3=keytype //����ǽ���spi����Ҫntohlת��
		//  ��Ӧ��child_sa_destroy arg1==spi
		HandleData data1;
		sscanf(buffer, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", data1.method, data1.arg1, data1.arg2, data1.arg3, data1.arg4);
		if (strcasecmp(data1.method, "childsaregister") == 0)
		{
			CHILDSA_register_handle(data1.arg1, data1.arg2);
			discon(fd, epfd);
		}
		if (strcasecmp(data1.method, "childsadestroy") == 0)
		{
			CHILDSA_destroy_handle(data1.arg1);
			discon(fd, epfd);
		}
		else if (strcasecmp(data1.method, "getsharedkey") == 0)
		{
			IKESA_key_get_handle(data1.arg1, fd);
			discon(fd, epfd);
		}
		else if (strcasecmp(data1.method, "getotpk") == 0)
		{
			OTP_key_get_handle(data1.arg1, data1.arg2, data1.arg3, fd);
		}
		else if (strcasecmp(data1.method, "getsk") == 0)
		{
			CHILDSA_key_get_handle(data1.arg1, data1.arg2, data1.arg3, data1.arg4, fd);
		}
		else
		{
			printf("invalid recvdataunix:%s\n",buffer);
			//discon(fd, epfd);
		}
	}
	return;
}

/**
 * @description: DH�Լ�Ԥ������Կ������
 * @param {char} *keylen ��Ҫ����Կ�����ַ�������
 * @param {int} fd	socket�ļ�������
 * @return {*}
 */
void IKESA_key_get_handle(const char *keylen, int fd)
{
	int len = atoi(keylen);
	char buf[len + 1];
	// �ж��Ƿ��Ѿ�ͬ�������û��ͬ�������Ƚ���˫��ͬ��
	if (!SAkey_sync_flag)
	{
		bool ret = IKESA_keyindex_sync();
		if (!ret)
		{
			perror("IKESA_keyindex_sync error!\n");
			char buf2[] = "A";
			send(fd, buf2, strlen(buf2), 0);
			return;
		}
	}
	// ��ȡ��Կ
	IKESA_key_read(buf, len);
	if (DEBUG_LEVEL == 1)
	{
		printf("qkey:%s size:%d sei:%d\n", buf, len, IKEkeyindex);
	}

	send(fd, buf, len, 0);
}

/**
 * @description: �Ự��Կ������ ��Կ���ڻ��Ƿ���kms��
 * @param {char} *spi �����SPI���֣��ַ�������ʽ
 * @param {char} *keylen  �������Կ���ȣ��ַ���
 * @param {char} *syn	��������к�
 * @param {char} *key_type	�������Կ���ͣ�0���� 1����
 * @param {int} fd	socket�ļ�������
 * @return {*}
 */
void CHILDSA_key_get_handle(const char *spi, const char *keylen, const char *syn, const char *key_type, int fd)
{
	int i = 0;
	int hostspi = atoi(key_type) == 1 ? atoi(spi) : htonl(atoi(spi)); // ����ǻ�ȡ������Կ�����spiֵ�������ֽڣ���Ҫ���������ֽ�ת��
	while (dynamicSPI[i]->spi != hostspi && i < spiCount)
	{
		i++;
	}
	SpiParams *local_spi = dynamicSPI[i];

	int seq = atoi(syn);
	int len = atoi(keylen);
	// �ж��Ƿ�Ϊ��һ����
	if (seq == 1)
	{
		local_spi->encalg_keysize = len;
		if (local_spi->encalg == 0)
		{
			local_spi->encalg = 1; // ��ֵΪ��̬�����㷨
		}
	}
	/* ������ʱ�Ƚ����ⲿ��
	// �ж�syn�Ƿ�Ϊ1�����Ǽ��ܷ�,������мӽ��ܹ�ϵͬ����������Ҫͬ��
	if (seq == 1 && atoi(key_type) == 0)
	{
		if (!CHILDSA_inbound_sync(local_spi))
		{
			perror("CHILDSA_inbound_sync error!\n");
			return;
		}
	}
	// �ж���Կ�����Ƿ�ͬ�������������Կ����ͬ��
	if (!local_spi->key_sync_flag)
	{
		if (!CHILDSA_keyindex_sync(local_spi))
		{
			perror("keyindex_sync error!\n");
			return;
		}
	}
	*/
	char buf[BUFFER_SIZE];
	if (*key_type == '0')
	{
		bool ret = derive_para_sync(local_spi); // ��������ͬ��
		if (!ret)
		{
			perror("derive_para_sync error!\n");
			return;
		}
		CHILDSA_key_read(local_spi, local_spi->raw_ekey, len); // ��ȡSA�Ự��Կ

		memcpy(buf, &local_spi->cur_ekeyd, sizeof(int));
		memcpy(buf + sizeof(int), local_spi->raw_ekey, len);
	}
	else
	{
	loop1:
		if (is_empty(local_spi->myQueue))
		{ // ���ж϶����Ƿ�Ϊ�գ�����ǿգ�˵��������δ������У�����һ��ʱ��ĵȴ�
			usleep(100);
			goto loop1;
		}
		CHILDSA_key_read(local_spi, local_spi->raw_dkey, len); // ��ȡ��Կ
		int dkeyd = dequeue(local_spi->myQueue);			   // ��ȷ�Ľ�������������һ�����й���
		memcpy(buf, &dkeyd, sizeof(int));
		memcpy(buf + sizeof(int), local_spi->raw_dkey, len);
	}
	send(fd, buf, sizeof(int) + len, 0);
}

/**
 * @description: otp��Կ������
 * @param {char} *spi	�����SPI���֣��ַ�������ʽ
 * @param {char} *syn	��������к�
 * @param {char} *key_type	�������Կ���ͣ�0���� 1����
 * @param {int} fd	socket�ļ�������
 * @return {*}
 */
void OTP_key_get_handle(const char *spi, const char *syn, const char *key_type, int fd)
{
	int i = 0;
	int hostspi = atoi(key_type) == 1 ? atoi(spi) : htonl(atoi(spi)); // ����ǻ�ȡ������Կ�����spiֵ�������ֽڣ���Ҫ���������ֽ�ת��
	while (dynamicSPI[i]->spi != hostspi && i < spiCount)
	{
		i++;
	}
	SpiParams *local_spi = dynamicSPI[i];

	if (local_spi->encalg == 0)
	{
		local_spi->encalg = 2; // ��ֵΪ����Ӧһ��һ���㷨
	}

	int seq = atoi(syn);
	// �ж�syn�Ƿ�Ϊ1�����Ǽ��ܷ���������мӽ��ܹ�ϵͬ����������Ҫͬ��
	if (seq == 1 && atoi(key_type) == 0)
	{
		if (!CHILDSA_inbound_sync(local_spi))
		{
			perror("CHILDSA_inbound_sync error!\n");
			return;
		}
	}
	// �ж���Կ�����Ƿ�ͬ�������������Կ����ͬ��
	if (!local_spi->key_sync_flag)
	{
		if (!CHILDSA_keyindex_sync(local_spi))
		{
			perror("keyindex_sync error!\n");
			return;
		}
	}
	char buf[512];
	if (*key_type == '0')
	{ // ������Կ
		int ekey_rw = local_spi->ekey_rw;
		if (seq > ekey_rw)
		{ //// �����û�г�ʼ����Կ���߳�����Կ����Χ��Ҫ����ԭʼ��Կ�Լ�syn����,Э���µ���Կ��������
			if (local_spi->ekeybuff != NULL)
				free(local_spi->ekeybuff);
			local_spi->ekeybuff = (Keyblock *)malloc(WINSIZE * sizeof(Keyblock));
			bool ret = key_threshold_sync(local_spi); // ��Կ����ֵMͬ��
			for (int i = 0; i < WINSIZE; i++)
			{
				CHILDSA_key_read(local_spi, local_spi->ekeybuff[i].key, local_spi->eM);
				local_spi->ekeybuff[i].size = local_spi->eM;
			}
			// ���´���
			local_spi->ekey_rw = ekey_rw + WINSIZE;
		}
		// ����

		memcpy(buf, local_spi->ekeybuff[(seq - 1) % WINSIZE].key, local_spi->ekeybuff[(seq - 1) % WINSIZE].size);
		// printf("qkey:%s size:%d sei:%d\n", buf, local_spi->ekeybuff[(seq - 1) % WINSIZE].size, local_spi->keyindex);
		send(fd, buf, local_spi->ekeybuff[(seq - 1) % WINSIZE].size, 0);
	}
	else
	{ // ������Կ:���ڽ�����Կά��һ������Կ�Ĵ������ݴ��ȥ����Կ��Ӧ��ʧ�����
	loop2:
		if (seq > local_spi->dkey_rw)
		{
			if (is_empty(local_spi->myQueue))
			{ // ���ж϶����Ƿ�Ϊ�գ�����ǿգ�˵��������δ������У�����һ��ʱ��ĵȴ�
				usleep(100000);
				goto loop2;
			}
			// �����û�г�ʼ����Կ���߳�����Կ����Χ��Ҫ����ԭʼ��Կ�Լ�syn����,Э���µ���Կ��������
			if (local_spi->olddkeybuff != NULL)
				free(local_spi->olddkeybuff);
			local_spi->olddkeybuff = local_spi->dkeybuff;
			local_spi->dkeybuff = (Keyblock *)malloc(WINSIZE * sizeof(Keyblock));
			int dM = dequeue(local_spi->myQueue);
			for (int i = 0; i < WINSIZE; i++)
			{
				CHILDSA_key_read(local_spi, local_spi->dkeybuff[i].key, dM);
				local_spi->dkeybuff[i].size = dM;
			}
			// ���´���
			local_spi->dkey_lw = local_spi->dkey_rw + 1;
			local_spi->dkey_rw += WINSIZE;
			goto loop2;
		}
		// ����
		if (seq >= local_spi->dkey_lw)
		{
			memcpy(buf, local_spi->dkeybuff[(seq - 1) % WINSIZE].key, local_spi->dkeybuff[(seq - 1) % WINSIZE].size); // �������ݰ�
			// printf("qkey:%s size:%d sei:%d\n", buf, local_spi->dkeybuff[(seq - 1) % WINSIZE].size, local_spi->keyindex);
			send(fd, buf, local_spi->dkeybuff[(seq - 1) % WINSIZE].size, 0);
		}
		else
		{
			memcpy(buf, local_spi->olddkeybuff[(seq - 1) % WINSIZE].key, local_spi->olddkeybuff[(seq - 1) % WINSIZE].size); // �������ݰ�
			// printf("qkey:%s size:%d sei:%d\n", buf, local_spi->olddkeybuff[(seq - 1) % WINSIZE].size, local_spi->keyindex);
			send(fd, buf, local_spi->olddkeybuff[(seq - 1) % WINSIZE].size, 0);
		}
	}
}

/**
 * @description: spiע��������
 * @param {char *} spi	spi������ֵ
 * @param {char *} inbound 1 if �뾳SA
 * @return {*}
 */
void CHILDSA_register_handle(const char *spi, const char *inbound)
{
	// �����⵽�µ�SPI
	int newSPI = htonl(atoi(spi)); // ��ͳһת��Ϊ�����ֽ���
	int newinbound = atoi(inbound);
	// ��̬�����ڴ棬���洢�µ�SPI����
	create_sa(newSPI, newinbound);
}

void CHILDSA_destroy_handle(const char *spi){
	// �����⵽SPI��������
	int delSPI = htonl(atoi(spi)); // ��ͳһת��Ϊ�����ֽ���
	delete_sa(delSPI);
}

/**
 * @description: ���̵߳Ĵ���,��������socket�˿�
 * @return {*}
 */
void *thread_reactor_local()
{
	// ���̵߳Ĵ���
	printf("This is the af_unix thread.\n");
	int epfd, nfds, i;
	struct epoll_event events[MAX_EVENTS];
	// ���� epoll ʵ��
	epfd = epoll_create1(0);
	if (epfd == -1)
	{
		perror("epoll_create1 error!\n");
		exit(1);
	}
	// ���ؼ���
	int local_lfd = init_listen_local(epfd);
	while (1)
	{
		nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
		if (nfds == -1)
		{
			perror("epoll_wait error!\n");
			exit(1);
		}

		for (i = 0; i < nfds; i++)
		{
			int fd = events[i].data.fd;
			if (events[i].events & EPOLLIN)
			{
				if (fd == local_lfd)
				{
					printf("local_connection request!\n");
					handler_conreq_unix(local_lfd, epfd); // ��������������
				}
				else
				{
					handler_recdata_unix(fd, epfd); // ��Կ����ע���¼�
				}
			}
		}
	}
	close(epfd);
	close(local_lfd);
	pthread_exit(NULL);
}
