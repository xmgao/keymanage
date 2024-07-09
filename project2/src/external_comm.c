/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2024-07-08 17:20:13
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-09 16:14:01
 * @FilePath: \c\keymanage\project2\src\external_comm.c
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */
#include "external_comm.h"
#include "key_management.h"

#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <openssl/hmac.h>
#include <pthread.h>

#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))

#define up_index 2									// ������������
#define down_index 500								// ������������
#define LT 0.2										// �½�
#define WINSIZE 4096								// ��Կ���ڴ�С
#define HMAC_KEY "7890ABCDEF1234567890ABCDEF123456" // HMAC��Կ
#define MAX_EVENTS 10000							// ����������

// �������ݰ��ṹ����
#define METHOD_SIZE 32
#define DATA_SIZE 64
#define HMAC_SIZE 32
#define PACKET_SIZE (METHOD_SIZE + DATA_SIZE + HMAC_SIZE)

#define DEBUG_LEVEL 1

void init_external_comm()
{
	pthread_t thread_external;
	pthread_create(&thread_external, NULL, reactor_external_socket, NULL);
	if (pthread_detach(thread_external) != 0)
	{
		perror("pthread_detach");
		return;
	}
}

// ����HMAC���ݰ�
void create_hmac_packet(const char *method, const char data[][17], int data_count, unsigned char *packet)
{
	// ������ݰ�
	memset(packet, 0, PACKET_SIZE);

	// ���method
	strncpy((char *)packet, method, METHOD_SIZE);

	// �������
	for (int i = 0; i < data_count && i < 10; i++)
	{
		if (DEBUG_LEVEL == 1)
		{
			printf("data[%d]: %s (line %d)\n", i, data[i], __LINE__);
		}

		strncpy((char *)(packet + METHOD_SIZE + i * 16), data[i], 16);
		// ȷ���ַ�����null��β
		packet[METHOD_SIZE + i * 16 + 16] = '\0';
	}

	//  ����HMAC
	unsigned char hmac_result[HMAC_SIZE];
	unsigned int len = HMAC_SIZE;
	HMAC(EVP_sha256(), HMAC_KEY, strlen(HMAC_KEY), packet, METHOD_SIZE + DATA_SIZE, hmac_result, &len);
	// ��HMAC���ֱ����ӵ����ݰ�ĩβ
	memcpy(packet + METHOD_SIZE + DATA_SIZE, hmac_result, HMAC_SIZE);
}

int verify_hmac_packet(const unsigned char *packet)
{
	unsigned char expected_hmac[HMAC_SIZE];
	unsigned int len = HMAC_SIZE;

	// ����������HMAC
	HMAC(EVP_sha256(), HMAC_KEY, strlen(HMAC_KEY), packet, METHOD_SIZE + DATA_SIZE, expected_hmac, &len);

	// �Ƚ�������HMAC�ͽ��յ���HMAC
	return memcmp(expected_hmac, packet + METHOD_SIZE + DATA_SIZE, HMAC_SIZE) == 0;
}

/**
 * @description: �ⲿ������ʼ����ʹ��tcp
 * @param {int} port ��Ҫ�������ⲿ�˿�
 * @param {int} epfd epoll�ļ�������
 * @return {int} ���ؼ������׽��ֵ�ַ
 */
int init_listen_external(int port, int epfd)
{
	int lfd, ret;
	struct epoll_event tep;
	struct sockaddr_in serv_addr;

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	// ���û������IP��ַת��Ϊ�����ֽ���Ķ����Ƹ�ʽ
	if (inet_pton(AF_INET, "0.0.0.0", &serv_addr.sin_addr) <= 0)
	{
		perror("Invalid IP address");
		exit(EXIT_FAILURE);
	}
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
	{
		perror("socket create error!\n");
		exit(1);
	}
	// ���ö˿ڸ��ã�ʹ������TIME_WAIT�ȴ�����
	int opt = 1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	int br = bind(lfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (br < 0)
	{
		perror("bind error!\n");
		exit(1);
	}

	listen(lfd, 128);

	tep.events = EPOLLIN;
	tep.data.fd = lfd;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &tep);
	if (ret == -1)
	{
		perror("epoll_ctl_add error!\n");
		exit(1);
	}

	return lfd;
}

/**
 * @description: ����tcp����
 * @param {int} *fd ����soket�ļ��������ĵ�ַ
 * @param {char} *dest Ŀ�ĵ�ַ
 * @param {int} port Ŀ�Ķ˿�
 * @return {*} true if ���ӳɹ�
 */
bool con_tcpserv(int *fd, const char *dest, int port)
{
	int ret, cr;
	struct sockaddr_in serv_addr;
	*fd = socket(AF_INET, SOCK_STREAM, 0);
	if (*fd < 0)
	{
		perror("socket error!\n");
		return false;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	inet_pton(AF_INET, dest, &serv_addr.sin_addr.s_addr);

	cr = connect(*fd, (struct sockaddr *)(&serv_addr), sizeof(serv_addr)); // ���ӶԷ�������
	if (cr < 0)
	{
		perror("connect error!\n");
		return false;
	}
	return true;
}

/**
 * @description: ����tcp��������
 * @param {int} fd �������ļ�������
 * @param {int} epfd epoll�ļ�������
 * @return {*}
 */
void handler_conreq_tcp(int fd, int epfd)
{
	struct sockaddr_in cli_addr;
	char cli_ip[INET_ADDRSTRLEN];
	socklen_t client_addr_size = sizeof(cli_addr);
	struct epoll_event tep;
	int ret;

	int ar = accept(fd, (struct sockaddr *)(&cli_addr), &client_addr_size);
	if (ar < 0)
	{
		perror("accept error");
		return;
	}

	// ��ȡ�ͻ��˵� IP ��ַ
	if (inet_ntop(AF_INET, &cli_addr.sin_addr, cli_ip, sizeof(cli_ip)) == NULL)
	{
		perror("inet_ntop error");
		close(ar);
		return;
	}
	if (DEBUG_LEVEL == 1)
	{
		printf("ip address is: %s, port is: %d\n", cli_ip, ntohs(cli_addr.sin_port));
	}

	// ���ͻ��� IP ��ַ�Ƿ��� remoteip ƥ��
	if (strcmp(cli_ip, remote_ip) != 0)
	{
		printf("Rejected connection from: %s\n", cli_ip);
		close(ar);
		return;
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
		perror("epoll_ctl_add error");
		close(ar);
		exit(1);
	}
}

/**
 * @description: �ر�tcp����
 * @param {int} fd ��Ҫ�رյ��ļ�������
 * @param {int} epfd epoll�ļ�������
 * @return {*}
 */
void discon(int fd, int epfd)
{
	int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
	if (ret < 0)
	{
		perror("EPOLL_CTL_DEL error...\n");
		// ����ѡ���¼��־����ִ�������������߼�
	}
	close(fd);
}

/**
 * @description:
 * @param {int} fd
 * @param {int} epfd
 * @return {*}
 */
void handler_recdata_tcp(int fd, int epfd)
{

	char received_packet[PACKET_SIZE];
	// ��ջ�����
	memset(received_packet, 0, PACKET_SIZE);
	ssize_t bytesRead;

	bytesRead = read(fd, received_packet, PACKET_SIZE);

	if (bytesRead <= 0)
	{
		perror("read error");
		discon(fd, epfd);
	}
	else if (!verify_hmac_packet(received_packet))
	{
		printf("HMAC verify failed! (line %d)\n", __LINE__);
		discon(fd, epfd);
	}
	else
	{
		if (DEBUG_LEVEL == 1)
		{
			printf("HMAC verify success! (line %d)\n", __LINE__);
		}

		// �����ȡ��������
		//  ��Ӧ��keyindexsync  arg1=spi, arg2=global_keyindex
		//  ��Ӧ��SAkeysync  arg1=remotekeyindex
		//  ��Ӧ��encflagsync arg1==spi arg2=inbound
		//  ��Ӧ��derive_sync  arg1==spi arg2==key_d
		//  ��Ӧ��eM_sync  arg1==spi arg2==tem_eM

		// ����method
		HandleData data1;
		memset(&data1, 0, sizeof(HandleData));
		strncpy(data1.method, (char *)received_packet, METHOD_SIZE);
		// ��������
		strncpy(data1.arg1, (char *)(received_packet + METHOD_SIZE), 16);
		strncpy(data1.arg2, (char *)(received_packet + METHOD_SIZE + 16 * 1), 16);
		strncpy(data1.arg3, (char *)(received_packet + METHOD_SIZE + 16 * 2), 16);
		strncpy(data1.arg4, (char *)(received_packet + METHOD_SIZE + 16 * 3), 16);

		if (strncasecmp(data1.method, "keyindexsync", 12) == 0)
		{
			keysync_handle(data1.arg1, data1.arg2, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(data1.method, "SAkeysync", 9) == 0)
		{
			SAkey_sync_handle(data1.arg1, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(data1.method, "encflagsync", 11) == 0)
		{
			encflag_handle(data1.arg1, data1.arg2, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(data1.method, "desync", 6) == 0)
		{
			desync_handle(data1.arg1, data1.arg2, fd);
		}
		else if (strncasecmp(data1.method, "eMsync", 6) == 0)
		{
			eMsync_handle(data1.arg1, data1.arg2, fd);
		}
		else
		{
			printf("invalid recdata\n");
			discon(fd, epfd);
		}
	}
}

/**
 * @description: �ӽ��ܶ�Ӧ��ϵͬ������
 * @param {SpiParams *} local_spi �������Ϊ����spi������ָ��
 * @return {*} TRUE if���ܶ�Ӧ����
 */

bool encflag_sync(SpiParams *local_spi)
{
	int spi = local_spi->spi;
	int local_flag = local_spi->in_bound;
	int fd, ret, remote_flag;
	if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
	{
		perror("encflag_sync connect error!\n");
		return false;
	}
	printf("spi:%d\tencrypt_flag:%d\n", spi, local_flag);

	const char *method = "encflagsync";
	char data[2][17] = {0};
	unsigned char packet[PACKET_SIZE];

	// ������ת��Ϊ�ַ������洢��data������
	snprintf(data[0], 17, "%d", spi);
	snprintf(data[1], 17, "%d", local_flag);
	create_hmac_packet(method, data, 2, packet);
	send(fd, packet, PACKET_SIZE, 0);

	// ������Ϣʱ
	char received_packet[PACKET_SIZE];
	read(fd, received_packet, PACKET_SIZE);

	// ��֤HMAC
	if (verify_hmac_packet(received_packet))
	{
		if (DEBUG_LEVEL == 1)
		{
			printf("HMAC verify success! (line %d)\n", __LINE__);
		}
		// ����method
		char method[METHOD_SIZE + 1] = {0};
		strncpy(method, (char *)received_packet, METHOD_SIZE);
		//  ��������
		char param1[17] = {0};
		strncpy(param1, (char *)(received_packet + METHOD_SIZE), 16);
		sscanf(param1, "%d", &remote_flag);
		close(fd);
		if (local_flag ^ remote_flag == 1)
			return true;
	}
	else
	{
		printf("HMAC verify failed! (line %d)\n", __LINE__);
		close(fd);
		return false;
	}
}

// SA��Կͬ��,������Զ�˷��������Խ�������ͬ����Կƫ��
bool IKESAkey_sync()
{
	int fd, ret, remote_keyindex;
	if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
	{
		perror("SAkeysync connect error!\n");
		return false;
	}

	const char *method = "SAkeysync";
	char data[1][17];
	memset(data, 0, sizeof(data));
	unsigned char packet[PACKET_SIZE];

	// ������ת��Ϊ�ַ������洢��data������
	snprintf(data[0], 17, "%d", IKEkeyindex);
	// ��ӡ������Ϣ
	if (DEBUG_LEVEL == 1)
	{
		printf("begin create hmac packet! (line %d)\n", __LINE__);
		printf("data[0]: %s\n", data[0]);
		printf("method: %s\n", method);
	}

	create_hmac_packet(method, data, 1, packet);
	send(fd, packet, PACKET_SIZE, 0);
	//  ������Ϣʱ
	char received_packet[PACKET_SIZE];
	read(fd, received_packet, PACKET_SIZE);

	// ��֤HMAC
	if (verify_hmac_packet(received_packet))
	{
		// ����method
		char method[METHOD_SIZE + 1] = {0};
		strncpy(method, (char *)received_packet, METHOD_SIZE);
		//  ��������
		char param1[17] = {0};
		strncpy(param1, (char *)(received_packet + METHOD_SIZE), 16);

		if (DEBUG_LEVEL == 1)
		{
			printf("HMAC verify success! (line %d)\n", __LINE__);
			printf("Method: %s \t param1:%s\n", method, param1);
		}

		sscanf(param1, "%d", &remote_keyindex);
		IKEkeyindex = max(IKEkeyindex, remote_keyindex);
		SAkey_sync_flag = true;
		close(fd);
		return true;
	}
	else
	{
		printf("HMAC verify failed!\n");
		close(fd);
		return false;
	}
}

/**
 * @description: ��Կͬ��,������Զ�˷�������������ͬ����Կƫ��
 * @param {SpiParams *} local_spi ����spi������ָ��
 * @return {*} TRUE if��Կƫ��ͬ���ɹ�
 */
bool key_index_sync(SpiParams *local_spi)
{
	int spi = local_spi->spi;
	int local_keyindex = local_spi->keyindex;
	int local_delkeyindex = local_spi->delkeyindex;

	int fd, ret;
	int global_keyindex;
	if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
	{
		perror("keyindexsync connect error!\n");
		return false;
	}

	const char *method = "SAkeyindexsync";
	char data[2][17] = {0};
	unsigned char packet[PACKET_SIZE];

	// ������ת��Ϊ�ַ������洢��data������
	snprintf(data[0], 17, "%d", spi);
	snprintf(data[1], 17, "%d", local_keyindex + local_delkeyindex);
	create_hmac_packet(method, data, 2, packet);
	send(fd, packet, PACKET_SIZE, 0);

	// ������Ϣʱ
	char received_packet[PACKET_SIZE];
	read(fd, received_packet, PACKET_SIZE);

	// ��֤HMAC
	if (verify_hmac_packet(received_packet))
	{

		// ����method
		char method[METHOD_SIZE + 1] = {0};
		strncpy(method, (char *)received_packet, METHOD_SIZE);
		//  ��������
		char param1[17] = {0};
		strncpy(param1, (char *)(received_packet + METHOD_SIZE), 16);
		if (DEBUG_LEVEL == 1)
		{
			printf("HMAC verify success! (line %d)\n", __LINE__);
			printf("Method: %s param1:%s\n", method, param1);
		}
		sscanf(param1, "%d", &global_keyindex);
		close(fd);
		local_spi->keyindex = max(local_keyindex + local_delkeyindex, global_keyindex) - local_delkeyindex;
		local_spi->key_sync_flag = true;
		return true;
	}
	else
	{
		printf("HMAC verify failed!\n");
		close(fd);
		return false;
	}
}

bool derive_sync(SpiParams *local_spi)
{
	local_spi->pre_t = local_spi->cur_t;
	gettimeofday(&local_spi->cur_t, NULL);
	static int fd = -1;
	int ret, tmp_keyd;
	int next_ekeyd = local_spi->cur_ekeyd;
	// ͨ����Կ�����жϽ���������Կ��������
	FILE *fp;
	fp = fopen(KEY_FILE, "rb");
	fseek(fp, 0, SEEK_END);	  // ��λ���ļ�ĩ
	int nFileLen = ftell(fp); // �ļ�����
	fclose(fp);
	// // �жϾ���Կ�ش�С
	// int poolsize = (nFileLen - 1 * local_spi->keyindex);
	if (nFileLen < LT * MAX_KEYFILE_SIZE)
	{
		tmp_keyd = (next_ekeyd * up_index) < 10000 ? next_ekeyd * up_index : 10000; // �������ӣ�����ÿ����Կ�������ݰ���Χ
	}
	else
	{
		if (local_spi->pre_t.tv_sec == 0)
		{
			tmp_keyd = next_ekeyd;
		}
		else
		{
			double duration = (local_spi->cur_t.tv_sec - local_spi->pre_t.tv_sec) + (local_spi->cur_t.tv_usec - local_spi->pre_t.tv_usec) / 1000000.0;
			int vconsume = 48 / duration; // ��������
			if (vconsume >= key_creat_rate / 2)
			{
				tmp_keyd = (next_ekeyd * up_index) < 10000 ? next_ekeyd * up_index : 10000; // ��������
			}
			else
			{
				tmp_keyd = (next_ekeyd - down_index) > 64 ? next_ekeyd - down_index : 64; // ���Լ�С
			}
		}
	}

	// ��δ���������
	if (fd == -1)
	{ // ���ӶԷ�������
		if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
		{
			perror("derive_sync connect error!\n");
			return false;
		}
	}
	// ������Ϣʱ
	const char *method = "desync";
	char data[2][17] = {0};
	unsigned char packet[PACKET_SIZE];

	// ������ת��Ϊ�ַ������洢��data������
	snprintf(data[0], 17, "%d", local_spi->spi);
	snprintf(data[1], 17, "%d", tmp_keyd);
	create_hmac_packet(method, data, 2, packet);
	ret = send(fd, packet, PACKET_SIZE, 0);

	if (ret < 0)
	{
		perror("derive_sync send error!\n");
		return false;
	}
	local_spi->cur_ekeyd = tmp_keyd;
	return true;
}

/**
 * @description: OTP������Կ��ֵeM����ͬ��
 * @param {SpiParams *} local_spi	����spi������ָ��
 * @return {*}	True if ͬ���ɹ�
 */
bool eM_sync(SpiParams *local_spi)
{
	static int fd = -1;
	int ret, tmp_eM;
	int spi = local_spi->spi;
	int eM = local_spi->eM;
	local_spi->pre_t = local_spi->cur_t;
	gettimeofday(&local_spi->cur_t, NULL);
	if (local_spi->pre_t.tv_sec == 0)
	{
		tmp_eM = eM;
	}
	else
	{
		double duration = (local_spi->cur_t.tv_sec - local_spi->pre_t.tv_sec) + (local_spi->cur_t.tv_usec - local_spi->pre_t.tv_usec) / 1000000.0;
		int vconsume = WINSIZE * eM / duration; // ��Կ�������ʣ���λ �ֽ�/s
		if (vconsume >= key_creat_rate / 2)
		{
			tmp_eM = (eM / 2 > 16) ? eM / 2 : 16; // ���Լ���,�½�16
		}
		else
		{
			tmp_eM = (eM + 16 < 128) ? eM + 16 : 128; // �������ӣ��Ͻ�128�ֽ�
		}
	}
	// ��δ���������
	if (fd == -1)
	{
		if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
		{
			perror("eM_sync connect error!\n");
			return false;
		}
	}
	// ������Ϣʱ
	const char *method = "eMsync";
	char data[2][17] = {0};
	unsigned char packet[PACKET_SIZE];

	// ������ת��Ϊ�ַ������洢��data������
	snprintf(data[0], 17, "%d", spi);
	snprintf(data[1], 17, "%d", tmp_eM);
	create_hmac_packet(method, data, 2, packet);
	ret = send(fd, packet, PACKET_SIZE, 0);
	if (ret < 0)
	{
		perror("eM_sync send error!\n");
		return false;
	}
	local_spi->eM = tmp_eM;
	return true;
}

/**
 * @description: �ӽ��ܶ�Ӧ��ϵ����
 * @param {char} *spi spi������ֵ
 * @param {char} *remote_flag 0 if ����
 * @param {int} fd socket�ļ�������
 * @return {*}
 */
void encflag_handle(const char *spi, const char *remote_flag, int fd)
{
	int i = 0;
	while (dynamicSPI[i]->spi != atoi(spi))
	{
		i++;
	}
	SpiParams *local_spi = dynamicSPI[i];
	printf("local_encrypt_flag:%d remote_flag:%d\n", local_spi->in_bound, atoi(remote_flag));

	// ������Ϣʱ
	const char *method = "encflagsync";
	char data[1][17] = {0};
	unsigned char packet[PACKET_SIZE];

	// ������ת��Ϊ�ַ������洢��data������
	snprintf(data[0], 17, "%d", local_spi->in_bound);
	create_hmac_packet(method, data, 1, packet);
	send(fd, packet, PACKET_SIZE, 0);
}

void SAkey_sync_handle(const char *remote_index, int fd)
{
	SAkey_sync_flag = true;
	IKEkeyindex = max(IKEkeyindex, atoi(remote_index));
	// ������Ϣʱ
	const char *method = "SAkeyindexsync";
	char data[1][17] = {0};
	unsigned char packet[PACKET_SIZE];

	// ������ת��Ϊ�ַ������洢��data������
	snprintf(data[0], 17, "%d", IKEkeyindex);
	create_hmac_packet(method, data, 1, packet);
	send(fd, packet, PACKET_SIZE, 0);
}

/**
 * @description: ��Կ����ͬ��������
 * @param {char} *spi spi������ֵ
 * @param {char} *global_index ȫ����Կƫ������
 * @param {int} fd socket�ļ�������
 * @return {*}
 */
void keysync_handle(const char *spi, const char *global_index, int fd)
{
	int i = 0;
	while (dynamicSPI[i]->spi != atoi(spi))
	{
		i++;
	}
	SpiParams *local_spi = dynamicSPI[i];
	int delkeyindex = local_spi->delkeyindex;
	int keyindex = local_spi->keyindex;
	local_spi->keyindex = max(delkeyindex + keyindex, atoi(global_index)) - delkeyindex;
	local_spi->key_sync_flag = true;
	// ������Ϣʱ
	const char *method = "keyindexsync";
	char data[1][17] = {0};
	unsigned char packet[PACKET_SIZE];

	// ������ת��Ϊ�ַ������洢��data������
	snprintf(data[0], 17, "%d", keyindex + delkeyindex);
	create_hmac_packet(method, data, 1, packet);
	send(fd, packet, PACKET_SIZE, 0);
}

/**
 * @description: ��Կ��������ͬ��
 * @param {char} *spi spi������ֵ
 * @param {char} *key_d ҪЭ�̵���Կ��������
 * @param {int} fd socket�ļ�������
 * @return {*}
 */
void desync_handle(const char *spi, const char *key_d, int fd)
{
	int i = 0;
	while (dynamicSPI[i]->spi != atoi(spi))
	{
		i++;
	}
	SpiParams *local_spi = dynamicSPI[i];
	int tmp_keyd = atoi(key_d);
	enqueue(local_spi->myQueue, tmp_keyd);
}

/**
 * @description:  ��Կ����ֵͬ��
 * @param {char} *spi spi������ֵ
 * @param {char} *tmp_eM ҪЭ�̵���Կ����ֵ����
 * @param {int} fd socket�ļ�������
 * @return {*}
 */
void eMsync_handle(const char *spi, const char *tmp_eM, int fd)
{
	int i = 0;
	while (dynamicSPI[i]->spi != atoi(spi))
	{
		i++;
	}
	SpiParams *local_spi = dynamicSPI[i];
	int tmp_dM = atoi(tmp_eM);
	enqueue(local_spi->myQueue, tmp_dM);
	return;
}

/**
 * @description: tcp���������У������ⲿ�˿�
 * @return {*}
 */
void *reactor_external_socket()
{

	printf("This is the tcp_unix thread.\n");
	int epfd1, nfds1, i;
	struct epoll_event events1[MAX_EVENTS];
	// ���� epoll ʵ��
	epfd1 = epoll_create1(0);
	if (epfd1 == -1)
	{
		perror("epoll_create1 error!\n");
		exit(1);
	}
	// �ⲿ����
	int external_lfd = init_listen_external(SERV_PORT, epfd1);
	while (1)
	{
		nfds1 = epoll_wait(epfd1, events1, MAX_EVENTS, -1);
		if (nfds1 == -1)
		{
			perror("epoll_wait error!\n");
			exit(1);
		}
		for (i = 0; i < nfds1; i++)
		{
			int fd = events1[i].data.fd;
			if (events1[i].events & EPOLLIN)
			{
				if (fd == external_lfd)
				{
					handler_conreq_tcp(external_lfd, epfd1); // �����ⲿTCP��������
				}
				else
				{
					handler_recdata_tcp(fd, epfd1); // ��Կ����ͬ���¼�
				}
			}
		}
	}
	close(epfd1);
	close(external_lfd);
	pthread_exit(NULL);
}
