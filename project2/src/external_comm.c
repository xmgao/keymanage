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

#define up_index 2									// 派生增长因子
#define down_index 500								// 派生减少因子
#define LT 0.2										// 下界
#define WINSIZE 4096								// 密钥窗口大小
#define HMAC_KEY "7890ABCDEF1234567890ABCDEF123456" // HMAC密钥
#define MAX_EVENTS 10000							// 最大监听数量

// 定义数据包结构长度
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

// 创建HMAC数据包
void create_hmac_packet(const char *method, const char data[][17], int data_count, unsigned char *packet)
{
	// 清空数据包
	memset(packet, 0, PACKET_SIZE);

	// 填充method
	strncpy((char *)packet, method, METHOD_SIZE);

	// 填充数据
	for (int i = 0; i < data_count && i < 10; i++)
	{
		if (DEBUG_LEVEL == 1)
		{
			printf("data[%d]: %s (line %d)\n", i, data[i], __LINE__);
		}

		strncpy((char *)(packet + METHOD_SIZE + i * 16), data[i], 16);
		// 确保字符串以null结尾
		packet[METHOD_SIZE + i * 16 + 16] = '\0';
	}

	//  计算HMAC
	unsigned char hmac_result[HMAC_SIZE];
	unsigned int len = HMAC_SIZE;
	HMAC(EVP_sha256(), HMAC_KEY, strlen(HMAC_KEY), packet, METHOD_SIZE + DATA_SIZE, hmac_result, &len);
	// 将HMAC结果直接添加到数据包末尾
	memcpy(packet + METHOD_SIZE + DATA_SIZE, hmac_result, HMAC_SIZE);
}

int verify_hmac_packet(const unsigned char *packet)
{
	unsigned char expected_hmac[HMAC_SIZE];
	unsigned int len = HMAC_SIZE;

	// 计算期望的HMAC
	HMAC(EVP_sha256(), HMAC_KEY, strlen(HMAC_KEY), packet, METHOD_SIZE + DATA_SIZE, expected_hmac, &len);

	// 比较期望的HMAC和接收到的HMAC
	return memcmp(expected_hmac, packet + METHOD_SIZE + DATA_SIZE, HMAC_SIZE) == 0;
}

/**
 * @description: 外部监听初始化，使用tcp
 * @param {int} port 需要监听的外部端口
 * @param {int} epfd epoll文件描述符
 * @return {int} 返回监听的套接字地址
 */
int init_listen_external(int port, int epfd)
{
	int lfd, ret;
	struct epoll_event tep;
	struct sockaddr_in serv_addr;

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	// 将用户输入的IP地址转换为网络字节序的二进制格式
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
	// 设置端口复用，使得跳过TIME_WAIT等待过程
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
 * @description: 发起tcp连接
 * @param {int} *fd 保存soket文件描述符的地址
 * @param {char} *dest 目的地址
 * @param {int} port 目的端口
 * @return {*} true if 连接成功
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

	cr = connect(*fd, (struct sockaddr *)(&serv_addr), sizeof(serv_addr)); // 连接对方服务器
	if (cr < 0)
	{
		perror("connect error!\n");
		return false;
	}
	return true;
}

/**
 * @description: 处理tcp连接请求
 * @param {int} fd 监听的文件描述符
 * @param {int} epfd epoll文件描述符
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

	// 获取客户端的 IP 地址
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

	// 检查客户端 IP 地址是否与 remoteip 匹配
	if (strcmp(cli_ip, remote_ip) != 0)
	{
		printf("Rejected connection from: %s\n", cli_ip);
		close(ar);
		return;
	}

	// 设置 ar socket 非阻塞
	int flag = fcntl(ar, F_GETFL);
	flag |= O_NONBLOCK;
	fcntl(ar, F_SETFL, flag);

	// 事件赋值
	tep.events = EPOLLIN;
	tep.data.fd = ar;

	// 事件上树
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, ar, &tep);
	if (ret == -1)
	{
		perror("epoll_ctl_add error");
		close(ar);
		exit(1);
	}
}

/**
 * @description: 关闭tcp连接
 * @param {int} fd 需要关闭的文件描述符
 * @param {int} epfd epoll文件描述符
 * @return {*}
 */
void discon(int fd, int epfd)
{
	int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
	if (ret < 0)
	{
		perror("EPOLL_CTL_DEL error...\n");
		// 可以选择记录日志或者执行其他错误处理逻辑
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
	// 清空缓冲区
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

		// 处理读取到的数据
		//  对应于keyindexsync  arg1=spi, arg2=global_keyindex
		//  对应于SAkeysync  arg1=remotekeyindex
		//  对应于encflagsync arg1==spi arg2=inbound
		//  对应于derive_sync  arg1==spi arg2==key_d
		//  对应于eM_sync  arg1==spi arg2==tem_eM

		// 解析method
		HandleData data1;
		memset(&data1, 0, sizeof(HandleData));
		strncpy(data1.method, (char *)received_packet, METHOD_SIZE);
		// 解析数据
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
 * @description: 加解密对应关系同步函数
 * @param {SpiParams *} local_spi 传入参数为本地spi参数的指针
 * @return {*} TRUE if加密对应解密
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

	// 将参数转换为字符串并存储在data数组中
	snprintf(data[0], 17, "%d", spi);
	snprintf(data[1], 17, "%d", local_flag);
	create_hmac_packet(method, data, 2, packet);
	send(fd, packet, PACKET_SIZE, 0);

	// 接收消息时
	char received_packet[PACKET_SIZE];
	read(fd, received_packet, PACKET_SIZE);

	// 验证HMAC
	if (verify_hmac_packet(received_packet))
	{
		if (DEBUG_LEVEL == 1)
		{
			printf("HMAC verify success! (line %d)\n", __LINE__);
		}
		// 解析method
		char method[METHOD_SIZE + 1] = {0};
		strncpy(method, (char *)received_packet, METHOD_SIZE);
		//  解析数据
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

// SA密钥同步,本地与远端服务器尝试建立连接同步密钥偏移
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

	// 将参数转换为字符串并存储在data数组中
	snprintf(data[0], 17, "%d", IKEkeyindex);
	// 打印调试信息
	if (DEBUG_LEVEL == 1)
	{
		printf("begin create hmac packet! (line %d)\n", __LINE__);
		printf("data[0]: %s\n", data[0]);
		printf("method: %s\n", method);
	}

	create_hmac_packet(method, data, 1, packet);
	send(fd, packet, PACKET_SIZE, 0);
	//  接收消息时
	char received_packet[PACKET_SIZE];
	read(fd, received_packet, PACKET_SIZE);

	// 验证HMAC
	if (verify_hmac_packet(received_packet))
	{
		// 解析method
		char method[METHOD_SIZE + 1] = {0};
		strncpy(method, (char *)received_packet, METHOD_SIZE);
		//  解析数据
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
 * @description: 密钥同步,本地与远端服务器建立连接同步密钥偏移
 * @param {SpiParams *} local_spi 本地spi参数的指针
 * @return {*} TRUE if密钥偏移同步成功
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

	// 将参数转换为字符串并存储在data数组中
	snprintf(data[0], 17, "%d", spi);
	snprintf(data[1], 17, "%d", local_keyindex + local_delkeyindex);
	create_hmac_packet(method, data, 2, packet);
	send(fd, packet, PACKET_SIZE, 0);

	// 接收消息时
	char received_packet[PACKET_SIZE];
	read(fd, received_packet, PACKET_SIZE);

	// 验证HMAC
	if (verify_hmac_packet(received_packet))
	{

		// 解析method
		char method[METHOD_SIZE + 1] = {0};
		strncpy(method, (char *)received_packet, METHOD_SIZE);
		//  解析数据
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
	// 通过密钥余量判断接下来的密钥派生参数
	FILE *fp;
	fp = fopen(KEY_FILE, "rb");
	fseek(fp, 0, SEEK_END);	  // 定位到文件末
	int nFileLen = ftell(fp); // 文件长度
	fclose(fp);
	// // 判断净密钥池大小
	// int poolsize = (nFileLen - 1 * local_spi->keyindex);
	if (nFileLen < LT * MAX_KEYFILE_SIZE)
	{
		tmp_keyd = (next_ekeyd * up_index) < 10000 ? next_ekeyd * up_index : 10000; // 乘性增加，增大每个密钥保护数据包范围
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
			int vconsume = 48 / duration; // 计算速率
			if (vconsume >= key_creat_rate / 2)
			{
				tmp_keyd = (next_ekeyd * up_index) < 10000 ? next_ekeyd * up_index : 10000; // 乘性增加
			}
			else
			{
				tmp_keyd = (next_ekeyd - down_index) > 64 ? next_ekeyd - down_index : 64; // 线性减小
			}
		}
	}

	// 还未发起过连接
	if (fd == -1)
	{ // 连接对方服务器
		if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
		{
			perror("derive_sync connect error!\n");
			return false;
		}
	}
	// 发送消息时
	const char *method = "desync";
	char data[2][17] = {0};
	unsigned char packet[PACKET_SIZE];

	// 将参数转换为字符串并存储在data数组中
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
 * @description: OTP分组密钥阈值eM更新同步
 * @param {SpiParams *} local_spi	本地spi参数的指针
 * @return {*}	True if 同步成功
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
		int vconsume = WINSIZE * eM / duration; // 密钥消耗速率，单位 字节/s
		if (vconsume >= key_creat_rate / 2)
		{
			tmp_eM = (eM / 2 > 16) ? eM / 2 : 16; // 乘性减少,下界16
		}
		else
		{
			tmp_eM = (eM + 16 < 128) ? eM + 16 : 128; // 加性增加，上界128字节
		}
	}
	// 还未发起过连接
	if (fd == -1)
	{
		if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
		{
			perror("eM_sync connect error!\n");
			return false;
		}
	}
	// 发送消息时
	const char *method = "eMsync";
	char data[2][17] = {0};
	unsigned char packet[PACKET_SIZE];

	// 将参数转换为字符串并存储在data数组中
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
 * @description: 加解密对应关系处理
 * @param {char} *spi spi的整数值
 * @param {char} *remote_flag 0 if 加密
 * @param {int} fd socket文件描述符
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

	// 发送消息时
	const char *method = "encflagsync";
	char data[1][17] = {0};
	unsigned char packet[PACKET_SIZE];

	// 将参数转换为字符串并存储在data数组中
	snprintf(data[0], 17, "%d", local_spi->in_bound);
	create_hmac_packet(method, data, 1, packet);
	send(fd, packet, PACKET_SIZE, 0);
}

void SAkey_sync_handle(const char *remote_index, int fd)
{
	SAkey_sync_flag = true;
	IKEkeyindex = max(IKEkeyindex, atoi(remote_index));
	// 发送消息时
	const char *method = "SAkeyindexsync";
	char data[1][17] = {0};
	unsigned char packet[PACKET_SIZE];

	// 将参数转换为字符串并存储在data数组中
	snprintf(data[0], 17, "%d", IKEkeyindex);
	create_hmac_packet(method, data, 1, packet);
	send(fd, packet, PACKET_SIZE, 0);
}

/**
 * @description: 密钥索引同步请求处理
 * @param {char} *spi spi的整数值
 * @param {char} *global_index 全局密钥偏移索引
 * @param {int} fd socket文件描述符
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
	// 发送消息时
	const char *method = "keyindexsync";
	char data[1][17] = {0};
	unsigned char packet[PACKET_SIZE];

	// 将参数转换为字符串并存储在data数组中
	snprintf(data[0], 17, "%d", keyindex + delkeyindex);
	create_hmac_packet(method, data, 1, packet);
	send(fd, packet, PACKET_SIZE, 0);
}

/**
 * @description: 密钥派生参数同步
 * @param {char} *spi spi的整数值
 * @param {char} *key_d 要协商的密钥派生参数
 * @param {int} fd socket文件描述符
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
 * @description:  密钥块阈值同步
 * @param {char} *spi spi的整数值
 * @param {char} *tmp_eM 要协商的密钥块阈值参数
 * @param {int} fd socket文件描述符
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
 * @description: tcp服务器运行，监听外部端口
 * @return {*}
 */
void *reactor_external_socket()
{

	printf("This is the tcp_unix thread.\n");
	int epfd1, nfds1, i;
	struct epoll_event events1[MAX_EVENTS];
	// 创建 epoll 实例
	epfd1 = epoll_create1(0);
	if (epfd1 == -1)
	{
		perror("epoll_create1 error!\n");
		exit(1);
	}
	// 外部监听
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
					handler_conreq_tcp(external_lfd, epfd1); // 处理外部TCP连接请求
				}
				else
				{
					handler_recdata_tcp(fd, epfd1); // 密钥参数同步事件
				}
			}
		}
	}
	close(epfd1);
	close(external_lfd);
	pthread_exit(NULL);
}
