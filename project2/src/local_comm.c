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

#define MAX_EVENTS 10000			 // 最大监听数量
#define BUFFER_SIZE 512				 // 普通数据包缓冲区最大长度
#define socket_path "/tmp/my_socket" // 定义本地套接字路径
#define WINSIZE 4096				 // 密钥窗口大小

#define DEBUG_LEVEL 1

void init_local_comm()
{
	pthread_t thread_local;
	// 启动监听服务器，开始监听密钥请求
	pthread_create(&thread_local, NULL, thread_reactor_local, NULL);
	if (pthread_detach(thread_local) != 0)
	{
		perror("pthread_detach");
		return;
	}
}

/**
 * @description: 本地监听初始化，使用AF_UNIX
 * @param {int} epfd epoll文件描述符
 * @return {int} 返回监听的套接字地址
 */
int init_listen_local(int epfd)
{
	int unix_sock, ret;
	struct epoll_event tep;

	struct sockaddr_un serv_addr;

	// 创建 UNIX 域套接字
	unix_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (unix_sock < 0)
	{
		perror("socket create error!\n");
		exit(1);
	}
	// 设置套接字地址信息
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sun_family = AF_UNIX;
	strncpy(serv_addr.sun_path, socket_path, sizeof(serv_addr.sun_path) - 1);

	// 在bind之前，你可以选择性地删除已存在的套接字文件
	unlink(socket_path); // 删除已存在的文件
	// 绑定 UNIX 域套接字
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
 * @description: 创建 UNIX 域套接字连接
 * @param {int} *fd 保存soket文件描述符的地址
 * @return {*} true if 连接成功
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

	cr = connect(*fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)); // 连接对方套接字地址
	if (cr < 0)
	{
		perror("connect error!\n");
		return false;
	}
	return true;
}

/**
 * @description:  处理 UNIX 域套接字连接请求
 * @param {int} fd 监听的文件描述符
 * @param {int} epfd epoll文件描述符
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
		// 处理错误
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
		perror("epoll_ctl_add error!\n");
		exit(1);
	}
}

/**
 * @description: 处理 UNIX 域套接字密钥和注册请求
 * @param {int} fd
 * @param {int} epfd
 * @return {*}
 */
void handler_recdata_unix(int fd, int epfd)
{
	char buffer[BUFFER_SIZE];
	// 清空缓冲区
	memset(buffer, 0, BUFFER_SIZE);
	ssize_t bytesRead = read(fd, buffer, BUFFER_SIZE);
	if (bytesRead == -1)
	{
		perror("Failed to read data from socket");
		exit(EXIT_FAILURE);
	}
	else if (bytesRead == 0)
	{
		// 连接关闭，进行相应处理
		discon(fd, epfd);
	}
	else
	{
		// 在这里处理从 UNIX 域套接字中读取的数据
		// 可以根据需求对读取到的数据进行处理
		// 读取数据后，检查并去除换行符
		if (buffer[bytesRead - 1] == '\n')
		{
			buffer[bytesRead - 1] = '\0'; // 将换行符替换为字符串结束符
		}
		if (DEBUG_LEVEL == 1)
		{
			printf("Received data from socket: %s\n", buffer);
		}
		//  对应于child_sa_register arg1==spi, arg2=inbound
		//  对应于getsharedkey  arg1=keylen(字节)
		//  对应于getsk  arg1==spi, arg2=keylen(字节), arg3=syn,arg4=keytype(0解密；1解密)
		//  对应于getotpk arg1==spi, arg2=syn,arg3=keytype //如果是解密spi则需要ntohl转换
		//  对应于child_sa_destroy arg1==spi
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
 * @description: DH以及预共享密钥请求处理
 * @param {char} *keylen 需要的密钥长度字符串常量
 * @param {int} fd	socket文件描述符
 * @return {*}
 */
void IKESA_key_get_handle(const char *keylen, int fd)
{
	int len = atoi(keylen);
	char buf[len + 1];
	// 判断是否已经同步，如果没有同步，首先进行双方同步
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
	// 读取密钥
	IKESA_key_read(buf, len);
	if (DEBUG_LEVEL == 1)
	{
		printf("qkey:%s size:%d sei:%d\n", buf, len, IKEkeyindex);
	}

	send(fd, buf, len, 0);
}

/**
 * @description: 会话密钥请求处理 密钥窗口还是放在kms里
 * @param {char} *spi 传入的SPI数字，字符串的形式
 * @param {char} *keylen  请求的密钥长度，字符串
 * @param {char} *syn	请求的序列号
 * @param {char} *key_type	请求的密钥类型，0加密 1解密
 * @param {int} fd	socket文件描述符
 * @return {*}
 */
void CHILDSA_key_get_handle(const char *spi, const char *keylen, const char *syn, const char *key_type, int fd)
{
	int i = 0;
	int hostspi = atoi(key_type) == 1 ? atoi(spi) : htonl(atoi(spi)); // 如果是获取加密密钥传入的spi值是主机字节，需要经过网络字节转换
	while (dynamicSPI[i]->spi != hostspi && i < spiCount)
	{
		i++;
	}
	SpiParams *local_spi = dynamicSPI[i];

	int seq = atoi(syn);
	int len = atoi(keylen);
	// 判断是否为第一个包
	if (seq == 1)
	{
		local_spi->encalg_keysize = len;
		if (local_spi->encalg == 0)
		{
			local_spi->encalg = 1; // 赋值为动态派生算法
		}
	}
	/* 减少延时先禁用这部分
	// 判断syn是否为1，且是加密方,是则进行加解密关系同步，否则不需要同步
	if (seq == 1 && atoi(key_type) == 0)
	{
		if (!CHILDSA_inbound_sync(local_spi))
		{
			perror("CHILDSA_inbound_sync error!\n");
			return;
		}
	}
	// 判断密钥索引是否同步，否则进行密钥索引同步
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
		bool ret = derive_para_sync(local_spi); // 派生参数同步
		if (!ret)
		{
			perror("derive_para_sync error!\n");
			return;
		}
		CHILDSA_key_read(local_spi, local_spi->raw_ekey, len); // 读取SA会话密钥

		memcpy(buf, &local_spi->cur_ekeyd, sizeof(int));
		memcpy(buf + sizeof(int), local_spi->raw_ekey, len);
	}
	else
	{
	loop1:
		if (is_empty(local_spi->myQueue))
		{ // 先判断队列是否为空，如果是空，说明参数还未到达队列，进行一定时间的等待
			usleep(100);
			goto loop1;
		}
		CHILDSA_key_read(local_spi, local_spi->raw_dkey, len); // 读取密钥
		int dkeyd = dequeue(local_spi->myQueue);			   // 正确的解密派生参数由一个队列管理
		memcpy(buf, &dkeyd, sizeof(int));
		memcpy(buf + sizeof(int), local_spi->raw_dkey, len);
	}
	send(fd, buf, sizeof(int) + len, 0);
}

/**
 * @description: otp密钥请求处理
 * @param {char} *spi	传入的SPI数字，字符串的形式
 * @param {char} *syn	请求的序列号
 * @param {char} *key_type	请求的密钥类型，0加密 1解密
 * @param {int} fd	socket文件描述符
 * @return {*}
 */
void OTP_key_get_handle(const char *spi, const char *syn, const char *key_type, int fd)
{
	int i = 0;
	int hostspi = atoi(key_type) == 1 ? atoi(spi) : htonl(atoi(spi)); // 如果是获取加密密钥传入的spi值是主机字节，需要经过网络字节转换
	while (dynamicSPI[i]->spi != hostspi && i < spiCount)
	{
		i++;
	}
	SpiParams *local_spi = dynamicSPI[i];

	if (local_spi->encalg == 0)
	{
		local_spi->encalg = 2; // 赋值为自适应一次一密算法
	}

	int seq = atoi(syn);
	// 判断syn是否为1，且是加密方，是则进行加解密关系同步，否则不需要同步
	if (seq == 1 && atoi(key_type) == 0)
	{
		if (!CHILDSA_inbound_sync(local_spi))
		{
			perror("CHILDSA_inbound_sync error!\n");
			return;
		}
	}
	// 判断密钥索引是否同步，否则进行密钥索引同步
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
	{ // 加密密钥
		int ekey_rw = local_spi->ekey_rw;
		if (seq > ekey_rw)
		{ //// 如果还没有初始的密钥或者超出密钥服务范围需要更新原始密钥以及syn窗口,协商新的密钥派生参数
			if (local_spi->ekeybuff != NULL)
				free(local_spi->ekeybuff);
			local_spi->ekeybuff = (Keyblock *)malloc(WINSIZE * sizeof(Keyblock));
			bool ret = key_threshold_sync(local_spi); // 密钥块阈值M同步
			for (int i = 0; i < WINSIZE; i++)
			{
				CHILDSA_key_read(local_spi, local_spi->ekeybuff[i].key, local_spi->eM);
				local_spi->ekeybuff[i].size = local_spi->eM;
			}
			// 更新窗口
			local_spi->ekey_rw = ekey_rw + WINSIZE;
		}
		// 解锁

		memcpy(buf, local_spi->ekeybuff[(seq - 1) % WINSIZE].key, local_spi->ekeybuff[(seq - 1) % WINSIZE].size);
		// printf("qkey:%s size:%d sei:%d\n", buf, local_spi->ekeybuff[(seq - 1) % WINSIZE].size, local_spi->keyindex);
		send(fd, buf, local_spi->ekeybuff[(seq - 1) % WINSIZE].size, 0);
	}
	else
	{ // 解密密钥:对于解密密钥维护一个旧密钥的窗口来暂存过去的密钥以应对失序包。
	loop2:
		if (seq > local_spi->dkey_rw)
		{
			if (is_empty(local_spi->myQueue))
			{ // 先判断队列是否为空，如果是空，说明参数还未到达队列，进行一定时间的等待
				usleep(100000);
				goto loop2;
			}
			// 如果还没有初始的密钥或者超出密钥服务范围需要更新原始密钥以及syn窗口,协商新的密钥派生参数
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
			// 更新窗口
			local_spi->dkey_lw = local_spi->dkey_rw + 1;
			local_spi->dkey_rw += WINSIZE;
			goto loop2;
		}
		// 解锁
		if (seq >= local_spi->dkey_lw)
		{
			memcpy(buf, local_spi->dkeybuff[(seq - 1) % WINSIZE].key, local_spi->dkeybuff[(seq - 1) % WINSIZE].size); // 正常数据包
			// printf("qkey:%s size:%d sei:%d\n", buf, local_spi->dkeybuff[(seq - 1) % WINSIZE].size, local_spi->keyindex);
			send(fd, buf, local_spi->dkeybuff[(seq - 1) % WINSIZE].size, 0);
		}
		else
		{
			memcpy(buf, local_spi->olddkeybuff[(seq - 1) % WINSIZE].key, local_spi->olddkeybuff[(seq - 1) % WINSIZE].size); // 乱序数据包
			// printf("qkey:%s size:%d sei:%d\n", buf, local_spi->olddkeybuff[(seq - 1) % WINSIZE].size, local_spi->keyindex);
			send(fd, buf, local_spi->olddkeybuff[(seq - 1) % WINSIZE].size, 0);
		}
	}
}

/**
 * @description: spi注册请求处理
 * @param {char *} spi	spi的整数值
 * @param {char *} inbound 1 if 入境SA
 * @return {*}
 */
void CHILDSA_register_handle(const char *spi, const char *inbound)
{
	// 假设检测到新的SPI
	int newSPI = htonl(atoi(spi)); // 先统一转换为网络字节序
	int newinbound = atoi(inbound);
	// 动态分配内存，并存储新的SPI参数
	create_sa(newSPI, newinbound);
}

void CHILDSA_destroy_handle(const char *spi){
	// 假设检测到SPI销毁请求
	int delSPI = htonl(atoi(spi)); // 先统一转换为网络字节序
	delete_sa(delSPI);
}

/**
 * @description: 子线程的代码,监听本地socket端口
 * @return {*}
 */
void *thread_reactor_local()
{
	// 子线程的代码
	printf("This is the af_unix thread.\n");
	int epfd, nfds, i;
	struct epoll_event events[MAX_EVENTS];
	// 创建 epoll 实例
	epfd = epoll_create1(0);
	if (epfd == -1)
	{
		perror("epoll_create1 error!\n");
		exit(1);
	}
	// 本地监听
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
					handler_conreq_unix(local_lfd, epfd); // 处理本地连接请求
				}
				else
				{
					handler_recdata_unix(fd, epfd); // 密钥请求及注册事件
				}
			}
		}
	}
	close(epfd);
	close(local_lfd);
	pthread_exit(NULL);
}
