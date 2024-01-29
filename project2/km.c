/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2023-03-30 15:42:44
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-01-29 11:40:11
 * @FilePath: \c\keymanage\project2\km.c
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */

#include "km.h"

//  编译: gcc km.c -o km -g -pthread
// 运行 sudo ./km remoteip >testlog 2> errlog

#define MAX_EVENTS 10000 // 最大监听数量
#define BUFFER_SIZE 128	 // 普通数据包缓冲区最大长度
#define buf_size 1548	 // OTP数据包缓冲区最大长度，应该为一个MTU加上完整性保护密钥的字节数
#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define socket_path "/tmp/my_socket"	  // 定义本地套接字路径
#define EXTERNAL_PORT 50001				  // 默认服务器外部监听端口
#define MAX_KEYFILE_SIZE 20 * 1024 * 1024 // 最大密钥文件大小，当密钥文件大于最大限制时，不再填充密钥 20M
#define keypool_path "keypool"			  // 定义本地密钥池文件夹
#define KEY_FILE "keyfile.kf"			  // dh,psk密钥文件
#define TEMPKEY_FILE "tempkeyfile.kf"	  // 临时密钥文件
#define INIT_KEYD 100					  // 初始密钥派生参数
#define INIT_KEYM 16					  // 初始OTP密钥块阈值16字节
#define up_index 2						  // 派生增长因子
#define down_index 500					  // 派生减少因子
#define LT 0.2							  // 下界
#define HT 0.7							  // 上界
#define WINSIZE 4096					  // 密钥窗口大小
#define MAX_DYNAMIC_SPI_COUNT 100		  // 最多同时存在SPI个数

SpiParams *dynamicSPI[MAX_DYNAMIC_SPI_COUNT];
int key_creat_rate;		// 密钥产生速率全局变量
int SAkeyindex;			// 用于标识本地SA密钥池索引。
bool SAkey_sync_flag;	// 密钥同步标志，用于供应sa协商
int spiCount = 0;		// 当前SPI个数
pthread_rwlock_t keywr; // 共享密钥池的读写锁
pthread_mutex_t mutex;	// 共享密钥池的读写锁
int SERV_PORT;			// 服务器监听端口
char remote_ip[32];		// 记录远程ip地址

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

// TODO：需要实现一种访问控制机制，拒绝恶意的IP地址
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
	// 外部监听
	inet_pton(AF_INET, "0.0.0.0", &serv_addr.sin_addr.s_addr);
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
 * @description: 创建 UNIX 域套接字连接
 * @param {int} *fd 保存soket文件描述符的地址
 * @return {*} true if 连接成功
 */
bool con_unixserv(int *fd)
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
 * @description: 处理tcp连接请求
 * @param {int} fd 监听的文件描述符
 * @param {int} epfd epoll文件描述符
 * @return {*}
 */
void handler_conreq_tcp(int fd, int epfd)
{
	struct sockaddr_in cli_addr;
	char cli_ip[16];
	int client_addr_size, ret;
	struct epoll_event tep;
	int ar = accept(fd, (struct sockaddr *)(&cli_addr), &client_addr_size);
	// printf("ip address is: %s,port is: %d\n", inet_ntop(AF_INET, &cli_addr.sin_addr.s_addr, cli_ip, sizeof(cli_ip)), ntohs(cli_addr.sin_port));
	//  设置ar socket非阻塞
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
	else
	{
		// printf("Unix domain socket path is: %s\n", cli_addr.sun_path);
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
 * @description: 关闭tcp或unix连接
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
		// printf("Received data from socket: %s\n", buffer);
		//  对应于getk  arg1=keylen(字节)
		//  对应于getsk  arg1==spi, arg2=keylen(字节), arg3=syn,arg4=keytype(0解密；1解密)
		//  对应于getotpk arg1==spi, arg2=syn,arg3=keytype //如果是解密spi则需要ntohl转换
		//  对应于spiregister arg1==spi, arg2=inbound
		HandleData data1;
		sscanf(buffer, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", data1.method, data1.arg1, data1.arg2, data1.arg3, data1.arg4);
		if (strncasecmp(data1.method, "spiregister", 11) == 0)
		{
			spiregister_handle(data1.arg1, data1.arg2, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(data1.method, "getsharedkey", 12) == 0)
		{
			getsharedkey_handle(data1.arg1, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(data1.method, "getotpk", 7) == 0)
		{
			getotpk_handle(data1.arg1, data1.arg2, data1.arg3, fd);
		}
		else if (strncasecmp(data1.method, "getsk", 5) == 0)
		{
			getsk_handle(data1.arg1, data1.arg2, data1.arg3, data1.arg4, fd);
		}
		else
		{
			printf("invalid recvdata\n");
			discon(fd, epfd);
		}
	}
	return;
}

/**
 * @description:
 * @param {int} fd
 * @param {int} epfd
 * @return {*}
 */
void handler_recdata_tcp(int fd, int epfd)
{

	char buffer[BUFFER_SIZE];
	// 清空缓冲区
	memset(buffer, 0, BUFFER_SIZE);
	// tcpsockfd 上有数据到达
	ssize_t bytesRead = read(fd, buffer, BUFFER_SIZE);
	if (bytesRead == -1)
	{
		perror("Failed to read data from sockfd");
		exit(EXIT_FAILURE);
	}
	else if (bytesRead == 0)
	{
		// 连接关闭，进行相应处理
		discon(fd, epfd);
	}
	else
	{
		// 处理读取到的数据
		if (buffer[bytesRead - 1] == '\n')
			buffer[bytesRead - 1] = '\0';
		// printf("recieve:%s\n", buffer);
		//  对应于keyindexsync  arg1=spi, arg2=global_keyindex
		//  对应于SAkeysync  arg1=remotekeyindex
		//  对应于encflagsync arg1==spi arg2=encrypt_flag
		//  对应于derive_sync  arg1==spi arg2==key_d
		//  对应于eM_sync  arg1==spi arg2==tem_eM
		HandleData data1;
		sscanf(buffer, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", data1.method, data1.arg1, data1.arg2, data1.arg3, data1.arg4);
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
			printf("invalid recdata:%s\n", buffer);
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
	int local_flag = local_spi->encrypt_flag;
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
	int fd, ret, remote_flag;
	if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
	{
		perror("encflag_sync connect error!\n");
		return false;
	}
	printf("spi:%d\tencrypt_flag:%d\n", spi, local_flag);
	sprintf(buf, "encflagsync %d %d\n", spi, local_flag);
	send(fd, buf, strlen(buf), 0);

	ret = read(fd, rbuf, sizeof(rbuf));
	sscanf(rbuf, "%[^ ] %d", method, &remote_flag); // scanf("%[^\n] ", s); 输入一行，回车作为结束符。 行末回车符不处理; %[^ ]表示除了空格都可以读
	close(fd);
	if (local_flag ^ remote_flag == 1)
		return true;
	return false;
}

// SA密钥同步,本地与远端服务器尝试建立连接同步密钥偏移
bool SAkey_sync()
{
	int fd, ret;
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
	if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
	{
		perror("SAkeysync connect error!\n");
		return false;
	}
	sprintf(buf, "SAkeysync %d\n", SAkeyindex);
	ret = send(fd, buf, strlen(buf), 0);
	if (ret < 0)
	{
		perror("SAkeysync send error!\n");
		return false;
	}
	ret = read(fd, rbuf, sizeof(rbuf));
	int remote_keyindex;
	sscanf(rbuf, "%[^ ] %d", method, &remote_keyindex);
	SAkeyindex = max(SAkeyindex, remote_keyindex);
	SAkey_sync_flag = true;
	close(fd);
	return true;
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
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];

	if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
	{
		perror("keyindexsync connect error!\n");
		return false;
	}
	sprintf(buf, "keyindexsync %d %d\n", spi, local_keyindex + local_delkeyindex);
	ret = send(fd, buf, strlen(buf), 0);
	if (ret < 0)
	{
		perror("keyindex_sync connect error!\n");
		return false;
	}
	ret = read(fd, rbuf, sizeof(rbuf));
	int global_keyindex;
	sscanf(rbuf, "%[^ ] %d", method, &global_keyindex); // 修改
	close(fd);
	local_spi->keyindex = max(local_keyindex + local_delkeyindex, global_keyindex) - local_delkeyindex;
	local_spi->key_sync_flag = true;
	return true;
}

bool derive_sync(SpiParams *local_spi)
{
	local_spi->pre_t = local_spi->cur_t;
	gettimeofday(&local_spi->cur_t, NULL);
	static int fd = -1;
	int ret, tmp_keyd;
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
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

	sprintf(buf, "desync %d %d\n", local_spi->spi, tmp_keyd);
	// 还未发起过连接
	if (fd == -1)
	{ // 连接对方服务器
		if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
		{
			perror("derive_sync connect error!\n");
			return false;
		}
	}
	ret = send(fd, buf, strlen(buf), 0);
	if (ret < 0)
	{
		perror("derive_sync send error!\n");
		return false;
	}
	local_spi->cur_ekeyd = tmp_keyd;
	return true;
}
/**
 * @description: // 密钥派生参数协商 版本2，只按照密钥池阈值变化
 * @param {SpiParams *} local_spi 本地spi参数的指针
 * @return {*} TRUE if密钥派生参数协商成功
 */
// bool derive_sync(SpiParams *local_spi)
// {
// 	int spi = local_spi->spi;
// 	static int fd = -1;
// 	int ret, tmp_keyd;
// 	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
// 	int next_ekeyd = local_spi->cur_ekeyd;
// 	// 通过密钥余量判断接下来的密钥派生参数
// 	FILE *fp;
// 	fp = fopen(KEY_FILE, "rb");
// 	fseek(fp, 0, SEEK_END);	  // 定位到文件末
// 	int nFileLen = ftell(fp); // 文件长度
// 	fclose(fp);
// 	// 判断净密钥池大小
// 	int poolsize = (nFileLen - 1 * local_spi->keyindex);
// 	if (poolsize < LT * MAX_KEYFILE_SIZE)
// 	{
// 		tmp_keyd = (next_ekeyd * up_index) < 10000 ? next_ekeyd * up_index : 10000; // 乘性增加，增大每个密钥保护数据包范围
// 	}
// 	else if (poolsize > HT * MAX_KEYFILE_SIZE)
// 	{
// 		tmp_keyd = (next_ekeyd - down_index) > 100 ? next_ekeyd - down_index : 100; // 线性减小，减少每个密钥保护数据包范围
// 	}
// 	else
// 	{
// 		tmp_keyd = next_ekeyd;
// 	}

// 	sprintf(buf, "desync %d %d\n", spi, tmp_keyd);
// 	// 还未发起过连接
// 	if (fd == -1)
// 	{ // 连接对方服务器
// 		if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
// 		{
// 			perror("derive_sync connect error!\n");
// 			return false;
// 		}
// 	}
// 	ret = send(fd, buf, strlen(buf), 0);
// 	if (ret < 0)
// 	{
// 		perror("derive_sync send error!\n");
// 		return false;
// 	}
// 	local_spi->cur_ekeyd = tmp_keyd;
// 	return true;
// }

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
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
	sprintf(buf, "eMsync %d %d\n", spi, tmp_eM);
	// 还未发起过连接
	if (fd == -1)
	{
		if (!con_tcpserv(&fd, remote_ip, SERV_PORT))
		{
			perror("eM_sync connect error!\n");
			return false;
		}
	}
	ret = send(fd, buf, strlen(buf), 0);
	if (ret < 0)
	{
		perror("eM_sync send error!\n");
		return false;
	}
	local_spi->eM = tmp_eM;
	return true;
}

/**
 * @description:  更新密钥池，更新删除密钥索引
 * @param {SpiParams *} local_spi 本地spi参数的指针
 * @return {*}
 */
void renewkey(SpiParams *local_spi)
{
	int delindex = local_spi->keyindex; // 要删除的密钥的索引
	if (delindex == 0)
	{
		return;
	}
	FILE *fp = fopen(local_spi->keyfile, "rb");
	FILE *fp2 = fopen(TEMPKEY_FILE, "wb");
	if (fp == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	else
	{
		fseek(fp, delindex * 1, SEEK_SET); // 文件指针偏移到指定位置
		char buffer = fgetc(fp);
		int cnt = 0;
		while (!feof(fp))
		{
			cnt++;
			fputc(buffer, fp2);
			buffer = fgetc(fp);
		}
		fclose(fp2);
	}
	fclose(fp);
	remove(KEY_FILE);
	if (rename(TEMPKEY_FILE, KEY_FILE) == 0)
	{
		local_spi->delkeyindex += delindex;
		local_spi->keyindex = 0;
		printf("key pool renewed...\ndelkeyindex:%d  keyindex:%d  \n", local_spi->delkeyindex, local_spi->keyindex);
	}
	else
	{
		perror("rename error!");
	}
}

// 比较函数用于排序
int compare(const void *a, const void *b)
{
	const char *strA = *(const char **)a;
	const char *strB = *(const char **)b;
	return strcmp(strA, strB);
	// 将文件名转换为数字并进行比较
	// int numA = atoi(strA);
	// int numB = atoi(strB);

	// return numA - numB;
}

/**
 * @description:
 * @param {char} *folderPath
 * @param {FILE} *fp
 * @return {*}
 */
void readFilesInFolder(const char *folderPath, FILE *fp)
{
	DIR *dir;
	struct dirent *entry;

	dir = opendir(folderPath);
	if (dir == NULL)
	{
		perror("null folderpath!");
		return;
	}
	// 最多100个密钥文件，100k
	const int maxFiles = 100;		   //
	const int maxFileNameLength = 256; // 最大文件名长度
	char **fileNames = (char **)malloc(maxFiles * sizeof(char *));
	int numFiles = 0;

	while ((entry = readdir(dir)) != NULL)
	{
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		char filePath[maxFileNameLength];
		sprintf(filePath, "%s/%s", folderPath, entry->d_name);
		if (entry->d_type == DT_DIR)
		{
			readFilesInFolder(filePath, fp);
		}
		else
		{
			//
			fileNames[numFiles] = (char *)malloc(sizeof(char) * maxFileNameLength);
			strcpy(fileNames[numFiles], entry->d_name);
			numFiles++;
		}
	}
	closedir(dir);

	// numFiles==1;保护最后一个密钥文件，有可能正在写入
	if (numFiles <= 1)
	{
		usleep(100000);
		free(fileNames[0]);
		free(fileNames);
		return;
	}

	// 将密钥文件按照文件名(产生的时间顺序)排序
	qsort(fileNames, numFiles, sizeof(const char *), compare);

	// 写入密钥到文件fp内
	for (int i = 0; i < numFiles - 1; i++)
	{
		// printf("filename:%s\n", fileNames[i]);
		char kfilePath[256]; //
		sprintf(kfilePath, "%s/%s", folderPath, fileNames[i]);
		FILE *file = fopen(kfilePath, "rb");
		if (file)
		{
			char buffer[1024];
			size_t bytesRead;
			while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0)
			{
				fwrite(buffer, 1, bytesRead, fp);
			}
			fclose(file);
			// 读取后删除密钥
			// remove(kfilePath);
		}
		free(fileNames[i]);
	}

	free(fileNames);
}

// 为每个spi的密钥池写入密钥
/**
 * @description:
 * @param {void} *args
 * @return {*}
 */
void *thread_writeSAkey(void *args)
{

	printf("spikey supply starting...\n");
	// 模拟不断写入密钥到密钥池文件
	while (1)
	{
		usleep(500000); // 等待0.5s
		for (int i = 0; i < spiCount; i++)
		{
			FILE *fp = fopen(dynamicSPI[i]->keyfile, "ab");
			int nFileLen = ftell(fp); // 文件长度
			if (nFileLen < 10 * MAX_KEYFILE_SIZE)
			{
				const char *folderPath = "my_folder";		   // 文件夹路径
				pthread_rwlock_wrlock(&dynamicSPI[i]->rwlock); // 上写锁
				readFilesInFolder(folderPath, fp);
				pthread_rwlock_unlock(&dynamicSPI[i]->rwlock); // 解锁
			}
			fclose(fp);
		}
	}
}

/**
 * @description: 	// 模拟不断写入密钥到密钥池文件
 * @param {void} *args 空参数
 * @return {*}
 */
// void *thread_writesharedkey(void *args)
// {
// 	// 首先定义文件指针：fp
// 	FILE *fp;
// 	remove(KEY_FILE);
// 	printf("sharedkey supply starting...\n");
// 	// 模拟不断写入密钥到密钥池文件
// 	srand(666);
// 	while (1)
// 	{
// 		// 再填充sharedkey密钥,写入DH密钥和预共享密钥，为他们单独提供一个密钥池
// 		unsigned char *buf = (unsigned char *)malloc(key_creat_rate * sizeof(unsigned char));
// 		for (int i = 0; i < key_creat_rate; i++)
// 		{ // 随机形成密钥串
// 			buf[i] = rand() % 256;
// 		}
// 		pthread_rwlock_wrlock(&keywr); // 上锁
// 		fp = fopen(KEY_FILE, "ab");
// 		fseek(fp, 0, SEEK_END);	  // 定位到文件末
// 		int nFileLen = ftell(fp); // 文件长度
// 		// printf("keypoolsize:%d Byetes\n", nFileLen);
// 		if (nFileLen < MAX_KEYFILE_SIZE)
// 		{
// 			fwrite(buf, sizeof(unsigned char), key_creat_rate, fp);
// 		}
// 		free(buf);
// 		fclose(fp);
// 		pthread_rwlock_unlock(&keywr); // 解锁
// 		usleep(500000);				   // 等待0.5s
// 	}
// 	pthread_exit(0);
// }

// 密钥速率探测
void *thread_keyradetection(void *args)
{
	key_creat_rate = 100000; // 初始化速率100kbps
	// 首先定义文件指针：fp
	FILE *fp;
	int prefilelen = 0;
	int nextfilelen = 0;
	int detetctime = 500000; // 探测时间，单位us
	while (1)
	{
		fp = fopen(KEY_FILE, "rb");
		fseek(fp, 0, SEEK_END);	 // 定位到文件末
		nextfilelen = ftell(fp); // 文件长度
		fclose(fp);
		if (prefilelen == 0)
		{
			prefilelen = nextfilelen;
		}
		else
		{	
			// 此时探测密钥速率
			key_creat_rate = (int)((nextfilelen - prefilelen) * 1000 / detetctime); // kbps
			//printf("key_creat_rate: %d kbps\n", key_creat_rate);
			prefilelen = nextfilelen;
		}
		usleep(detetctime); // 等待0.5s
	}
	pthread_exit(0);
}

// 密钥重放器
void *thread_writesharedkey(void *args)
{
	// 首先定义文件指针：fp
	FILE *fp = fopen(KEY_FILE, "ab+");
	fseek(fp, 0, SEEK_END); // 定位到文件末
	printf("sharedkey supply starting...\n");
	FILE *file = fopen("rawkeyfile.kf", "rb"); // 格式化的密钥重放文件
	if (file == NULL)
	{
		perror("Error opening file");
		pthread_exit(0);
	}
	unsigned char block[522]; // 8字节时间戳+2字节密钥长度(512字节)+512字节密钥
	time_t prevTimestamp = 0;
	while (fread(block, sizeof(char), sizeof(block), file) == sizeof(block))
	{
		// 提取时间戳
		time_t currentTimestamp;
		memcpy(&currentTimestamp, block, sizeof(uint64_t));
		if (prevTimestamp != 0)
		{
			// 单位纳秒
			time_t interval = currentTimestamp - prevTimestamp;
			// 执行操作，暂停指定间隔
			// printf("Performing operation with interval: %.2f mseconds\n", (float)interval/ 1000000);
			unsigned char key[512];
			memcpy(key, block + sizeof(uint64_t) + 2, 512);
			pthread_rwlock_wrlock(&keywr); // 上锁
			fseek(fp, 0, SEEK_END);		   // 定位到文件末
			int nFileLen = ftell(fp);	   // 文件长度
			if (nFileLen < MAX_KEYFILE_SIZE)
			{
				fwrite(key, sizeof(unsigned char), 512, fp);
			}
			pthread_rwlock_unlock(&keywr); // 解锁
			// 按照指定间隔暂停程序执行,微妙
			usleep((int)(interval / 1000));
		}
		prevTimestamp = currentTimestamp;
	}
	fclose(file);
	fclose(fp);
	pthread_exit(0);
}

/**
 * @description: 读取DH密钥和预共享密钥，为他们单独提供一个密钥池
 * @param {char} *buf	保存密钥的缓存数组
 * @param {int} len		需要密钥的长度
 * @return {*}
 */
void readsharedkey(char *const buf, int len)
{
	char *pb = buf;
	pthread_rwlock_rdlock(&keywr); // 上读锁
	FILE *fp = fopen(KEY_FILE, "rb");
	if (fp == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	while (1)
	{
		fseek(fp, SAkeyindex, SEEK_SET); // 将文件指针偏移到指定位置
		int bytes_read = fread(pb, sizeof(char), len, fp);
		// 在 buffer 中有 bytes_read 个字节的数据，其中可能包含空字符
		if (bytes_read == len)
		{
			break;
		}
		else
		{
			printf("key supply empty!\n");
			pthread_rwlock_unlock(&keywr); // 解锁
			sleep(1);
			pthread_rwlock_rdlock(&keywr); // 上读锁
			printf("key require try again!\n");
		}
	}
	SAkeyindex += len;
	fclose(fp);
	pthread_rwlock_unlock(&keywr); // 解锁
}

/**
 * @description:  读取本地SA会话密钥
 * @param {SpiParams *} local_spi 本地spi参数的指针
 * @param {char} *buf 保存密钥的缓存数组
 * @param {int} len 需要密钥的长度
 * @return {*}
 */
void readSAkey(SpiParams *local_spi, char *const buf, int len)
{
	char *pb = buf;
	pthread_rwlock_rdlock(&(local_spi->rwlock)); // 上读锁
	FILE *fp = fopen(local_spi->keyfile, "rb");
	if (fp == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	int keyindex = local_spi->keyindex;
	while (1)
	{
		fseek(fp, keyindex, SEEK_SET); // 将文件指针偏移到指定位置
		int bytes_read = fread(pb, sizeof(char), len, fp);
		if (bytes_read == len)
		{
			// 在 buffer 中有 bytes_read 个字节的数据，其中可能包含空字符
			break;
		}
		else
		{
			printf("key supply empty!\n");
			pthread_rwlock_unlock(&local_spi->rwlock); // 解锁
			sleep(1);
			pthread_rwlock_rdlock(&local_spi->rwlock); // 上读锁
			printf("key require try again!\n");
		}
	}
	keyindex += len;
	local_spi->keyindex = keyindex;
	fclose(fp);
	pthread_rwlock_unlock(&local_spi->rwlock); // 解锁
}

/**
 * @description: DH以及预共享密钥请求处理
 * @param {char} *keylen 需要的密钥长度字符串常量
 * @param {int} fd	socket文件描述符
 * @return {*}
 */
void getsharedkey_handle(const char *keylen, int fd)
{
	int len = atoi(keylen);
	char buf[len + 1];
	// 判断是否已经同步，如果没有同步，首先进行双方同步
	if (!SAkey_sync_flag)
	{
		bool ret = SAkey_sync();
		if (!ret)
		{
			perror("SAkey_sync error!\n");
			char buf2[] = "A";
			send(fd, buf2, strlen(buf2), 0);
			return;
		}
	}
	// 读取密钥
	readsharedkey(buf, len);
	// printf("qkey:%s size:%d sei:%d\n", buf, len, SAkeyindex);
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
void getsk_handle(const char *spi, const char *keylen, const char *syn, const char *key_type, int fd)
{
	int i = 0;
	int hostspi = atoi(key_type) == 1 ? ntohl(atoi(spi)) : atoi(spi);
	while (dynamicSPI[i]->spi != hostspi)
	{
		i++;
	}
	SpiParams *local_spi = dynamicSPI[i];
	int seq = atoi(syn);
	int len = atoi(keylen);
	// 判断syn是否为1，且是加密方,是则进行加解密关系同步，否则不需要同步
	if (seq == 1 && atoi(key_type) == 0)
	{
		if (!encflag_sync(local_spi))
		{
			perror("encflag_sync error!\n");
			return;
		}
	}
	// 判断密钥索引是否同步，否则进行密钥索引同步
	if (!local_spi->key_sync_flag)
	{
		if (!key_index_sync(local_spi))
		{
			perror("keyindex_sync error!\n");
			return;
		}
	}
	char buf[BUFFER_SIZE];
	if (*key_type == '0')
	{
		bool ret = derive_sync(local_spi); // 派生参数同步
		if (!ret)
		{
			perror("derive_sync error!\n");
			return;
		}
		readSAkey(local_spi, local_spi->raw_ekey, len); // 读取SA会话密钥

		memcpy(buf, &local_spi->cur_ekeyd, sizeof(int));
		memcpy(buf + sizeof(int), local_spi->raw_ekey, len);
	}
	else
	{
	loop1:
		if (isEmpty(&local_spi->myQueue))
		{ // 先判断队列是否为空，如果是空，说明参数还未到达队列，进行一定时间的等待
			usleep(1000);
			goto loop1;
		}
		readSAkey(local_spi, local_spi->raw_dkey, len); // 读取密钥
		int dkeyd = dequeue(&local_spi->myQueue);		// 正确的解密派生参数由一个队列管理
		memcpy(buf, &dkeyd, sizeof(int));
		memcpy(buf + sizeof(int), local_spi->raw_dkey, len);
	}
	send(fd, buf, sizeof(int)+len, 0);
}

// void getsk_handle(const char *spi, const char *keylen, const char *syn, const char *key_type, int fd)
// {
// 	int i = 0;
// 	int hostspi = atoi(key_type) == 1 ? ntohl(atoi(spi)) : atoi(spi);
// 	while (dynamicSPI[i]->spi != hostspi)
// 	{
// 		i++;
// 	}
// 	SpiParams *local_spi = dynamicSPI[i];
// 	int seq = atoi(syn);
// 	int len = atoi(keylen);
// 	// 判断syn是否为1，且是加密方,是则进行加解密关系同步，否则不需要同步
// 	if (seq == 1 && atoi(key_type) == 0)
// 	{
// 		if (!encflag_sync(local_spi))
// 		{
// 			perror("encflag_sync error!\n");
// 			return;
// 		}
// 	}
// 	// 判断密钥索引是否同步，否则进行密钥索引同步
// 	if (!local_spi->key_sync_flag)
// 	{
// 		if (!key_index_sync(local_spi))
// 		{
// 			perror("keyindex_sync error!\n");
// 			return;
// 		}
// 	}
// 	char buf[BUFFER_SIZE];
// 	if (*key_type == '0')
// 	{
// 		if (seq > local_spi->ekey_rw)
// 		{									   // 如果还没有初始的密钥或者超出密钥服务范围需要进行派生参数同步
// 			bool ret = derive_sync(local_spi); // 派生参数同步
// 			if (!ret)
// 			{
// 				perror("derive_sync error!\n");
// 				return;
// 			}
// 			readSAkey(local_spi, local_spi->raw_ekey, len); // 读取SA会话密钥
// 			local_spi->ekey_rw += local_spi->cur_ekeyd;
// 		}
// 		memcpy(buf, local_spi->raw_ekey, len);
// 	}
// 	else // 解密密钥:对于解密密钥维护一个旧密钥的窗口来暂存过去的密钥以应对失序包。
// 	{
// 	loop1:
// 		if (seq > local_spi->dkey_rw)
// 		{
// 			if (isEmpty(&local_spi->myQueue))
// 			{ // 先判断队列是否为空，如果是空，说明参数还未到达队列，进行一定时间的等待
// 				usleep(100000);
// 				goto loop1;
// 			}
// 			// 如果还没有初始的密钥或者超出密钥服务范围需要更新原始密钥以及syn窗口,
// 			memcpy(local_spi->old_dkey, local_spi->raw_dkey, len);
// 			readSAkey(local_spi, local_spi->raw_dkey, len); // 读取密钥
// 			// 更新窗口
// 			local_spi->dkey_lw = local_spi->dkey_rw + 1;
// 			int dkeyd = dequeue(&local_spi->myQueue); // 正确的解密派生参数由一个队列管理
// 			local_spi->dkey_rw += dkeyd;
// 			goto loop1;
// 		}

// 		if (seq >= local_spi->dkey_lw)
// 		{
// 			memcpy(buf, local_spi->raw_dkey, len); // 正常数据包
// 		}
// 		else
// 		{
// 			memcpy(buf, local_spi->old_dkey, len); // 乱序数据包
// 		}
// 	}
// 	//printf("qkey:%s size:%d sei:%d\n", buf, len, local_spi->keyindex);
// 	send(fd, buf, len, 0);
// }

/**
 * @description: otp密钥请求处理
 * @param {char} *spi	传入的SPI数字，字符串的形式
 * @param {char} *syn	请求的序列号
 * @param {char} *key_type	请求的密钥类型，0加密 1解密
 * @param {int} fd	socket文件描述符
 * @return {*}
 */
void getotpk_handle(const char *spi, const char *syn, const char *key_type, int fd)
{
	int i = 0;
	int hostspi = atoi(key_type) == 1 ? ntohl(atoi(spi)) : atoi(spi);
	while (dynamicSPI[i]->spi != hostspi)
	{
		i++;
	}
	SpiParams *local_spi = dynamicSPI[i];
	int seq = atoi(syn);
	// 判断syn是否为1，且是加密方，是则进行加解密关系同步，否则不需要同步
	if (seq == 1 && atoi(key_type) == 0)
	{
		if (!encflag_sync(local_spi))
		{
			perror("encflag_sync error!\n");
			return;
		}
	}
	// 判断密钥索引是否同步，否则进行密钥索引同步
	if (!local_spi->key_sync_flag)
	{
		if (!key_index_sync(local_spi))
		{
			perror("keyindex_sync error!\n");
			return;
		}
	}
	char buf[buf_size];
	if (*key_type == '0')
	{ // 加密密钥
		int ekey_rw = local_spi->ekey_rw;
		if (seq > ekey_rw)
		{ //// 如果还没有初始的密钥或者超出密钥服务范围需要更新原始密钥以及syn窗口,协商新的密钥派生参数
			if (local_spi->ekeybuff != NULL)
				free(local_spi->ekeybuff);
			local_spi->ekeybuff = (Keyblock *)malloc(WINSIZE * sizeof(Keyblock));
			bool ret = eM_sync(local_spi); // 密钥块阈值M同步
			for (int i = 0; i < WINSIZE; i++)
			{
				readSAkey(local_spi, local_spi->ekeybuff[i].key, local_spi->eM);
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
			if (isEmpty(&local_spi->myQueue))
			{ // 先判断队列是否为空，如果是空，说明参数还未到达队列，进行一定时间的等待
				usleep(100000);
				goto loop2;
			}
			// 如果还没有初始的密钥或者超出密钥服务范围需要更新原始密钥以及syn窗口,协商新的密钥派生参数
			if (local_spi->olddkeybuff != NULL)
				free(local_spi->olddkeybuff);
			local_spi->olddkeybuff = local_spi->dkeybuff;
			local_spi->dkeybuff = (Keyblock *)malloc(WINSIZE * sizeof(Keyblock));
			int dM = dequeue(&local_spi->myQueue);
			for (int i = 0; i < WINSIZE; i++)
			{
				readSAkey(local_spi, local_spi->dkeybuff[i].key, dM);
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
 * @param {int} fd socket文件描述符
 * @return {*}
 */
void spiregister_handle(const char *spi, const char *inbound, int fd)
{
	// 假设通过某种方式检测到新的SPI
	int newSPI = atoi(spi);
	int newinbound = atoi(inbound);
	// 动态分配内存，并存储新的SPI参数
	dynamicSPI[spiCount] = (SpiParams *)malloc(sizeof(SpiParams));

	char hexStr[64];											// 足够大的字符数组来存储转换后的字符串
	sprintf(hexStr, "%s/%x", keypool_path, htonl(newSPI));		// 将数字转换为十六进制字符串
	strcpy(dynamicSPI[spiCount]->keyfile, hexStr);				// 用SPI初始化密钥池名字
	pthread_rwlock_init(&(dynamicSPI[spiCount]->rwlock), NULL); // 初始化读写锁
	pthread_mutex_init(&(dynamicSPI[spiCount]->mutex), NULL);	// 初始化互斥锁
	if (dynamicSPI[spiCount] != NULL)
	{
		dynamicSPI[spiCount]->spi = newSPI;
		// 初始化其他与SPI相关的参数
		dynamicSPI[spiCount]->key_sync_flag = false;							   // 密钥索引同步标志设置为false
		dynamicSPI[spiCount]->delkeyindex = 0, dynamicSPI[spiCount]->keyindex = 0; // 初始化密钥偏移
		dynamicSPI[spiCount]->ekeybuff = NULL;
		dynamicSPI[spiCount]->dkeybuff = NULL;
		dynamicSPI[spiCount]->olddkeybuff = NULL;
		dynamicSPI[spiCount]->ekey_rw = 0;
		dynamicSPI[spiCount]->dkey_lw = 0;
		dynamicSPI[spiCount]->dkey_rw = 0;
		// 如果是入站SPI，需要初始化解密参数
		if (newinbound)
		{
			dynamicSPI[spiCount]->encrypt_flag = 1;
			initializeQueue(&(dynamicSPI[spiCount]->myQueue)); // 初始化解密密钥派生参数队列
		}
		else
		{
			dynamicSPI[spiCount]->encrypt_flag = 0;
			dynamicSPI[spiCount]->cur_ekeyd = INIT_KEYD; // 初始化加密密钥派生参数
			dynamicSPI[spiCount]->eM = INIT_KEYM;
		}
		spiCount++; // 更新计数器
		printf("Memory allocation successed for new SPI.\n");
	}
	else
	{
		printf("Memory allocation failed for new SPI.\n");
	}
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
	char buf[BUFFER_SIZE];
	printf("local_encrypt_flag:%d remote_flag:%d\n", local_spi->encrypt_flag, atoi(remote_flag));
	sprintf(buf, "encflagsync %d\n", local_spi->encrypt_flag);
	send(fd, buf, strlen(buf), 0);
}

void SAkey_sync_handle(const char *remote_index, int fd)
{
	SAkeyindex = max(SAkeyindex, atoi(remote_index));
	SAkey_sync_flag = true;
	char buf[BUFFER_SIZE];
	sprintf(buf, "SAkeyindexsync %d\n", SAkeyindex);
	send(fd, buf, strlen(buf), 0);
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
	char buf[BUFFER_SIZE];
	sprintf(buf, "keyindexsync %d\n", keyindex + delkeyindex);
	send(fd, buf, strlen(buf), 0);
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
	enqueue(&local_spi->myQueue, tmp_keyd);
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
	enqueue(&local_spi->myQueue, tmp_dM);
	return;
}

/**
 * @description: 子线程的代码,监听本地socket端口
 * @return {*}
 */
void *reactor_local_socket()
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
					printf("local_connection request:!\n");
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

int main(int argc, char *argv[])
{
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
	SAkey_sync_flag = false;
	// 删除文件夹内的文件
	char command[256];
	snprintf(command, sizeof(command), "rm -rf %s", keypool_path);
	system(command);
	// 创建文件夹
	if (mkdir(keypool_path, 777) != 0)
	{
		perror("mkdir");
		exit(EXIT_FAILURE);
	}

	//先移除旧的密钥文件
	remove(KEY_FILE);

	pthread_rwlock_init(&keywr, NULL); // 初始化读写锁
	pthread_mutex_init(&mutex, NULL);  // 初始化互斥锁
	pthread_t writethread[3];
	pthread_create(&writethread[0], NULL, thread_writesharedkey, NULL); // DH密钥写入线程启动
	pthread_detach(writethread[0]);										// 线程分离
	pthread_create(&writethread[1], NULL, thread_writeSAkey, NULL);		// SA密钥写入线程启动
	pthread_detach(writethread[1]);										// 线程分离
	pthread_create(&writethread[2], NULL, thread_keyradetection, NULL); // 密钥速率探测线程启动
	pthread_detach(writethread[2]);										// 线程分离

	pthread_t thread1, thread2;
	// 启动监听服务器，开始监听密钥请求
	pthread_create(&thread1, NULL, reactor_local_socket, NULL);
	pthread_create(&thread2, NULL, reactor_external_socket, NULL);
	// 等待子线程结束
	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

	// 程序退出时释放资源
	pthread_rwlock_destroy(&keywr); // 销毁读写锁
	pthread_mutex_destroy(&mutex);	// 销毁互斥锁
	for (int i = 0; i < spiCount; ++i)
	{ // 释放内存
		free(dynamicSPI[i]->ekeybuff);
		free(dynamicSPI[i]->dkeybuff);
		free(dynamicSPI[i]->olddkeybuff);
		pthread_mutex_destroy(&(dynamicSPI[i]->mutex));
		pthread_rwlock_destroy(&(dynamicSPI[i]->rwlock));
		free(dynamicSPI[i]);
	}
	return 0;
}
