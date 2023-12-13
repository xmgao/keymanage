/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2023-03-30 15:42:44
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2023-12-13 18:12:37
 * @FilePath: \c\keymanage\km.c
 * @Description: 
 * 
 * Copyright (c) 2023 by ${git_name_email}, All Rights Reserved. 
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/types.h>

#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <error.h>
#include <dirent.h>
#include <math.h>
#include <pthread.h>

//  编译: gcc epollrun.c -o km -g -pthread
// 运行 ./km remoteip

#define MAX_EVENTS 10	 // 最大监听数量
#define BUFFER_SIZE 1024 // 数据包缓冲区最大长度
#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define LOCAL_PORT 50000				  // 默认服务器内部监听端口
#define socket_path "/tmp/my_socket"	//定义本地套接字路径
#define EXTERNAL_PORT 50001				  // 默认服务器外部监听端口
#define MAX_KEYFILE_SIZE 1024 * 1024 * 2 // 最大密钥文件大小，当密钥文件大于最大限制时，不再填充密钥 2M
#define MAX_KEYPOOL_SIZE (MAX_KEYFILE_SIZE/2) // 最大密钥池大小，用来判断密钥派生参数
#define KEY_CREATE_RATE 1024 * 16		  // 密钥每秒生成长度 128kbps
#define KEY_UNIT_SIZE 4					  // 密钥基本存储单位4字节
#define KEY_RATIO 1000					  // SA密钥与会话密钥的比值
#define KEY_FILE "keyfile.kf"			  // dh,psk密钥文件
#define TEMPKEY_FILE "tempkeyfile.kf"	  // 临时密钥文件
#define LOCAL_IPADDR "127.0.0.1"		  // 本地ip地址
#define INIT_KEYD 100					  // 初始密钥派生参数
#define up_index 2						  // 派生增长因子
#define down_index 500					  // 派生减少因子
#define LT 0.2							  // 下界
#define LT 0.8							  // 上界
#define WINSIZE 4096					  // 密钥窗口大小
#define MAX_DYNAMIC_SPI_COUNT 100		 //最多同时存在SPI个数
#define INIT_KEYM 16					//初始密钥块阈值16字节

//解密派生参数队列
#define MAX_QUEUE_SIZE 100

typedef struct {
    int data[MAX_QUEUE_SIZE];
    int front;
    int rear;
} Queue;

// 初始化队列
void initializeQueue(Queue *queue) {
    queue->front = -1;
    queue->rear = -1;
}

// 检查队列是否为空
int isEmpty(Queue *queue) {
    return (queue->front == -1 && queue->rear == -1);
}

// 检查队列是否已满
int isFull(Queue *queue) {
    return ((queue->rear + 1) % MAX_QUEUE_SIZE == queue->front);
}

// 入队
/**
 * @description: 
 * @param {Queue} *queue
 * @param {int} value
 * @return {*}
 */
void enqueue(Queue *queue, int value) {
    if (isFull(queue)) {
        printf("Queue is full. Cannot enqueue.\n");
        return;
    } else if (isEmpty(queue)) {
        queue->front = 0;
        queue->rear = 0;
    } else {
        queue->rear = (queue->rear + 1) % MAX_QUEUE_SIZE;
    }
    queue->data[queue->rear] = value;
}

// 出队
int dequeue(Queue *queue) {
    int value;
    if (isEmpty(queue)) {
        printf("Queue is empty. Cannot dequeue.\n");
        return -1; // 代表出队失败
    } else if (queue->front == queue->rear) {
        value = queue->data[queue->front];
        queue->front = -1;
        queue->rear = -1;
    } else {
        value = queue->data[queue->front];
        queue->front = (queue->front + 1) % MAX_QUEUE_SIZE;
    }
    return value;
}

// 用于OTP的密钥块结构体
typedef struct
{
	char key[1500];
	int size;
} Keyblock;

typedef struct SpiParams SpiParams;
// 结构体定义，存储与每个SPI相关的参数
struct SpiParams {
    int spi;											//SPI值，用数字表示
	bool in_bound;										//true如果是入站SPI
	char keyfile[100]; 									//spi对应的密钥池文件名
	bool key_sync_flag;								   // 密钥索引同步标志
	int delkeyindex, keyindex; 							// 密钥索引，用于删除过期密钥，标识当前的密钥
	int encrypt_flag;					   // 加密密钥以及解密密钥的对应关系，0标识加密，1标识解密
	int cur_ekeyd, next_ekeyd, cur_dkeyd, next_dkeyd;  // 记录当前的密钥派生参数和下一个密钥派生参数
	char raw_ekey[64],raw_dkey[64],old_dkey[64];	 // 记录原始量子密钥
	Queue myQueue; //解密参数队列
	int eM,dM;	//加密密钥阈值，解密密钥阈值
	Keyblock *ekeybuff, *dkeybuff, *olddkeybuff;
	int  ekey_rw,dkey_lw,dkey_rw;  //加密右窗口，解密左窗口，解密右窗口
};

SpiParams *dynamicSPI[MAX_DYNAMIC_SPI_COUNT];

int SAkeyindex;  //用于标识本地SA密钥池索引。
int spiCount = 0; //当前SPI个数
pthread_rwlock_t keywr;
int SERV_PORT;									   // 服务器监听端口
char remote_ip[32];								   // 记录远程ip地址


//本地监听初始化，使用AF_UNIX
int init_listen_local(int epfd) {
    int unix_sock, ret;
    struct epoll_event tep;

    struct sockaddr_un serv_addr;

    // 创建 UNIX 域套接字
    unix_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_sock < 0) {
        perror("socket create error!\n");
        exit(1);
    }
    // 设置套接字地址信息
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, socket_path, sizeof(serv_addr.sun_path) - 1);

    // 绑定 UNIX 域套接字
    ret = bind(unix_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (ret < 0) {
        perror("bind error!\n");
        exit(1);
    }

    listen(unix_sock, 128);

    tep.events = EPOLLIN;
    tep.data.fd = unix_sock;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, unix_sock, &tep);
    if (ret == -1) {
        perror("epoll_ctl_add error!\n");
        exit(1);
    }

    return unix_sock;
}

//TODO
//外部监听初始化，使用tcp
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

// 发起tcp连接
bool con_tcpserv(int *fd, const char *src, int port)
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
	serv_addr.sin_port = htons(SERV_PORT);
	inet_pton(AF_INET, src, &serv_addr.sin_addr.s_addr);

	cr = connect(*fd, (struct sockaddr *)(&serv_addr), sizeof(serv_addr)); // 连接对方服务器
	if (cr < 0)
	{
		perror("connect error!\n");
		return false;
	}
	return true;
}

//创建 UNIX 域套接字连接
bool con_unixserv(int *fd) {
    int ret, cr;
    *fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (*fd < 0) {
        perror("socket error!\n");
        return false;
    }

    struct sockaddr_un serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, socket_path, sizeof(serv_addr.sun_path) - 1);

    cr = connect(*fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)); // 连接对方服务器
    if (cr < 0) {
        perror("connect error!\n");
        return false;
    }
    return true;
}



// 处理连接请求
void do_tcpcrecon(int fd, int epfd)
{
	struct sockaddr_in cli_addr;
	char cli_ip[16];
	int client_addr_size, ret;
	struct epoll_event tep;
	int ar = accept(fd, (struct sockaddr *)(&cli_addr), &client_addr_size);
	printf("ip address is: %s,port is: %d\n", inet_ntop(AF_INET, &cli_addr.sin_addr.s_addr, cli_ip, sizeof(cli_ip)), ntohs(cli_addr.sin_port));
	// 设置ar socket非阻塞
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

//处理 UNIX 域套接字连接请求
void do_unixcrecon(int fd, int epfd) {
    struct sockaddr_un cli_addr;
    int client_addr_size, ret;
    struct epoll_event tep;
    int ar = accept(fd, (struct sockaddr *)&cli_addr, &client_addr_size);
    printf("Unix domain socket path is: %s\n", cli_addr.sun_path);

    // 设置 ar socket 非阻塞
    int flag = fcntl(ar, F_GETFL);
    flag |= O_NONBLOCK;
    fcntl(ar, F_SETFL, flag);

    // 事件赋值
    tep.events = EPOLLIN;
    tep.data.fd = ar;

    // 事件上树
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, ar, &tep);
    if (ret == -1) {
        perror("epoll_ctl_add error!\n");
        exit(1);
    }
}


// 关闭tcp或unix连接
void discon(int fd, int epfd)
{
	int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
	if (ret < 0)
	{
		perror("EPOLL_CTL_DEL error...\n");
		// exit(1);
	}
	close(fd);
}
void do_recdata_unix(int fd, int epfd) {
    char buffer[BUFFER_SIZE];
    ssize_t bytesRead = read(fd, buffer, BUFFER_SIZE);
    if (bytesRead == -1) {
        perror("Failed to read data from socket");
        exit(EXIT_FAILURE);
    } else if (bytesRead == 0) {
        // 连接关闭，进行相应处理
        discon(fd, epfd);
    } else {
        // 在这里处理从 UNIX 域套接字中读取的数据
        // 可以根据需求对读取到的数据进行处理
        printf("Received data from socket: %s\n", buffer);
		// 处理读取到的数据
		if (buffer[bytesRead - 1] == '\n')
			buffer[bytesRead - 1] = '\0';
		printf("recieve:%s\n", buffer);
		// 对应于getk   arg1==spi, arg2=keylen(字节)
		// 对应于getsk  arg1==spi, arg2=keylen(字节), arg3=syn,arg4=keytype
		// 对应于getotpk arg1==spi, arg2=syn,arg3=keytype
		// 对应于spiregister arg1==spi, arg2=inbound
		uint8_t method[32] = {}, arg1[64] = {}, arg2[64] = {}, arg3[64] = {}, arg4[64] = {};
		int key_type;
		sscanf(buffer, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", method, arg1, arg2, arg3, arg4);
		if (strncasecmp(method, "spiregister", 11) == 0)
		{
			spiregister_handle(arg1, arg2, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "getk", 4) == 0)
		{
			getk_handle(arg1, arg2, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "getotpk", 7) == 0)
		{
			getsk_handle_otp(arg1, arg2, arg3, fd);
		}
		else if (strncasecmp(method, "getsk", 5) == 0)
		{
			getsk_handle(arg1, arg2, arg3, arg4, fd);
		}
		else
		{
			printf("invalid recdata\n");
			discon(fd, epfd);
		}
	}
}

void do_recdata_external(int fd, int epfd)
{


	char buffer[BUFFER_SIZE];
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
		printf("recieve:%s\n", buffer);
		// 对应于keyindexsync  arg1=keyindex, arg2=delkeyindex
		// 对应于encflagsync arg1==encrypt_flag
		// 对应于derive_sync  arg1==key_d
		// 对应于eM_sync  arg1==tem_eM arg2==nextseq
		uint8_t method[32] = {}, arg1[64] = {}, arg2[64] = {}, arg3[64] = {}, arg4[64] = {};
		int key_type;
		sscanf(buffer, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", method, arg1, arg2, arg3, arg4);
		if (strncasecmp(method, "keyindexsync", 7) == 0)
		{
			keysync_handle(arg1, arg2, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "encflagsync", 6) == 0)
		{
			kisync_handle(arg1, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "desync", 6) == 0)
		{
			desync_handle(arg1, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "eMsync", 6) == 0)
		{
			eMsync_handle(arg1, arg2, fd);
		}
		else
		{
			printf("invalid recdata:%s\n", buffer);
			discon(fd, epfd);
		}
	}
}

// 加解密密钥对应关系同步
/**
 * @description: 加解密对应关系同步函数
 * @param {SpiParams *} local_spi 传入参数为本地spi参数的指针
 * @return {*} TRUE if加密对应解密
 */

bool encflag_sync(SpiParams * local_spi)
{	int spi=local_spi->spi;
	int local_flag=local_spi->encrypt_flag;
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
	int fd, ret, remote_flag;

	con_tcpserv(&fd, remote_ip, SERV_PORT); // 连接对方服务器
	printf("spi:%d\tencrypt_flag:%d\n",spi,local_flag);
	sprintf(buf, "encflagsync %d %d\n",spi,local_flag);
	send(fd, buf, strlen(buf), 0);

	ret = read(fd, rbuf, sizeof(rbuf));
	sscanf(rbuf, "%[^ ] %d", method, &remote_flag); // scanf("%[^\n] ", s); 输入一行，回车作为结束符。 行末回车符不处理; %[^ ]表示除了空格都可以读
	close(fd);
	if (local_flag ^ remote_flag == 1)
		return true;
	return false;
}


/**
 * @description: 密钥同步,本地与远端服务器建立连接同步密钥偏移
 * @param {SpiParams *} local_spi 本地spi参数的指针
 * @return {*} TRUE if密钥偏移同步成功
 */
bool key_index_sync(SpiParams * local_spi)
{	int spi=local_spi->spi;
	int local_keyindex=local_spi->keyindex;
	int local_delkeyindex=local_spi->delkeyindex;
	
	int fd, ret;
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];

	con_tcpserv(&fd, remote_ip, SERV_PORT); // 连接对方服务器
	sprintf(buf, "keyindexsync %d %d\n", spi,local_keyindex+local_delkeyindex);
	ret = send(fd, buf, strlen(buf), 0);
	if (ret < 0)
	{
		perror("keyindex_sync connect error!\n");
		return false;
	}
	ret = read(fd, rbuf, sizeof(rbuf));
	int global_keyindex;
	sscanf(rbuf, "%[^ ] %d", method, &global_keyindex,); // 修改
	close(fd);
	local_spi->keyindex=max(local_keyindex+local_delkeyindex,global_keyindex)-local_delkeyindex;
	local_spi->key_sync_flag = true;
	return true;
}


/**
 * @description: // 密钥派生参数协商
 * @param {SpiParams *} local_spi 本地spi参数的指针
 * @return {*} TRUE if密钥派生参数协商成功
 */
/*版本1，类似论文的方案，除了阈值之外还按速率变化
bool derive_sync(SpiParams * local_spi)
{	
	int fd, ret, tmp_keyd;
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
	// 通过密钥余量判断接下来的密钥派生参数
	cur_ekeyd = next_ekeyd;
	FILE *fp;
	fp = fopen(KEY_FILE, "r");
	fseek(fp, 0, SEEK_END);	  // 定位到文件末
	int nFileLen = ftell(fp); // 文件长度
	fclose(fp);
	// 判断文件大小，若文件大于设定的值则不再写入
	int poolsize = (nFileLen - KEY_UNIT_SIZE * sekeyindex) / 2;
	static struct timeval pre_t, cur_t;
	pre_t=cur_t;
	gettimeofday(&cur_t, NULL);
	if (poolsize < LT * MAX_KEYPOOL_SIZE )
	{
		tmp_keyd = (next_ekeyd * up_index) < 10000 ? next_ekeyd * up_index : 10000;	
	}
	else {
		if (pre_t.tv_sec == 0)
	{
		tmp_keyd=next_ekeyd;
	}
	else{
		double duration = (cur_t.tv_sec - pre_t.tv_sec) + (cur_t.tv_usec - pre_t.tv_usec) / 1000000.0;
		int vconsume=48/duration; //密钥消耗速率，单位 字节/s
		if(vconsume>=KEY_CREATE_RATE/2){
			tmp_keyd = (next_ekeyd * up_index) < 10000 ? next_ekeyd * up_index : 10000;			//乘性增加
		}
		else{
			tmp_keyd = (next_ekeyd - down_index) > 100 ? next_ekeyd - down_index : 100;				//綫性減少
		}
	}
	}

	sprintf(buf, "desync %d\n", tmp_keyd);

	con_tcpserv(&fd, remote_ip, SERV_PORT); // 连接对方服务器
	ret = send(fd, buf, strlen(buf), 0);
	if (ret < 0)
	{
		perror("derive_sync connect error!\n");
		return false;
	}
	ret = read(fd, rbuf, sizeof(rbuf));
	int r_keyd;
	sscanf(rbuf, "%[^ ] %d", method, &r_keyd);
	close(fd);
	if (tmp_keyd == r_keyd)
	{
		next_ekeyd = tmp_keyd;
		return true;
	}

	return false;
}
*/


/**
 * @description: // 密钥派生参数协商 版本2，只按照密钥池阈值变化
 * @param {SpiParams *} local_spi 本地spi参数的指针
 * @return {*} TRUE if密钥派生参数协商成功
 */
bool derive_sync(SpiParams * local_spi)
{	int spi=local_spi->spi;
	int fd, ret, tmp_keyd;
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
	int next_ekeyd=local_spi->next_ekeyd;
	local_spi->cur_ekeyd = next_ekeyd;
	// 通过密钥余量判断接下来的密钥派生参数
	FILE *fp;
	fp = fopen(KEY_FILE, "r");
	fseek(fp, 0, SEEK_END);	  // 定位到文件末
	int nFileLen = ftell(fp); // 文件长度
	fclose(fp);
	// 判断文件大小，若文件大于设定的值则不再写入
	int poolsize = (nFileLen - KEY_UNIT_SIZE * local_spi->keyindex);
	if (poolsize < LT * MAX_KEYPOOL_SIZE )
	{
		tmp_keyd = (next_ekeyd * up_index) < 10000 ? next_ekeyd * up_index : 10000;		//乘性增加，增大每个密钥保护数据包范围
	}
	else if(poolsize > LT * MAX_KEYPOOL_SIZE){
		tmp_keyd = (next_ekeyd - down_index) > 100 ? next_ekeyd - down_index : 100;		//线性减小，减少每个密钥保护数据包范围
	}
	else {
		tmp_keyd=next_ekeyd;
	}

	sprintf(buf, "desync %d %d\n", spi,tmp_keyd);
	con_tcpserv(&fd, remote_ip, SERV_PORT); // 连接对方服务器
	ret = send(fd, buf, strlen(buf), 0);
	if (ret < 0)
	{
		perror("derive_sync connect error!\n");
		return false;
	}
	ret = read(fd, rbuf, sizeof(rbuf));
	int r_keyd;
	sscanf(rbuf, "%[^ ] %d", method, &r_keyd);
	close(fd);
	if (tmp_keyd == r_keyd)
	{
		local_spi->next_ekeyd = tmp_keyd;
		return true;
	}
	return false;
}

//TODO
//这里需要对每个spi区分密钥池
/**
 * @description:  更新密钥池，更新删除密钥索引
 * @param {SpiParams *} local_spi 本地spi参数的指针
 * @return {*}
 */
void renewkey(SpiParams * local_spi)
{
	int delindex=local_spi->keyindex;				   // 要删除的密钥的索引
	if (delindex == 0)
	{
		return;
	}
	FILE *fp = fopen(local_spi->keyfile, "r");
	FILE *fp2 = fopen(TEMPKEY_FILE, "w");
	if (fp == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	else
	{
		fseek(fp, delindex * KEY_UNIT_SIZE, SEEK_SET); // 文件指针偏移到指定位置
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
		printf("key pool renewed...\ndelkeyindex:%d  keyindex:%d  \n", local_spi->delkeyindex , local_spi->keyindex);
	}
	else
	{
		perror("rename error!");
	}
}

//TODO
//需要对每个SPI单独隔离密钥池
/*
void *thread_write()
{
	// 首先定义文件指针：fp
	FILE *fp;
	remove(KEY_FILE);
	printf("key supply starting...\n");
	// 模拟不断写入密钥到密钥池文件
	int count = 0; // 计数器，用来触发密钥池更新
	srand(111);
	while (1)
	{
		unsigned char *buf = (unsigned char *)malloc(KEY_CREATE_RATE * sizeof(unsigned char));
		int i = 0;
		for (; i < KEY_CREATE_RATE; i++)
		{ // 随机形成密钥串
			buf[i] = rand() % 256;
		}
		pthread_rwlock_wrlock(&keywr); // 上锁
		fp = fopen(KEY_FILE, "a+");
		fseek(fp, 0, SEEK_END);	  // 定位到文件末
		int nFileLen = ftell(fp); // 文件长度
		fseek(fp, 0, SEEK_SET);	  // 恢复到文件头
		// 判断文件大小，若文件大于设定的值则不再写入
		float poolsize = (float)(nFileLen - KEY_UNIT_SIZE * (sekeyindex + sdkeyindex) / 2) / (1024 * 1024);
		printf("keypoolsize:%.2f MByetes\n", poolsize);
		if (nFileLen < MAX_KEYFILE_SIZE)
		{
			fwrite(buf, sizeof(unsigned char), KEY_CREATE_RATE, fp);
		}
		free(buf);
		fclose(fp);
		// if (nFileLen >= MAX_KEYFILE_SIZE && count >= 30)
		// { // 密钥池满且更新时间超过30s
		// 	renewkey();
		// 	count = 0;
		// }
		pthread_rwlock_unlock(&keywr); // 解锁
		count++;
		sleep(1); // 等待1s
	}

	pthread_exit(0);
}
*/

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
	FILE *fp = fopen(KEY_FILE, "r");
	if (fp == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	int i = 0;
	while (i * KEY_UNIT_SIZE < len)
	{

		fseek(fp, SAkeyindex * KEY_UNIT_SIZE, SEEK_SET);
		fgets(pb, KEY_UNIT_SIZE + 1, fp);
		i++;
		pb += KEY_UNIT_SIZE;
		SAkeyindex++;
	}
	rewind(fp);
	pthread_rwlock_unlock(&keywr); // 解锁
}


/**
 * @description: // 读取本地SA会话密钥
 * @param {SpiParams *} local_spi 本地spi参数的指针
 * @param {char} *buf 保存密钥的缓存数组
 * @param {int} len 需要密钥的长度
 * @return {*}
 */
void readSAkey(SpiParams * local_spi,char *const buf, int len)
{
	char *pb = buf;
	//pthread_rwlock_rdlock(&keywr); // 上读锁
	FILE *fp = fopen(local_spi->keyfile, "r");
	if (fp == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	int keyindex=local_spi->keyindex;
	int i = 0;
	while (i * KEY_UNIT_SIZE < len)
	{
		fseek(fp, keyindex * KEY_UNIT_SIZE, SEEK_SET);
		while (fgets(pb, KEY_UNIT_SIZE + 1, fp) == NULL)
		{
			printf("key supply empty!\n");
			// pthread_rwlock_unlock(&keywr); // 解锁
			// sleep(2);//等待密钥生成
			// pthread_rwlock_rdlock(&keywr); // 上读锁
			printf("key supply try again!\n");
			fseek(fp, keyindex * KEY_UNIT_SIZE, SEEK_SET); // 将文件指针偏移到指定位置
		}
		i++;
		pb += KEY_UNIT_SIZE;
		keyindex++;
	}
	local_spi->keyindex=keyindex;
	fclose(fp);
	//pthread_rwlock_unlock(&keywr); // 解锁
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
	// 读取密钥
	readsharedkey(buf, len);
	send(fd, buf, len, 0);
}

// 会话密钥请求处理
//修改后，密钥窗口还是放在kms里
void getsk_handle(const char *spi, const char *keylen, const char *syn, const char *key_type, int fd)
{	
	int i=0;
	while(dynamicSPI[i]->spi!=atoi(spi)){
		i++;
	}
	SpiParams * local_spi=dynamicSPI[i];
	int seq=atoi(syn);
	// 判断syn是否为1，是则进行密钥偏移同步，否则不需要同步
	if (!local_spi->key_sync_flag)
	{
		bool ret = key_index_sync(local_spi);
		if (!ret)
		{
			perror("key_sync error!\n");
			return;
		}
	}
	int ekey_rw=local_spi->ekey_rw;
	int dkey_lw=local_spi->dkey_lw;
	int dkey_rw=local_spi->dkey_rw;
	char buf[BUFFER_SIZE];
	if (*key_type == '0'){	
		if (seq > ekey_rw) {  //如果还没有初始的密钥或者超出密钥服务范围需要进行派生参数同步
		bool ret = derive_sync(local_spi); // 派生参数同步
		if (!ret)
		{
			perror("derive_sync error!\n");
			return;
		}
		readSAkey(local_spi, local_spi->raw_ekey, atoi(keylen)); // 读取SA会话密钥
		local_spi->ekey_rw = ekey_rw + local_spi->cur_ekeyd;
		}
		sprintf(buf, "%s %d\n",local_spi->raw_ekey, local_spi->cur_ekeyd);
	}
	else //解密密钥:对于解密密钥维护一个旧密钥的窗口来暂存过去的密钥以应对失序包。
	{
		loop1:
		if (seq > dkey_rw) {  //如果还没有初始的密钥或者超出密钥服务范围需要更新原始密钥以及syn窗口,
			memcpy(local_spi->old_dkey,local_spi->raw_dkey,atoi(keylen));
			readSAkey(local_spi, local_spi->raw_dkey, atoi(keylen)); // 读取密钥
			//更新窗口
			dkey_lw = dkey_rw+1;
			int dkeyd=dequeue(&local_spi->myQueue); //正确的解密派生参数由一个队列管理
			dkey_rw = dkey_rw + dkeyd;
			goto loop1;

		}
		if (seq < dkey_lw) {
			sprintf(buf, "%s %d\n", local_spi->old_dkey, local_spi->cur_dkeyd);
		}
		else  {
			sprintf(buf, "%s %d\n", local_spi->raw_dkey, local_spi->cur_dkeyd);
		}
		local_spi->dkey_lw=dkey_lw;
		local_spi->dkey_rw=dkey_rw;
	}
	send(fd, buf, strlen(buf), 0);
}

//TODO
int establish_connection()
{
	static int socket_fd = -1; // 静态变量用于保存套接字的文件描述符
	if (socket_fd == -1)
	{
		// 第一次调用，创建套接字
		socket_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (socket_fd == -1)
		{
			perror("Failed to create socket");
			// 处理套接字创建失败的情况
			return -1;
		}
		// 可以在这里进行套接字的初始化配置
		struct sockaddr_in serv_addr;
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(SERV_PORT);					   // 设置服务器端口号
		inet_pton(AF_INET, remote_ip, &serv_addr.sin_addr.s_addr); // 设置服务器IP地址
		int connect_result = connect(socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
		if (connect_result == -1)
		{
			perror("eM_sync connect error!\n");
			return -1;
		}
	}
	return socket_fd;
}

// 分组密钥阈值更新
bool updateM(int seq)
{
	static struct timeval pre_t, cur_t;
	if (pre_t.tv_sec == 0)
	{
		gettimeofday(&pre_t, NULL);
		gettimeofday(&cur_t, NULL);
		return true;
	}
	int fd, ret, tmp_eM;
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
	pre_t = cur_t;
	gettimeofday(&cur_t, NULL);
	double duration = (cur_t.tv_sec - pre_t.tv_sec) + (cur_t.tv_usec - pre_t.tv_usec) / 1000000.0;
	int vconsume = WINSIZE * eM / duration; // 密钥消耗速率，单位 字节/s
	if (vconsume >= KEY_CREATE_RATE / 2)
	{
		tmp_eM = (eM / 2 > 16) ? eM / 2 : 16; // 乘性减少,下界16
	}
	else
	{
		tmp_eM = (eM + 16 < 128) ? eM + 16 : 128; // 加性增加，上界128字节
	}
	sprintf(buf, "eMsync %d %d\n", tmp_eM, seq);
	fd = establish_connection();
	if (fd == -1)
	{
		// 处理建立连接失败的情况
		perror("establish_connection error!\n");
		return false;
	}

	ret = send(fd, buf, strlen(buf), 0);
	printf("send:%d\tnextseq:%d\tfd:%d\n", tmp_eM, seq, fd);
	if (ret < 0)
	{
		// printf("eM_sync send error!\n");
		return false;
	}

	ret = read(fd, rbuf, sizeof(rbuf));
	if (ret < 0)
	{
			printf("eM_sync read error!\n");
			return false;
	}
	int r_eM;
	sscanf(rbuf, "%[^ ] %d", method, &r_eM);
	printf("read:%d\n", r_eM);

	if (tmp_eM == r_eM)
	{
		eM = tmp_eM;
		return true;
	}
	return false;
}

// otp密钥请求处理
void getsk_handle_otp(const char *spi, const char *syn, const char *key_type, int fd)
{
	int seq = atoi(syn);
	// 如果双方没有同步加解密密钥池对应关系则首先进行同步
	if (!(encrypt_flag ^ decrypt_flag))
	{
		bool ret = key_index_sync();
		if (!ret)
		{
			perror("key_index_sync error！\n");
			return;
		}
	}
	// 判断syn是否为1，是则进行同步，否则不需要同步,同时接收方的key_sync_flag会被设置为true，避免二次同步
	if (seq == 1 && !key_sync_flag)
	{
		bool ret = key_sync();
		if (!ret)
		{
			perror("key_sync error!\n");
			return;
		}
	}
	static int ekey_rw = 0, dkey_lw = 0, dkey_rw = 0, olddkey_lw;
	char buf[BUFFER_SIZE + 20];
	// 读取密钥
	if (*key_type == '0')
	{ // 加密密钥
		if (seq > ekey_rw)
		{ // 如果还没有初始的密钥或者超出密钥服务范围需要更新原始密钥以及syn窗口
			if (ekeybuff != NULL)
				free(ekeybuff);
			ekeybuff = (Keyblock *)malloc(WINSIZE * sizeof(Keyblock));
			bool ret = updateM(seq); // 密钥块阈值M同步
			for (int i = 0; i < WINSIZE; i++)
			{
				readkey(ekeybuff[i].key, *key_type, eM);
				ekeybuff[i].size = eM;
			}
			// 更新窗口
			ekey_rw = ekey_rw + WINSIZE;
		}
		printf("qkey:%s size:%d sei:%d sdi:%d\n", ekeybuff[(seq - 1) % WINSIZE].key, ekeybuff[(seq - 1) % WINSIZE].size, sekeyindex, sdkeyindex);
		sprintf(buf, "%s %d\n", ekeybuff[(seq - 1) % WINSIZE].key, ekeybuff[(seq - 1) % WINSIZE].size);
	}
	else
	{ // 解密密钥:对于解密密钥维护一个旧密钥的窗口来暂存过去的密钥以应对失序包。
	loop2:
		if (seq > dkey_rw)
		{ // 如果还没有初始的密钥或者超出密钥服务范围需要更新原始密钥以及syn窗口,协商新的密钥派生参数
			if (olddkeybuff != NULL)
				free(olddkeybuff);
			olddkeybuff = dkeybuff;
			dkeybuff = (Keyblock *)malloc(WINSIZE * sizeof(Keyblock));
			dM = dequeue(&myQueue);
			for (int i = 0; i < WINSIZE; i++)
			{
				readkey(dkeybuff[i].key, *key_type, dM);
				dkeybuff[i].size = dM;
			}

			// 更新窗口
			olddkey_lw = dkey_lw;
			dkey_lw = dkey_rw + 1;
			dkey_rw = dkey_rw + WINSIZE;
			goto loop2;
		}

		if (seq < dkey_lw)
		{
			printf("oldqkey:%s size:%d sei:%d sdi:%d\n", olddkeybuff[(seq - 1) % WINSIZE].key, olddkeybuff[(seq - 1) % WINSIZE].size, sekeyindex, sdkeyindex);
			sprintf(buf, "%s %d\n", olddkeybuff[(seq - 1) % WINSIZE].key, olddkeybuff[(seq - 1) % WINSIZE].size);
		}

		else
		{
			printf("qkey:%s size:%d sei:%d sdi:%d\n", dkeybuff[(seq - 1) % WINSIZE].key, dkeybuff[(seq - 1) % WINSIZE].size, sekeyindex, sdkeyindex);
			sprintf(buf, "%s %d\n", dkeybuff[(seq - 1) % WINSIZE].key, dkeybuff[(seq - 1) % WINSIZE].size);
		}
	}
	send(fd, buf, strlen(buf), 0);
}

void spiregister_handle(int spi,bool inbound){
	// 假设通过某种方式检测到新的SPI
    int newSPI = spi;
    // 动态分配内存，并存储新的SPI参数
    dynamicSPI[spiCount] = (SpiParams *)malloc(sizeof(SpiParams));

	char hexStr[20]; // 足够大的字符数组来存储转换后的字符串
	sprintf(hexStr, "%x", spi); // 将数字转换为十六进制字符串
	strcpy(dynamicSPI[spiCount]->keyfile, hexStr);							   // 用SPI初始化密钥池
    if (dynamicSPI[spiCount] != NULL) {
        dynamicSPI[spiCount]->spi = newSPI;
        // 初始化其他与SPI相关的参数

		 dynamicSPI[spiCount]->key_sync_flag = false;										   // 密钥索引同步标志设置为false
		 dynamicSPI[spiCount]->delkeyindex = 0,dynamicSPI[spiCount]->keyindex = 0; 	// 初始化密钥偏移
		//如果是入站SPI，需要初始化解密参数
		if(inbound){
			dynamicSPI[spiCount]->encrypt_flag=1;
			initializeQueue(&(dynamicSPI[spiCount]->myQueue));
			 dynamicSPI[spiCount]->cur_dkeyd = INIT_KEYD; // 初始化密钥派生参数
			 dynamicSPI[spiCount]->next_dkeyd = INIT_KEYD;
			 dynamicSPI[spiCount]->dM=INIT_KEYM;
		}
		else{
			dynamicSPI[spiCount]->encrypt_flag=0;
			 dynamicSPI[spiCount]->cur_ekeyd = INIT_KEYD;										   // 初始化密钥派生参数
			 dynamicSPI[spiCount]->next_ekeyd = INIT_KEYD;
			 dynamicSPI[spiCount]->eM=INIT_KEYM;
		}
        spiCount++; // 更新计数器
    } else {
        printf("Memory allocation failed for new SPI.\n");
    }


}

// 密钥索引同步请求处理
void keysync_handle(const char *tkeyindex, const char *tsekeyindex, const char *tsdkeyindex, int fd)
{

	char buf[BUFFER_SIZE];
	sprintf(buf, "keysync %d %d %d\n", keyindex + delkeyindex, sekeyindex + delkeyindex, sdkeyindex + delkeyindex);
	send(fd, buf, BUFFER_SIZE, 0);
	keyindex = max(atoi(tkeyindex), keyindex + delkeyindex) - delkeyindex; // 修改
	sekeyindex = max(atoi(tsdkeyindex), sekeyindex + delkeyindex) - delkeyindex;
	sdkeyindex = max(atoi(tsekeyindex), sdkeyindex + delkeyindex) - delkeyindex;
	key_sync_flag = true;
}

// 加解密对应关系处理
void kisync_handle(const char *encrypt_i, const char *decrypt_i, int fd)
{
	encrypt_flag = atoi(decrypt_i);
	decrypt_flag = atoi(encrypt_i);
	char buf[BUFFER_SIZE];
	sprintf(buf, "kisync %d %d\n", encrypt_flag, decrypt_flag);
	printf("encrypt_flag:%d decrypt_flag:%d\n", encrypt_flag, decrypt_flag);
	send(fd, buf, strlen(buf), 0);
}

// 密钥派生参数同步
void desync_handle(const char *key_d, int fd)
{
	int tmp_keyd = atoi(key_d);
	cur_dkeyd = next_dkeyd;
	next_dkeyd = tmp_keyd;
	enqueue(&myQueue, cur_dkeyd);
	char buf[BUFFER_SIZE];
	sprintf(buf, "desync %d\n", next_dkeyd);
	send(fd, buf, strlen(buf), 0);
}

// 密钥块阈值同步
void eMsync_handle(const char *tmp_eM, const char *nextseq, int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1 && errno == EBADF)
	{
		printf("fd is invalid\n");
		return;
	}

	printf("receive:%s\tnextseq:%s\n", tmp_eM, nextseq);
	int tmp_dM = atoi(tmp_eM);
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE];
	sprintf(buf, "dMsync %d\n", tmp_dM);
	enqueue(&myQueue, tmp_dM);
	send(fd, buf, strlen(buf), 0);
	return;
}

// 子线程的代码,监听本地端口
void *thread_function(void *arg)
{
	// 子线程的代码
	printf("This is the child thread.\n");
	int epfd, nfds, i;
	struct epoll_event events[MAX_EVENTS];
	int local_port = LOCAL_PORT; // 本地端口
	// 创建 epoll 实例
	epfd = epoll_create1(0);
	if (epfd == -1)
	{
		perror("epoll_create1 error!\n");
		exit(1);
	}
	// 本地监听
	int local_lfd = init_listen_local(local_port, epfd);

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
			// 处理本地连接
			if (events[i].events & EPOLLIN && fd == local_lfd)
			{
				// 处理本地连接逻辑
				printf("local_connection success!\n");
				do_unixcrecon(local_lfd, epfd);
			}
			else if (events[i].events & EPOLLIN)
			{
				do_recdata_unix(fd, epfd); // 密钥请求及注册事件
			}
			else
			{
				continue;
			}
		}
	}
	close(epfd);
	close(local_lfd);

	pthread_exit(NULL);
}

// 服务器运行，双线程
void epoll_run(int port)
{
	pthread_t tid;
	int ret;
	// 创建子线程
	ret = pthread_create(&tid, NULL, thread_function, NULL);
	if (ret != 0)
	{
		fprintf(stderr, "Failed to create thread.\n");
		return;
	}
	// 父线程代码
	printf("This is the parent thread.\n");
	int epfd1, nfds1, i;
	struct epoll_event events1[MAX_EVENTS];
	int external_port = port; // 外部端口
	// 创建 epoll 实例
	epfd1 = epoll_create1(0);
	if (epfd1 == -1)
	{
		perror("epoll_create1 error!\n");
		exit(1);
	}
	// 外部监听
	int external_lfd = init_listen_external(external_port, epfd1);
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

			// 处理外部连接
			if (events1[i].events & EPOLLIN && fd == external_lfd)
			{
				// 处理外部连接请求
				printf("\nexternal_connection success!\n"); // ...
				do_tcpcrecon(external_lfd, epfd1);
			}
			else if (events1[i].events & EPOLLIN)
			{
				do_recdata_external(fd, epfd1); // 密钥同步事件
			}
			else
			{
				continue;
			}
		}
	}
	close(epfd1);
	close(external_lfd);
	// 等待子线程结束
	pthread_join(tid, NULL);
}


int main(int argc, char *argv[])
{	


	pthread_rwlock_init(&keywr, NULL);							   // 初始化读写锁

	pthread_t tid[2];
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
	pthread_create(&tid[0], NULL, thread_write, NULL); // 密钥写入线程启动
	pthread_detach(tid[0]);							   // 线程分离
	epoll_run(SERV_PORT);							   // 启动监听服务器，开始监听密钥请求
	pthread_rwlock_destroy(&keywr);					   // 销毁读写锁
	for (int i = 0; i < spiCount; ++i) {
        free(dynamicSPI[i]);
    }
	return 0;
}
