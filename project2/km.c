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

//  ����: gcc km.c -o km -g -pthread
// ���� sudo ./km remoteip >testlog 2> errlog

#define MAX_EVENTS 10000 // ����������
#define BUFFER_SIZE 128	 // ��ͨ���ݰ���������󳤶�
#define buf_size 1548	 // OTP���ݰ���������󳤶ȣ�Ӧ��Ϊһ��MTU���������Ա�����Կ���ֽ���
#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define socket_path "/tmp/my_socket"	  // ���屾���׽���·��
#define EXTERNAL_PORT 50001				  // Ĭ�Ϸ������ⲿ�����˿�
#define MAX_KEYFILE_SIZE 20 * 1024 * 1024 // �����Կ�ļ���С������Կ�ļ������������ʱ�����������Կ 20M
#define keypool_path "keypool"			  // ���屾����Կ���ļ���
#define KEY_FILE "keyfile.kf"			  // dh,psk��Կ�ļ�
#define TEMPKEY_FILE "tempkeyfile.kf"	  // ��ʱ��Կ�ļ�
#define INIT_KEYD 100					  // ��ʼ��Կ��������
#define INIT_KEYM 16					  // ��ʼOTP��Կ����ֵ16�ֽ�
#define up_index 2						  // ������������
#define down_index 500					  // ������������
#define LT 0.2							  // �½�
#define HT 0.7							  // �Ͻ�
#define WINSIZE 4096					  // ��Կ���ڴ�С
#define MAX_DYNAMIC_SPI_COUNT 100		  // ���ͬʱ����SPI����

SpiParams *dynamicSPI[MAX_DYNAMIC_SPI_COUNT];
int key_creat_rate;		// ��Կ��������ȫ�ֱ���
int SAkeyindex;			// ���ڱ�ʶ����SA��Կ��������
bool SAkey_sync_flag;	// ��Կͬ����־�����ڹ�ӦsaЭ��
int spiCount = 0;		// ��ǰSPI����
pthread_rwlock_t keywr; // ������Կ�صĶ�д��
pthread_mutex_t mutex;	// ������Կ�صĶ�д��
int SERV_PORT;			// �����������˿�
char remote_ip[32];		// ��¼Զ��ip��ַ

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

// TODO����Ҫʵ��һ�ַ��ʿ��ƻ��ƣ��ܾ������IP��ַ
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
	// �ⲿ����
	inet_pton(AF_INET, "0.0.0.0", &serv_addr.sin_addr.s_addr);
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
 * @description: ���� UNIX ���׽�������
 * @param {int} *fd ����soket�ļ��������ĵ�ַ
 * @return {*} true if ���ӳɹ�
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

	cr = connect(*fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)); // ���ӶԷ��׽��ֵ�ַ
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
	char cli_ip[16];
	int client_addr_size, ret;
	struct epoll_event tep;
	int ar = accept(fd, (struct sockaddr *)(&cli_addr), &client_addr_size);
	// printf("ip address is: %s,port is: %d\n", inet_ntop(AF_INET, &cli_addr.sin_addr.s_addr, cli_ip, sizeof(cli_ip)), ntohs(cli_addr.sin_port));
	//  ����ar socket������
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
	else
	{
		// printf("Unix domain socket path is: %s\n", cli_addr.sun_path);
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
 * @description: �ر�tcp��unix����
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
		// printf("Received data from socket: %s\n", buffer);
		//  ��Ӧ��getk  arg1=keylen(�ֽ�)
		//  ��Ӧ��getsk  arg1==spi, arg2=keylen(�ֽ�), arg3=syn,arg4=keytype(0���ܣ�1����)
		//  ��Ӧ��getotpk arg1==spi, arg2=syn,arg3=keytype //����ǽ���spi����Ҫntohlת��
		//  ��Ӧ��spiregister arg1==spi, arg2=inbound
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
	// ��ջ�����
	memset(buffer, 0, BUFFER_SIZE);
	// tcpsockfd �������ݵ���
	ssize_t bytesRead = read(fd, buffer, BUFFER_SIZE);
	if (bytesRead == -1)
	{
		perror("Failed to read data from sockfd");
		exit(EXIT_FAILURE);
	}
	else if (bytesRead == 0)
	{
		// ���ӹرգ�������Ӧ����
		discon(fd, epfd);
	}
	else
	{
		// �����ȡ��������
		if (buffer[bytesRead - 1] == '\n')
			buffer[bytesRead - 1] = '\0';
		// printf("recieve:%s\n", buffer);
		//  ��Ӧ��keyindexsync  arg1=spi, arg2=global_keyindex
		//  ��Ӧ��SAkeysync  arg1=remotekeyindex
		//  ��Ӧ��encflagsync arg1==spi arg2=encrypt_flag
		//  ��Ӧ��derive_sync  arg1==spi arg2==key_d
		//  ��Ӧ��eM_sync  arg1==spi arg2==tem_eM
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
 * @description: �ӽ��ܶ�Ӧ��ϵͬ������
 * @param {SpiParams *} local_spi �������Ϊ����spi������ָ��
 * @return {*} TRUE if���ܶ�Ӧ����
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
	sscanf(rbuf, "%[^ ] %d", method, &remote_flag); // scanf("%[^\n] ", s); ����һ�У��س���Ϊ�������� ��ĩ�س���������; %[^ ]��ʾ���˿ո񶼿��Զ�
	close(fd);
	if (local_flag ^ remote_flag == 1)
		return true;
	return false;
}

// SA��Կͬ��,������Զ�˷��������Խ�������ͬ����Կƫ��
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
	sscanf(rbuf, "%[^ ] %d", method, &global_keyindex); // �޸�
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

	sprintf(buf, "desync %d %d\n", local_spi->spi, tmp_keyd);
	// ��δ���������
	if (fd == -1)
	{ // ���ӶԷ�������
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
 * @description: // ��Կ��������Э�� �汾2��ֻ������Կ����ֵ�仯
 * @param {SpiParams *} local_spi ����spi������ָ��
 * @return {*} TRUE if��Կ��������Э�̳ɹ�
 */
// bool derive_sync(SpiParams *local_spi)
// {
// 	int spi = local_spi->spi;
// 	static int fd = -1;
// 	int ret, tmp_keyd;
// 	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
// 	int next_ekeyd = local_spi->cur_ekeyd;
// 	// ͨ����Կ�����жϽ���������Կ��������
// 	FILE *fp;
// 	fp = fopen(KEY_FILE, "rb");
// 	fseek(fp, 0, SEEK_END);	  // ��λ���ļ�ĩ
// 	int nFileLen = ftell(fp); // �ļ�����
// 	fclose(fp);
// 	// �жϾ���Կ�ش�С
// 	int poolsize = (nFileLen - 1 * local_spi->keyindex);
// 	if (poolsize < LT * MAX_KEYFILE_SIZE)
// 	{
// 		tmp_keyd = (next_ekeyd * up_index) < 10000 ? next_ekeyd * up_index : 10000; // �������ӣ�����ÿ����Կ�������ݰ���Χ
// 	}
// 	else if (poolsize > HT * MAX_KEYFILE_SIZE)
// 	{
// 		tmp_keyd = (next_ekeyd - down_index) > 100 ? next_ekeyd - down_index : 100; // ���Լ�С������ÿ����Կ�������ݰ���Χ
// 	}
// 	else
// 	{
// 		tmp_keyd = next_ekeyd;
// 	}

// 	sprintf(buf, "desync %d %d\n", spi, tmp_keyd);
// 	// ��δ���������
// 	if (fd == -1)
// 	{ // ���ӶԷ�������
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
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
	sprintf(buf, "eMsync %d %d\n", spi, tmp_eM);
	// ��δ���������
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
 * @description:  ������Կ�أ�����ɾ����Կ����
 * @param {SpiParams *} local_spi ����spi������ָ��
 * @return {*}
 */
void renewkey(SpiParams *local_spi)
{
	int delindex = local_spi->keyindex; // Ҫɾ������Կ������
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
		fseek(fp, delindex * 1, SEEK_SET); // �ļ�ָ��ƫ�Ƶ�ָ��λ��
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

// �ȽϺ�����������
int compare(const void *a, const void *b)
{
	const char *strA = *(const char **)a;
	const char *strB = *(const char **)b;
	return strcmp(strA, strB);
	// ���ļ���ת��Ϊ���ֲ����бȽ�
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
	// ���100����Կ�ļ���100k
	const int maxFiles = 100;		   //
	const int maxFileNameLength = 256; // ����ļ�������
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

	// numFiles==1;�������һ����Կ�ļ����п�������д��
	if (numFiles <= 1)
	{
		usleep(100000);
		free(fileNames[0]);
		free(fileNames);
		return;
	}

	// ����Կ�ļ������ļ���(������ʱ��˳��)����
	qsort(fileNames, numFiles, sizeof(const char *), compare);

	// д����Կ���ļ�fp��
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
			// ��ȡ��ɾ����Կ
			// remove(kfilePath);
		}
		free(fileNames[i]);
	}

	free(fileNames);
}

// Ϊÿ��spi����Կ��д����Կ
/**
 * @description:
 * @param {void} *args
 * @return {*}
 */
void *thread_writeSAkey(void *args)
{

	printf("spikey supply starting...\n");
	// ģ�ⲻ��д����Կ����Կ���ļ�
	while (1)
	{
		usleep(500000); // �ȴ�0.5s
		for (int i = 0; i < spiCount; i++)
		{
			FILE *fp = fopen(dynamicSPI[i]->keyfile, "ab");
			int nFileLen = ftell(fp); // �ļ�����
			if (nFileLen < 10 * MAX_KEYFILE_SIZE)
			{
				const char *folderPath = "my_folder";		   // �ļ���·��
				pthread_rwlock_wrlock(&dynamicSPI[i]->rwlock); // ��д��
				readFilesInFolder(folderPath, fp);
				pthread_rwlock_unlock(&dynamicSPI[i]->rwlock); // ����
			}
			fclose(fp);
		}
	}
}

/**
 * @description: 	// ģ�ⲻ��д����Կ����Կ���ļ�
 * @param {void} *args �ղ���
 * @return {*}
 */
// void *thread_writesharedkey(void *args)
// {
// 	// ���ȶ����ļ�ָ�룺fp
// 	FILE *fp;
// 	remove(KEY_FILE);
// 	printf("sharedkey supply starting...\n");
// 	// ģ�ⲻ��д����Կ����Կ���ļ�
// 	srand(666);
// 	while (1)
// 	{
// 		// �����sharedkey��Կ,д��DH��Կ��Ԥ������Կ��Ϊ���ǵ����ṩһ����Կ��
// 		unsigned char *buf = (unsigned char *)malloc(key_creat_rate * sizeof(unsigned char));
// 		for (int i = 0; i < key_creat_rate; i++)
// 		{ // ����γ���Կ��
// 			buf[i] = rand() % 256;
// 		}
// 		pthread_rwlock_wrlock(&keywr); // ����
// 		fp = fopen(KEY_FILE, "ab");
// 		fseek(fp, 0, SEEK_END);	  // ��λ���ļ�ĩ
// 		int nFileLen = ftell(fp); // �ļ�����
// 		// printf("keypoolsize:%d Byetes\n", nFileLen);
// 		if (nFileLen < MAX_KEYFILE_SIZE)
// 		{
// 			fwrite(buf, sizeof(unsigned char), key_creat_rate, fp);
// 		}
// 		free(buf);
// 		fclose(fp);
// 		pthread_rwlock_unlock(&keywr); // ����
// 		usleep(500000);				   // �ȴ�0.5s
// 	}
// 	pthread_exit(0);
// }

// ��Կ����̽��
void *thread_keyradetection(void *args)
{
	key_creat_rate = 100000; // ��ʼ������100kbps
	// ���ȶ����ļ�ָ�룺fp
	FILE *fp;
	int prefilelen = 0;
	int nextfilelen = 0;
	int detetctime = 500000; // ̽��ʱ�䣬��λus
	while (1)
	{
		fp = fopen(KEY_FILE, "rb");
		fseek(fp, 0, SEEK_END);	 // ��λ���ļ�ĩ
		nextfilelen = ftell(fp); // �ļ�����
		fclose(fp);
		if (prefilelen == 0)
		{
			prefilelen = nextfilelen;
		}
		else
		{	
			// ��ʱ̽����Կ����
			key_creat_rate = (int)((nextfilelen - prefilelen) * 1000 / detetctime); // kbps
			//printf("key_creat_rate: %d kbps\n", key_creat_rate);
			prefilelen = nextfilelen;
		}
		usleep(detetctime); // �ȴ�0.5s
	}
	pthread_exit(0);
}

// ��Կ�ط���
void *thread_writesharedkey(void *args)
{
	// ���ȶ����ļ�ָ�룺fp
	FILE *fp = fopen(KEY_FILE, "ab+");
	fseek(fp, 0, SEEK_END); // ��λ���ļ�ĩ
	printf("sharedkey supply starting...\n");
	FILE *file = fopen("rawkeyfile.kf", "rb"); // ��ʽ������Կ�ط��ļ�
	if (file == NULL)
	{
		perror("Error opening file");
		pthread_exit(0);
	}
	unsigned char block[522]; // 8�ֽ�ʱ���+2�ֽ���Կ����(512�ֽ�)+512�ֽ���Կ
	time_t prevTimestamp = 0;
	while (fread(block, sizeof(char), sizeof(block), file) == sizeof(block))
	{
		// ��ȡʱ���
		time_t currentTimestamp;
		memcpy(&currentTimestamp, block, sizeof(uint64_t));
		if (prevTimestamp != 0)
		{
			// ��λ����
			time_t interval = currentTimestamp - prevTimestamp;
			// ִ�в�������ָͣ�����
			// printf("Performing operation with interval: %.2f mseconds\n", (float)interval/ 1000000);
			unsigned char key[512];
			memcpy(key, block + sizeof(uint64_t) + 2, 512);
			pthread_rwlock_wrlock(&keywr); // ����
			fseek(fp, 0, SEEK_END);		   // ��λ���ļ�ĩ
			int nFileLen = ftell(fp);	   // �ļ�����
			if (nFileLen < MAX_KEYFILE_SIZE)
			{
				fwrite(key, sizeof(unsigned char), 512, fp);
			}
			pthread_rwlock_unlock(&keywr); // ����
			// ����ָ�������ͣ����ִ��,΢��
			usleep((int)(interval / 1000));
		}
		prevTimestamp = currentTimestamp;
	}
	fclose(file);
	fclose(fp);
	pthread_exit(0);
}

/**
 * @description: ��ȡDH��Կ��Ԥ������Կ��Ϊ���ǵ����ṩһ����Կ��
 * @param {char} *buf	������Կ�Ļ�������
 * @param {int} len		��Ҫ��Կ�ĳ���
 * @return {*}
 */
void readsharedkey(char *const buf, int len)
{
	char *pb = buf;
	pthread_rwlock_rdlock(&keywr); // �϶���
	FILE *fp = fopen(KEY_FILE, "rb");
	if (fp == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	while (1)
	{
		fseek(fp, SAkeyindex, SEEK_SET); // ���ļ�ָ��ƫ�Ƶ�ָ��λ��
		int bytes_read = fread(pb, sizeof(char), len, fp);
		// �� buffer ���� bytes_read ���ֽڵ����ݣ����п��ܰ������ַ�
		if (bytes_read == len)
		{
			break;
		}
		else
		{
			printf("key supply empty!\n");
			pthread_rwlock_unlock(&keywr); // ����
			sleep(1);
			pthread_rwlock_rdlock(&keywr); // �϶���
			printf("key require try again!\n");
		}
	}
	SAkeyindex += len;
	fclose(fp);
	pthread_rwlock_unlock(&keywr); // ����
}

/**
 * @description:  ��ȡ����SA�Ự��Կ
 * @param {SpiParams *} local_spi ����spi������ָ��
 * @param {char} *buf ������Կ�Ļ�������
 * @param {int} len ��Ҫ��Կ�ĳ���
 * @return {*}
 */
void readSAkey(SpiParams *local_spi, char *const buf, int len)
{
	char *pb = buf;
	pthread_rwlock_rdlock(&(local_spi->rwlock)); // �϶���
	FILE *fp = fopen(local_spi->keyfile, "rb");
	if (fp == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	int keyindex = local_spi->keyindex;
	while (1)
	{
		fseek(fp, keyindex, SEEK_SET); // ���ļ�ָ��ƫ�Ƶ�ָ��λ��
		int bytes_read = fread(pb, sizeof(char), len, fp);
		if (bytes_read == len)
		{
			// �� buffer ���� bytes_read ���ֽڵ����ݣ����п��ܰ������ַ�
			break;
		}
		else
		{
			printf("key supply empty!\n");
			pthread_rwlock_unlock(&local_spi->rwlock); // ����
			sleep(1);
			pthread_rwlock_rdlock(&local_spi->rwlock); // �϶���
			printf("key require try again!\n");
		}
	}
	keyindex += len;
	local_spi->keyindex = keyindex;
	fclose(fp);
	pthread_rwlock_unlock(&local_spi->rwlock); // ����
}

/**
 * @description: DH�Լ�Ԥ������Կ������
 * @param {char} *keylen ��Ҫ����Կ�����ַ�������
 * @param {int} fd	socket�ļ�������
 * @return {*}
 */
void getsharedkey_handle(const char *keylen, int fd)
{
	int len = atoi(keylen);
	char buf[len + 1];
	// �ж��Ƿ��Ѿ�ͬ�������û��ͬ�������Ƚ���˫��ͬ��
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
	// ��ȡ��Կ
	readsharedkey(buf, len);
	// printf("qkey:%s size:%d sei:%d\n", buf, len, SAkeyindex);
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
	// �ж�syn�Ƿ�Ϊ1�����Ǽ��ܷ�,������мӽ��ܹ�ϵͬ����������Ҫͬ��
	if (seq == 1 && atoi(key_type) == 0)
	{
		if (!encflag_sync(local_spi))
		{
			perror("encflag_sync error!\n");
			return;
		}
	}
	// �ж���Կ�����Ƿ�ͬ�������������Կ����ͬ��
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
		bool ret = derive_sync(local_spi); // ��������ͬ��
		if (!ret)
		{
			perror("derive_sync error!\n");
			return;
		}
		readSAkey(local_spi, local_spi->raw_ekey, len); // ��ȡSA�Ự��Կ

		memcpy(buf, &local_spi->cur_ekeyd, sizeof(int));
		memcpy(buf + sizeof(int), local_spi->raw_ekey, len);
	}
	else
	{
	loop1:
		if (isEmpty(&local_spi->myQueue))
		{ // ���ж϶����Ƿ�Ϊ�գ�����ǿգ�˵��������δ������У�����һ��ʱ��ĵȴ�
			usleep(1000);
			goto loop1;
		}
		readSAkey(local_spi, local_spi->raw_dkey, len); // ��ȡ��Կ
		int dkeyd = dequeue(&local_spi->myQueue);		// ��ȷ�Ľ�������������һ�����й���
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
// 	// �ж�syn�Ƿ�Ϊ1�����Ǽ��ܷ�,������мӽ��ܹ�ϵͬ����������Ҫͬ��
// 	if (seq == 1 && atoi(key_type) == 0)
// 	{
// 		if (!encflag_sync(local_spi))
// 		{
// 			perror("encflag_sync error!\n");
// 			return;
// 		}
// 	}
// 	// �ж���Կ�����Ƿ�ͬ�������������Կ����ͬ��
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
// 		{									   // �����û�г�ʼ����Կ���߳�����Կ����Χ��Ҫ������������ͬ��
// 			bool ret = derive_sync(local_spi); // ��������ͬ��
// 			if (!ret)
// 			{
// 				perror("derive_sync error!\n");
// 				return;
// 			}
// 			readSAkey(local_spi, local_spi->raw_ekey, len); // ��ȡSA�Ự��Կ
// 			local_spi->ekey_rw += local_spi->cur_ekeyd;
// 		}
// 		memcpy(buf, local_spi->raw_ekey, len);
// 	}
// 	else // ������Կ:���ڽ�����Կά��һ������Կ�Ĵ������ݴ��ȥ����Կ��Ӧ��ʧ�����
// 	{
// 	loop1:
// 		if (seq > local_spi->dkey_rw)
// 		{
// 			if (isEmpty(&local_spi->myQueue))
// 			{ // ���ж϶����Ƿ�Ϊ�գ�����ǿգ�˵��������δ������У�����һ��ʱ��ĵȴ�
// 				usleep(100000);
// 				goto loop1;
// 			}
// 			// �����û�г�ʼ����Կ���߳�����Կ����Χ��Ҫ����ԭʼ��Կ�Լ�syn����,
// 			memcpy(local_spi->old_dkey, local_spi->raw_dkey, len);
// 			readSAkey(local_spi, local_spi->raw_dkey, len); // ��ȡ��Կ
// 			// ���´���
// 			local_spi->dkey_lw = local_spi->dkey_rw + 1;
// 			int dkeyd = dequeue(&local_spi->myQueue); // ��ȷ�Ľ�������������һ�����й���
// 			local_spi->dkey_rw += dkeyd;
// 			goto loop1;
// 		}

// 		if (seq >= local_spi->dkey_lw)
// 		{
// 			memcpy(buf, local_spi->raw_dkey, len); // �������ݰ�
// 		}
// 		else
// 		{
// 			memcpy(buf, local_spi->old_dkey, len); // �������ݰ�
// 		}
// 	}
// 	//printf("qkey:%s size:%d sei:%d\n", buf, len, local_spi->keyindex);
// 	send(fd, buf, len, 0);
// }

/**
 * @description: otp��Կ������
 * @param {char} *spi	�����SPI���֣��ַ�������ʽ
 * @param {char} *syn	��������к�
 * @param {char} *key_type	�������Կ���ͣ�0���� 1����
 * @param {int} fd	socket�ļ�������
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
	// �ж�syn�Ƿ�Ϊ1�����Ǽ��ܷ���������мӽ��ܹ�ϵͬ����������Ҫͬ��
	if (seq == 1 && atoi(key_type) == 0)
	{
		if (!encflag_sync(local_spi))
		{
			perror("encflag_sync error!\n");
			return;
		}
	}
	// �ж���Կ�����Ƿ�ͬ�������������Կ����ͬ��
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
	{ // ������Կ
		int ekey_rw = local_spi->ekey_rw;
		if (seq > ekey_rw)
		{ //// �����û�г�ʼ����Կ���߳�����Կ����Χ��Ҫ����ԭʼ��Կ�Լ�syn����,Э���µ���Կ��������
			if (local_spi->ekeybuff != NULL)
				free(local_spi->ekeybuff);
			local_spi->ekeybuff = (Keyblock *)malloc(WINSIZE * sizeof(Keyblock));
			bool ret = eM_sync(local_spi); // ��Կ����ֵMͬ��
			for (int i = 0; i < WINSIZE; i++)
			{
				readSAkey(local_spi, local_spi->ekeybuff[i].key, local_spi->eM);
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
			if (isEmpty(&local_spi->myQueue))
			{ // ���ж϶����Ƿ�Ϊ�գ�����ǿգ�˵��������δ������У�����һ��ʱ��ĵȴ�
				usleep(100000);
				goto loop2;
			}
			// �����û�г�ʼ����Կ���߳�����Կ����Χ��Ҫ����ԭʼ��Կ�Լ�syn����,Э���µ���Կ��������
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
 * @param {int} fd socket�ļ�������
 * @return {*}
 */
void spiregister_handle(const char *spi, const char *inbound, int fd)
{
	// ����ͨ��ĳ�ַ�ʽ��⵽�µ�SPI
	int newSPI = atoi(spi);
	int newinbound = atoi(inbound);
	// ��̬�����ڴ棬���洢�µ�SPI����
	dynamicSPI[spiCount] = (SpiParams *)malloc(sizeof(SpiParams));

	char hexStr[64];											// �㹻����ַ��������洢ת������ַ���
	sprintf(hexStr, "%s/%x", keypool_path, htonl(newSPI));		// ������ת��Ϊʮ�������ַ���
	strcpy(dynamicSPI[spiCount]->keyfile, hexStr);				// ��SPI��ʼ����Կ������
	pthread_rwlock_init(&(dynamicSPI[spiCount]->rwlock), NULL); // ��ʼ����д��
	pthread_mutex_init(&(dynamicSPI[spiCount]->mutex), NULL);	// ��ʼ��������
	if (dynamicSPI[spiCount] != NULL)
	{
		dynamicSPI[spiCount]->spi = newSPI;
		// ��ʼ��������SPI��صĲ���
		dynamicSPI[spiCount]->key_sync_flag = false;							   // ��Կ����ͬ����־����Ϊfalse
		dynamicSPI[spiCount]->delkeyindex = 0, dynamicSPI[spiCount]->keyindex = 0; // ��ʼ����Կƫ��
		dynamicSPI[spiCount]->ekeybuff = NULL;
		dynamicSPI[spiCount]->dkeybuff = NULL;
		dynamicSPI[spiCount]->olddkeybuff = NULL;
		dynamicSPI[spiCount]->ekey_rw = 0;
		dynamicSPI[spiCount]->dkey_lw = 0;
		dynamicSPI[spiCount]->dkey_rw = 0;
		// �������վSPI����Ҫ��ʼ�����ܲ���
		if (newinbound)
		{
			dynamicSPI[spiCount]->encrypt_flag = 1;
			initializeQueue(&(dynamicSPI[spiCount]->myQueue)); // ��ʼ��������Կ������������
		}
		else
		{
			dynamicSPI[spiCount]->encrypt_flag = 0;
			dynamicSPI[spiCount]->cur_ekeyd = INIT_KEYD; // ��ʼ��������Կ��������
			dynamicSPI[spiCount]->eM = INIT_KEYM;
		}
		spiCount++; // ���¼�����
		printf("Memory allocation successed for new SPI.\n");
	}
	else
	{
		printf("Memory allocation failed for new SPI.\n");
	}
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
	char buf[BUFFER_SIZE];
	sprintf(buf, "keyindexsync %d\n", keyindex + delkeyindex);
	send(fd, buf, strlen(buf), 0);
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
	enqueue(&local_spi->myQueue, tmp_keyd);
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
	enqueue(&local_spi->myQueue, tmp_dM);
	return;
}

/**
 * @description: ���̵߳Ĵ���,��������socket�˿�
 * @return {*}
 */
void *reactor_local_socket()
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
					printf("local_connection request:!\n");
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

int main(int argc, char *argv[])
{
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
	SAkey_sync_flag = false;
	// ɾ���ļ����ڵ��ļ�
	char command[256];
	snprintf(command, sizeof(command), "rm -rf %s", keypool_path);
	system(command);
	// �����ļ���
	if (mkdir(keypool_path, 777) != 0)
	{
		perror("mkdir");
		exit(EXIT_FAILURE);
	}

	//���Ƴ��ɵ���Կ�ļ�
	remove(KEY_FILE);

	pthread_rwlock_init(&keywr, NULL); // ��ʼ����д��
	pthread_mutex_init(&mutex, NULL);  // ��ʼ��������
	pthread_t writethread[3];
	pthread_create(&writethread[0], NULL, thread_writesharedkey, NULL); // DH��Կд���߳�����
	pthread_detach(writethread[0]);										// �̷߳���
	pthread_create(&writethread[1], NULL, thread_writeSAkey, NULL);		// SA��Կд���߳�����
	pthread_detach(writethread[1]);										// �̷߳���
	pthread_create(&writethread[2], NULL, thread_keyradetection, NULL); // ��Կ����̽���߳�����
	pthread_detach(writethread[2]);										// �̷߳���

	pthread_t thread1, thread2;
	// ������������������ʼ������Կ����
	pthread_create(&thread1, NULL, reactor_local_socket, NULL);
	pthread_create(&thread2, NULL, reactor_external_socket, NULL);
	// �ȴ����߳̽���
	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

	// �����˳�ʱ�ͷ���Դ
	pthread_rwlock_destroy(&keywr); // ���ٶ�д��
	pthread_mutex_destroy(&mutex);	// ���ٻ�����
	for (int i = 0; i < spiCount; ++i)
	{ // �ͷ��ڴ�
		free(dynamicSPI[i]->ekeybuff);
		free(dynamicSPI[i]->dkeybuff);
		free(dynamicSPI[i]->olddkeybuff);
		pthread_mutex_destroy(&(dynamicSPI[i]->mutex));
		pthread_rwlock_destroy(&(dynamicSPI[i]->rwlock));
		free(dynamicSPI[i]);
	}
	return 0;
}
