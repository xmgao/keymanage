/*
 * @Author: xmgao dearlanxing@mail.ustc.edu.cn
 * @Date: 2023-03-30 15:42:44
 * @LastEditors: xmgao dearlanxing@mail.ustc.edu.cn
 * @LastEditTime: 2024-07-04 16:24:28
 * @FilePath: \c\keymanage\project2\km.c
 * @Description:
 *
 * Copyright (c) 2024 by ${git_name_email}, All Rights Reserved.
 */

#include "km.h"

//  ����: gcc km.c -o km -g -pthread -lssl -lcrypto
// ���� sudo ./km remoteip >testlog 2> errlog

#define MAX_EVENTS 10000 // ����������
#define BUFFER_SIZE 1024 // ��ͨ���ݰ���������󳤶�
#define buf_size 1548	 // OTP���ݰ���������󳤶ȣ�Ӧ��Ϊһ��MTU���������Ա�����Կ���ֽ���
#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define socket_path "/tmp/my_socket"				// ���屾���׽���·��
#define EXTERNAL_PORT 50001							// Ĭ�Ϸ������ⲿ�����˿�
#define MAX_KEYFILE_SIZE 200 * 1024 * 1024			// �����Կ�ļ���С������Կ�ļ������������ʱ�����������Կ 200M
#define keypool_path "keypool"						// ���屾����Կ���ļ���
#define KEY_FILE "keyfile.kf"						// dh,psk��Կ�ļ�
#define TEMPKEY_FILE "tempkeyfile.kf"				// ��ʱ��Կ�ļ�
#define INIT_KEYD 100								// ��ʼ��Կ��������
#define INIT_KEYM 16								// ��ʼOTP��Կ����ֵ16�ֽ�
#define up_index 2									// ������������
#define down_index 500								// ������������
#define LT 0.2										// �½�
#define HT 0.7										// �Ͻ�
#define WINSIZE 4096								// ��Կ���ڴ�С
#define MAX_DYNAMIC_SPI_COUNT 100					// ���ͬʱ����SPI����
#define HMAC_KEY "7890ABCDEF1234567890ABCDEF123456" // HMAC��Կ

#define METHOD_SIZE 32
#define DATA_SIZE 64
#define HMAC_SIZE 32
#define PACKET_SIZE (METHOD_SIZE + DATA_SIZE + HMAC_SIZE)

#define DEBUG_LEVEL 1

SpiParams *dynamicSPI[MAX_DYNAMIC_SPI_COUNT];
int key_creat_rate;		// ��Կ��������ȫ�ֱ���
int IKEkeyindex;		// ���ڱ�ʶ����SA��Կ��������
bool SAkey_sync_flag;	// ��Կͬ����־�����ڹ�ӦsaЭ��
int spiCount = 0;		// ��ǰSPI����
pthread_rwlock_t keywr; // ������Կ�صĶ�д��
pthread_mutex_t mutex;	// ������Կ�صĶ�д��
int SERV_PORT;			// �����������˿�
char remote_ip[32];		// ��¼Զ��ip��ַ

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

// // ��װHMACǩ��
// void hmac_sign(const char *message, char *signed_message)
// {
// 	unsigned char hmac_result[EVP_MAX_MD_SIZE];
// 	unsigned int hmac_len;

// 	// ����HMAC
// 	HMAC_CTX *ctx = HMAC_CTX_new();
// 	HMAC_Init_ex(ctx, HMAC_KEY, strlen(HMAC_KEY), EVP_sha256(), NULL);
// 	HMAC_Update(ctx, (unsigned char *)message, strlen(message));
// 	HMAC_Final(ctx, hmac_result, &hmac_len);
// 	HMAC_CTX_free(ctx);

// 	// ��HMAC���ӵ���Ϣ��
// 	strcpy(signed_message, message);
// 	char hmac_hex[EVP_MAX_MD_SIZE * 2 + 1];
// 	for (int i = 0; i < hmac_len; i++)
// 	{
// 		sprintf(&hmac_hex[i * 2], "%02hhx", hmac_result[i]);
// 	}
// 	strcat(signed_message, hmac_hex);
// }

// // ��֤ǩ�����װ
// bool hmac_verify(const char *signed_message, char *original_message)
// {
// 	unsigned int hmac_len = EVP_MD_size(EVP_sha256());
// 	unsigned int message_len = strlen(signed_message) - hmac_len * 2;

// 	// ��ȡԭʼ��Ϣ
// 	strncpy(original_message, signed_message, message_len);
// 	original_message[message_len] = '\0';

// 	// ��ȡ���յ���HMAC
// 	char received_hmac_hex[EVP_MAX_MD_SIZE * 2 + 1];
// 	strncpy(received_hmac_hex, signed_message + message_len, hmac_len * 2);
// 	received_hmac_hex[hmac_len * 2] = '\0';

// 	unsigned char received_hmac[EVP_MAX_MD_SIZE];
// 	for (int i = 0; i < hmac_len; i++)
// 	{
// 		sscanf(&received_hmac_hex[i * 2], "%02hhx", &received_hmac[i]);
// 	}

// 	// ����ԭʼ��Ϣ��HMAC
// 	unsigned char calculated_hmac[EVP_MAX_MD_SIZE];
// 	unsigned int calculated_hmac_len;
// 	HMAC_CTX *ctx = HMAC_CTX_new();
// 	HMAC_Init_ex(ctx, HMAC_KEY, strlen(HMAC_KEY), EVP_sha256(), NULL);
// 	HMAC_Update(ctx, (unsigned char *)original_message, strlen(original_message));
// 	HMAC_Final(ctx, calculated_hmac, &calculated_hmac_len);
// 	HMAC_CTX_free(ctx);

// 	// �Ƚ�HMAC
// 	if (memcmp(received_hmac, calculated_hmac, hmac_len) == 0)
// 	{
// 		return 1; // ��֤�ɹ�
// 	}
// 	else
// 	{
// 		return 0; // ��֤ʧ��
// 	}
// }

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
		if (DEBUG_LEVEL == 1)
		{
			printf("Received data from socket: %s\n", buffer);
		}

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

void *thread_keyschedule(void *args)
{
	// ģ�ⲻ��д����Կ����Կ���ļ�
	while (1)
	{
		sleep(30);					// �ȴ�30s
		int delindex = IKEkeyindex; // Ҫɾ������Կ������
		if (delindex == 0)
		{
			continue;
		}
		pthread_rwlock_wrlock(&keywr); // ����
		printf("Expired key cleanup starting...\n");
		FILE *fp = fopen(KEY_FILE, "rb"); // ��λ���ļ�ĩ
		FILE *fp2 = fopen(TEMPKEY_FILE, "wb");
		if (fp == NULL || fp2 == NULL)
		{
			perror("open keyfile error!\n");
			exit(1);
		}
		else
		{
			fseek(fp, delindex * 1, SEEK_SET); // �ļ�ָ��ƫ�Ƶ�ָ��λ��
			char buffer[BUFFER_SIZE];
			size_t bytesRead;
			while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, fp)) > 0)
			{
				fwrite(buffer, 1, bytesRead, fp2);
			}
			fclose(fp);
			fclose(fp2);
		}
		remove(KEY_FILE);
		if (rename(TEMPKEY_FILE, KEY_FILE) == 0)
		{
			IKEkeyindex = 0;
			printf("IKE key pool renew success! \n");
		}
		else
		{
			perror("rename error!");
		}
		pthread_rwlock_unlock(&keywr); // ����
		for (int i = 0; i < spiCount; i++)
		{
			renewSAkey(dynamicSPI[i]);
		}
	}
}

/**
 * @description:  ������Կ�أ�����ɾ����Կ����
 * @param {SpiParams *} local_spi ����spi������ָ��
 * @return {*}
 */
void renewSAkey(SpiParams *local_spi)
{
	int delindex = local_spi->keyindex; // Ҫɾ������Կ������
	if (delindex == 0)
	{
		return;
	}
	pthread_rwlock_wrlock(&local_spi->rwlock); // ��д��

	FILE *fp = fopen(local_spi->keyfile, "rb");
	FILE *fp2 = fopen(TEMPKEY_FILE, "wb");
	if (fp == NULL || fp2 == NULL)
	{
		perror("open keyfile error!\n");
		exit(1);
	}
	else
	{
		fseek(fp, delindex * 1, SEEK_SET); // �ļ�ָ��ƫ�Ƶ�ָ��λ��
		char buffer[BUFFER_SIZE];
		size_t bytesRead;
		while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, fp)) > 0)
		{
			fwrite(buffer, 1, bytesRead, fp2);
		}
		fclose(fp);
		fclose(fp2);
	}
	remove(local_spi->keyfile);
	if (rename(TEMPKEY_FILE, local_spi->keyfile) == 0)
	{
		local_spi->delkeyindex += delindex;
		local_spi->keyindex = 0;
		printf("key pool renewed...\n SPI:%x delkeyindex:%d  keyindex:%d  \n", htonl(local_spi->spi), local_spi->delkeyindex, local_spi->keyindex);
	}
	else
	{
		perror("rename error!");
	}
	pthread_rwlock_unlock(&local_spi->rwlock); // ����
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
		if (DEBUG_LEVEL == 1)
		{
			printf("filename:%s\n", fileNames[i]);
		}

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

// ��Կ����̽��
void *thread_keyradetection(void *args)
{
	printf("key_rate_detection starting...\n");
	key_creat_rate = 16000; // ��ʼ������16kBps
	// ���ȶ����ļ�ָ�룺fp
	FILE *fp;
	int prefilelen = 0;
	int nextfilelen = 0;
	int detetctime = 2000000; // ̽��ʱ�䣬��λus
	while (1)
	{
		pthread_rwlock_rdlock(&keywr); // �϶���
		fp = fopen(KEY_FILE, "rb");
		fseek(fp, 0, SEEK_END);	 // ��λ���ļ�ĩ
		nextfilelen = ftell(fp); // �ļ�����
		fclose(fp);
		pthread_rwlock_unlock(&keywr); // ����
		if (prefilelen == 0)
		{
			prefilelen = nextfilelen;
		}
		else
		{
			// ��ʱ̽����Կ����
			key_creat_rate = (int)((nextfilelen - prefilelen) / 2); // kBps
			// printf("key_creat_rate: %d kbps\n", key_creat_rate*8);
			prefilelen = nextfilelen;
		}
		usleep(detetctime); // �ȴ�2s
	}
	pthread_exit(0);
}

// ��Կ�ط���
void *thread_writeSAkey(void *args)
{

	printf("CHILDSAkey supply starting...\n");
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
			// ΪSAд��Կ
			for (int i = 0; i < spiCount; i++)
			{
				FILE *fp2 = fopen(dynamicSPI[i]->keyfile, "ab");
				{
					pthread_rwlock_wrlock(&dynamicSPI[i]->rwlock); // ��д��
					fseek(fp2, 0, SEEK_END);					   // ��λ���ļ�ĩ
					fwrite(key, sizeof(unsigned char), 512, fp2);
					pthread_rwlock_unlock(&dynamicSPI[i]->rwlock); // ����
				}
				fclose(fp2);
			}
			// ����ָ�������ͣ����ִ��,΢��
			usleep((int)(interval / 1000));
		}
		prevTimestamp = currentTimestamp;
	}
	fclose(file);
	pthread_exit(0);
}

// ��Կ�ط���
void *thread_writesharedkey(void *args)
{
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
			// ���ȶ����ļ�ָ�룺fp
			FILE *fp = fopen(KEY_FILE, "ab+");
			fseek(fp, 0, SEEK_END);	  // ��λ���ļ�ĩ
			int nFileLen = ftell(fp); // �ļ�����
			if (nFileLen < MAX_KEYFILE_SIZE)
			{
				fwrite(key, sizeof(unsigned char), 512, fp);
			}
			fclose(fp);
			pthread_rwlock_unlock(&keywr); // ����
			// ����ָ�������ͣ����ִ��,΢��
			usleep((int)(interval / 1000));
		}
		prevTimestamp = currentTimestamp;
	}
	fclose(file);

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
		fseek(fp, IKEkeyindex, SEEK_SET); // ���ļ�ָ��ƫ�Ƶ�ָ��λ��
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
	IKEkeyindex += len;
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
		bool ret = IKESAkey_sync();
		if (!ret)
		{
			perror("IKESAkey_sync error!\n");
			char buf2[] = "A";
			send(fd, buf2, strlen(buf2), 0);
			return;
		}
	}
	// ��ȡ��Կ
	readsharedkey(buf, len);
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
void getsk_handle(const char *spi, const char *keylen, const char *syn, const char *key_type, int fd)
{
	int i = 0;
	int hostspi = atoi(key_type) == 1 ? ntohl(atoi(spi)) : atoi(spi); // ����ǻ�ȡ������Կ�����spiֵ�Ǿ��������ֽ�ת���ģ���Ҫ��ת���������ֽ�
	while (dynamicSPI[i]->spi != hostspi)
	{
		i++;
	}
	SpiParams *local_spi = dynamicSPI[i];

	if (local_spi->encalg == 0)
	{
		local_spi->encalg = 1; // ��ֵΪ��̬�����㷨
	}

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
void getotpk_handle(const char *spi, const char *syn, const char *key_type, int fd)
{
	int i = 0;
	int hostspi = atoi(key_type) == 1 ? ntohl(atoi(spi)) : atoi(spi); // ����ǻ�ȡ������Կ�����spiֵ�Ǿ��������ֽ�ת���ģ���Ҫ��ת���������ֽ�
	while (dynamicSPI[i]->spi != hostspi)
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
		dynamicSPI[spiCount]->encalg = 0;										   // ��ʼ�޷�֪�������㷨
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
			dynamicSPI[spiCount]->in_bound = 1;
			initializeQueue(&(dynamicSPI[spiCount]->myQueue)); // ��ʼ��������Կ������������
		}
		else
		{
			dynamicSPI[spiCount]->in_bound = 0;
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

// ��������ᱻ�µ��߳�ִ��
void *print_variable()
{

	while (1)
	{
		system("clear");
		printf("\033[1H"); // ����궨λ����1��
		FILE *fp;
		fp = fopen(KEY_FILE, "rb");
		fseek(fp, 0, SEEK_END);	  // ��λ���ļ�ĩ
		int nFileLen = ftell(fp); // �ļ�����
		fclose(fp);
		printf("ikekeypoolsize: %08d \tBytes\n", nFileLen);
		printf("keycreatrate: %6d \tkbps\n", key_creat_rate * 8);
		printf("ikekeyuse: %08d \t Bytes\n", IKEkeyindex);

		printf("ipsecsatables: %2d \t SAs\n", spiCount);
		for (int i = 0; i < spiCount; i++)
		{
			printf("\nSPI: %x \t enc_flag:%d\n", htonl(dynamicSPI[i]->spi), dynamicSPI[i]->in_bound);
			FILE *fp = fopen(dynamicSPI[i]->keyfile, "rb");
			if (fp == NULL)
			{
				printf("Failed to open file: %s\n", dynamicSPI[i]->keyfile);
				// ������Ը��������Ҫ����������緵�ش���������˳�����
			}
			else
			{
				fseek(fp, 0, SEEK_END);
				int nSAFileLen = ftell(fp); // �ļ�����
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
		// ��ͣһ��ʱ�䣬�Ա�۲����
		sleep(2);
	}
	return NULL;
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

	// ���Ƴ��ɵ���Կ�ļ�
	remove(KEY_FILE);

	pthread_rwlock_init(&keywr, NULL); // ��ʼ����д��
	pthread_mutex_init(&mutex, NULL);  // ��ʼ��������
	pthread_t writethread[4];
	pthread_create(&writethread[0], NULL, thread_writesharedkey, NULL); // ��Կд���߳�����
	pthread_detach(writethread[0]);										// �̷߳���
	pthread_create(&writethread[1], NULL, thread_writeSAkey, NULL);		// SA��Կд���߳�����
	pthread_detach(writethread[1]);

	// pthread_create(&writethread[2], NULL, thread_keyschedule, NULL); // ��Կ�����߳�����
	// pthread_detach(writethread[2]);									 // �̷߳���

	// ̽���̵߳ȴ�1s������
	sleep(1);
	pthread_create(&writethread[3], NULL, thread_keyradetection, NULL); // ��Կ����̽���߳�����
	pthread_detach(writethread[3]);										// �̷߳���

	pthread_t thread_local, thread_external;
	pthread_t thread_front_end;
	// ������������������ʼ������Կ����
	pthread_create(&thread_local, NULL, reactor_local_socket, NULL);
	pthread_create(&thread_external, NULL, reactor_external_socket, NULL);
	sleep(1);
	// ����һ���µ��̣߳�����̻߳�ִ��print_variable����
	pthread_create(&thread_front_end, NULL, print_variable, NULL);

	// �ȴ����߳̽���
	pthread_join(thread_local, NULL);
	pthread_join(thread_external, NULL);

	// �ȴ��µ��߳̽���
	pthread_join(thread_front_end, NULL);

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
