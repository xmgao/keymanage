#include "epollrun.h"
#include<pthread.h>

//  ����: gcc epollrun.c -o km -g -pthread 
//���� ./km remoteip


bool key_sync_flag;  //��Կͬ����־
int delkeyindex, keyindex, sekeyindex, sdkeyindex;  //��Կ����������ɾ��������Կ����ʶ��ǰ��sa��Կ,������Կ��������Կ
int encrypt_flag, decrypt_flag;  //������Կ�Լ�������Կ�Ķ�Ӧ��ϵ��0��ʶ������Կ��1��ʶ������Կ
int SERV_PORT;  //�����������˿�
int cur_ekeyd, next_ekeyd, cur_dkeyd, next_dkeyd;   //��¼��ǰ����Կ������������һ����Կ��������
char  raw_ekey[64];//��¼ԭʼ������Կ
char remote_ip[32];  //��¼Զ��ip��ַ
int	next_dM[10000]={0};	//������Կ���ڴ�С�ı��ػ��棬������%10000��ѭ��

//����OTP����Կ��ṹ��
typedef struct {
    char key[1024];
    int size;
} Keyblock;

//ָ����Կ��ĳ�ʼֵ16�ֽ�
int eM=16,nexteM=16,dM=16,nextdM=16;

Keyblock *ekeybuff,*dkeybuff,*olddkeybuff;

int init_listen_local(int port, int epfd) {
    int lfd, ret;
    struct epoll_event tep;
    struct sockaddr_in serv_addr;
    socklen_t client_addr_size;
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    // ���ؼ���
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr.s_addr);
    
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket create error!\n");
        exit(1);
    }
    
    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    int br = bind(lfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if (br < 0) {
        perror("bind error!\n");
        exit(1);
    }
    
    listen(lfd, 128);

    tep.events = EPOLLIN;
    tep.data.fd = lfd;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &tep);
    if (ret == -1) {
        perror("epoll_ctl_add error!\n");
        exit(1);
    }
    
    return lfd;
}

int init_listen_external(int port, int epfd) {
    int lfd, ret;
    struct epoll_event tep;
    struct sockaddr_in serv_addr;
    socklen_t client_addr_size;
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    //�ⲿ����
	inet_pton(AF_INET, "0.0.0.0", &serv_addr.sin_addr.s_addr);
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket create error!\n");
        exit(1);
    }
    
    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    int br = bind(lfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if (br < 0) {
        perror("bind error!\n");
        exit(1);
    }
    
    listen(lfd, 128);

    tep.events = EPOLLIN;
    tep.data.fd = lfd;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &tep);
    if (ret == -1) {
        perror("epoll_ctl_add error!\n");
        exit(1);
    }
    
    return lfd;
}

//�������� 
bool con_serv(int* fd, const char* src, int port) {
    int  ret, cr;
    struct sockaddr_in serv_addr;
    socklen_t client_addr_size;

    *fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*fd < 0) {
        perror("socket error!\n");
        return false;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERV_PORT);
    inet_pton(AF_INET, src, &serv_addr.sin_addr.s_addr);


    cr = connect(*fd,(struct sockaddr*)(&serv_addr), sizeof(serv_addr)); //���ӶԷ�������
    if (cr < 0) {
        perror("connect error!\n");
        return false;
    }
	return true;
}

//������������
void do_crecon(int fd, int epfd) {
	struct sockaddr_in cli_addr;
	char cli_ip[16];
	int client_addr_size, ret;
	struct epoll_event tep;
	int ar = accept(fd, (struct sockaddr*)(&cli_addr), &client_addr_size);
	printf("ip address is: %s,port is: %d\n", inet_ntop(AF_INET, &cli_addr.sin_addr.s_addr, cli_ip, sizeof(cli_ip)),ntohs(cli_addr.sin_port));
	//����ar socket������
	int flag = fcntl(ar, F_GETFL);
	flag |= O_NONBLOCK;
	fcntl(ar, F_SETFL, flag);
	//�¼���ֵ
	tep.events = EPOLLIN;
	tep.data.fd = ar;

	//�¼�����
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, ar, &tep);
	if (ret == -1) {
		perror("epoll_ctl_add error!\n");
		exit(1);
	}
}


//�ر�����
void discon(int fd, int epfd) {

	int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
	if (ret < 0) {
		perror("EPOLL_CTL_DEL error...\n");
		//exit(1);
	}
	close(fd);

}

void do_recdata_local(int fd, int epfd){

        // ��ѯfd��״̬
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1 && errno == EBADF) {
		printf("fd is invalid\n");
		discon(fd, epfd);
		return;
	}

    char buffer[BUFFER_SIZE];
    // sockfd �������ݵ���
    ssize_t bytesRead = read(fd, buffer, BUFFER_SIZE);
    if (bytesRead == -1) {
        perror("Failed to read data from sockfd");
        exit(EXIT_FAILURE);
    } else if (bytesRead == 0) {
        // ���ӹرգ�������Ӧ����
        close(fd);
        // exit(EXIT_SUCCESS);
    } else {
        // �����ȡ��������
        if (buffer[bytesRead-1] == '\n') 
            buffer[bytesRead-1] = '\0';    
        printf("recieve:%s\n", buffer);
        //��Ӧ��getk   arg1==spi, arg2=keylen(�ֽ�)
		//��Ӧ��getsk  arg1==spi, arg2=keylen(�ֽ�), arg3=syn,arg4=keytype
		//��Ӧ��getotpk arg1==spi, arg2=syn,arg3=keytype
        uint8_t method[32] = {}, path[256] = {}, protocol[16] = {}, arg1[64] = {}, arg2[64] = {}, arg3[64] = {}, arg4[64] = {};
        int key_type;
        sscanf(buffer, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", method, arg1, arg2, arg3, arg4);
       if (strncasecmp(method, "getk", 4) == 0) {
			getk_handle(arg1, arg2, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "getotpk", 7) == 0) {
			getsk_handle_otp(arg1, arg2, arg3, fd);
		}
		else if (strncasecmp(method, "getsk", 5) == 0) {
			getsk_handle(arg1, arg2, arg3, arg4, fd);
			discon(fd, epfd);
		}
        else{
            printf("invalid recdata:%s\n",buffer);
			discon(fd, epfd);
        }

        }
    
}

void do_recdata_external(int fd, int epfd){

    // ��ѯfd��״̬
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1 && errno == EBADF) {
		printf("fd is invalid\n");
		discon(fd, epfd);
		return;
	}

    char buffer[BUFFER_SIZE];
    // sockfd �������ݵ���
    ssize_t bytesRead = read(fd, buffer, BUFFER_SIZE);
    if (bytesRead == -1) {
        perror("Failed to read data from sockfd");
        exit(EXIT_FAILURE);
    } else if (bytesRead == 0) {
        // ���ӹرգ�������Ӧ����
        close(fd);
        // exit(EXIT_SUCCESS);
    } else {
        // �����ȡ��������
        if (buffer[bytesRead-1] == '\n') 
            buffer[bytesRead-1] = '\0';    
        printf("recieve:%s\n", buffer);
        //��Ӧ��keysync  arg1=keyindex, arg2=sekeyindex,arg3=sdkeyindex
		//��Ӧ��key_index_sync arg1==encrypt_index, arg2==decrypt_index
		//��Ӧ��derive_sync  arg1==key_d
		//��Ӧ��eM_sync  arg1==tem_eM arg2==nextseq
        uint8_t method[32] = {}, path[256] = {}, protocol[16] = {}, arg1[64] = {}, arg2[64] = {}, arg3[64] = {}, arg4[64] = {};
        int key_type;
        sscanf(buffer, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", method, arg1, arg2, arg3, arg4);
        if (strncasecmp(method, "keysync", 7) == 0) {
			keysync_handle(arg1, arg2, arg3, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "kisync", 6) == 0) {
			kisync_handle(arg1, arg2, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "desync", 6) == 0) {
			desync_handle(arg1, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "eMsync", 6) == 0) {
			eMsync_handle(arg1, arg2, fd);
		}
        else{
            printf("invalid recdata:%s\n",buffer);
			discon(fd, epfd);
        }
        }
    
}

//�ӽ�����Կ��Ӧ��ϵͬ��
bool key_index_sync() {
	encrypt_flag = 0;
	decrypt_flag = 1;
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], kis[16];
	int fd, ret, tencrypt_index, tdecrypt_index;

	con_serv(&fd, remote_ip, SERV_PORT); //���ӶԷ�������
    printf("encrypt_flag:%d decrypt_flag:%d\n",encrypt_flag,decrypt_flag);
	sprintf(buf, "kisync %d %d\n", encrypt_flag, decrypt_flag);
	send(fd, buf, strlen(buf), 0);

	ret = read(fd, rbuf, sizeof(rbuf));
	sscanf(rbuf, "%[^ ] %d %d", kis, &tencrypt_index, &tdecrypt_index); //scanf("%[^\n] ", s); ����һ�У��س���Ϊ�������� ��ĩ�س���������; %[^ ]��ʾ���˿ո񶼿��Զ�
	close(fd);
	if (tencrypt_index == decrypt_flag && tdecrypt_index == encrypt_flag) {
		//close(fd);
		return true;
	}

	return false;
}

//��Կͬ��,������Զ�˷�������������ͬ����Կƫ��
bool key_sync() {

	int fd, ret;
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
	//struct sockaddr_in serv_addr, cli_addr;
	//socklen_t client_addr_size;
	sprintf(buf, "keysync di:%d ei:%d di:%d\n", keyindex + delkeyindex, sekeyindex + delkeyindex, sdkeyindex + delkeyindex);


	con_serv(&fd, remote_ip, SERV_PORT); //���ӶԷ�������


	ret = send(fd, buf, strlen(buf), 0);
	if (ret < 0) {
		perror("key_sync connect error!\n");
		return false;
	}
	ret = read(fd, rbuf, sizeof(rbuf));
	//n = get_line(fd, buf, BUFFER_SIZE);
	int tkeyindex, tsekeyindex, tsdkeyindex;
	sscanf(rbuf, "%[^ ] %d %d %d", method, &tkeyindex, &tsekeyindex, &tsdkeyindex);		//�޸�
	keyindex = max(tkeyindex, keyindex + delkeyindex) - delkeyindex;
	sekeyindex = max(tsdkeyindex, sekeyindex + delkeyindex) - delkeyindex;
	sdkeyindex = max(tsekeyindex, sdkeyindex + delkeyindex) - delkeyindex;

	//renewkey();
	close(fd);
	key_sync_flag = true;
	return true;
}


//��Կ��������Э��
bool derive_sync() {
	int fd, ret, tmp_keyd;
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
	//ͨ����Կ�����жϽ���������Կ��������
	cur_ekeyd = next_ekeyd;
	if (sdkeyindex > Th1 * MAX_KEYFILE_SIZE / KEY_UNIT_SIZE * 1 / 2 * (KEY_RATIO - 2) / KEY_RATIO) {
		tmp_keyd = (int)next_ekeyd * up_index;
	}
	else if (sdkeyindex < Th2 * MAX_KEYFILE_SIZE / KEY_UNIT_SIZE * 1 / 2 * (KEY_RATIO - 2) / KEY_RATIO) {
		tmp_keyd = (int)next_ekeyd * (1 - down_index);
	}
	else {
		tmp_keyd = next_ekeyd;
	}
	tmp_keyd=tmp_keyd>1000?tmp_keyd:1000;
	sprintf(buf, "desync %d\n", tmp_keyd);

	con_serv(&fd, remote_ip, SERV_PORT); //���ӶԷ�������
	ret = send(fd, buf, strlen(buf), 0);
	if (ret < 0) {
		perror("derive_sync connect error!\n");
		return false;
	}
	ret = read(fd, rbuf, sizeof(rbuf));
	int r_keyd;
	sscanf(rbuf, "%[^ ] %d", method, &r_keyd);
	close(fd);
	if (tmp_keyd == r_keyd) {
		next_ekeyd = tmp_keyd;
		return true;
	}

	return false;
}

//������Կ�أ�����ɾ����Կ����
void renewkey() {
	//int delkeyindex, keyindex, sekeyindex, sdkeyindex
	int delindex; 	//Ҫɾ������Կ������
	//pthread_rwlock_wrlock(&keywr); //����
	delindex = min(sdkeyindex, sekeyindex);
	if (delindex == 0) {
		return;
	}
	FILE* fp = fopen(KEY_FILE, "r");
	FILE* fp2 = fopen(TEMPKEY_FILE, "w");
	if (fp == NULL) {
		perror("open keyfile error!\n");
		exit(1);
	}
	else {
		fseek(fp, delindex * KEY_UNIT_SIZE, SEEK_SET); //�ļ�ָ��ƫ�Ƶ�ָ��λ��
		char buffer = fgetc(fp);
		int cnt = 0;
		while (!feof(fp)) {
			cnt++;
			fputc(buffer, fp2);
			buffer = fgetc(fp);
		}
		fclose(fp2);
	}
	fclose(fp);
	remove(KEY_FILE);
	if (rename(TEMPKEY_FILE, KEY_FILE) == 0) {
		delkeyindex += delindex;
		keyindex = 0;
		sekeyindex -= delindex;
		sdkeyindex -= delindex;
		printf("key pool renewed...\ndelkeyindex:%d  keyindex:%d  sekeyindex:%d  sdkeyindex:%d \n", delkeyindex, keyindex, sekeyindex, sdkeyindex);
	}
	else {
		perror("rename error!");
	}
	//pthread_rwlock_unlock(&keywr); //����
}
/*
//��Կд���߳�
void* thread_write() {
	//���ȶ����ļ�ָ�룺fp
	FILE* fp;
	remove(KEY_FILE);
	printf("key supply starting...\n");
	//ģ�ⲻ��д����Կ����Կ���ļ�
	int count=0; //������������������Կ�ظ���
	while (1) {
		unsigned char* buf=(unsigned char *)malloc(KEY_CREATE_RATE*sizeof(unsigned char));
		int i = 0;
		srand(666);
		for (; i < KEY_CREATE_RATE; i++) { //����γ���Կ��
			int ret = rand()%256;
			buf[i] = ret;
		}
		pthread_rwlock_wrlock(&keywr); //����
		fp = fopen(KEY_FILE, "a+");
		fseek(fp, 0, SEEK_END); //��λ���ļ�ĩ 
		int nFileLen = ftell(fp); //�ļ�����
		fseek(fp, 0, SEEK_SET); //�ָ����ļ�ͷ
		//�ж��ļ���С�����ļ������趨��ֵ����д��
		float poolsize=(float)(nFileLen-KEY_UNIT_SIZE*(sekeyindex+sdkeyindex)/2)/1024;
		printf("keypoolsize:%.2f KByetes\n",poolsize);
		if (nFileLen < MAX_KEYFILE_SIZE) {
			fputs(buf, fp);
		}
		free(buf);
		fclose(fp);
		if (nFileLen >= MAX_KEYFILE_SIZE && count >=30) { //��Կ�����Ҹ���ʱ�䳬��30s
			renewkey();
			count=0;
		}
		pthread_rwlock_unlock(&keywr); //����
		count++;
		sleep(1); //�ȴ�1s
	}

	pthread_exit(0);
}
*/

//��ȡ������Կ
void readkey(char* const buf, const char key_type, int size) {
	int len = size;
	char* pb = buf;

	FILE* fp = fopen(KEY_FILE, "r");
	if (fp == NULL) {
		perror("open keyfile error!\n");
		exit(1);
	}
	else {
		if (key_type == '0') {  //������Կ
			//fseek(fp, sekeyindex * KEY_UNIT_SIZE, SEEK_SET); //�ļ�ָ��ƫ�Ƶ�ָ��λ��
			int i = 0;
			while (i * KEY_UNIT_SIZE < len) {
				//�������ɾ����Կ����
				if ((sekeyindex+ delkeyindex) % KEY_RATIO != 0 && ((sekeyindex+ delkeyindex) - 1) % KEY_RATIO != 0 && (sekeyindex+ delkeyindex) % 2 == (encrypt_flag)) {
					fseek(fp, sekeyindex * KEY_UNIT_SIZE, SEEK_SET);
					while(fgets(pb, KEY_UNIT_SIZE + 1, fp) == NULL) {
						printf("key supply empty!\n");
						keyfile_write();
						printf("key supply try again!\n");
						fseek(fp, sekeyindex * KEY_UNIT_SIZE, SEEK_SET); // ���ļ�ָ��ƫ�Ƶ�ָ��λ��
						}
					i++;
					pb += KEY_UNIT_SIZE;
				}
				sekeyindex++;
			}
			rewind(fp);
		}
		else if (key_type == '1') {  //������Կ
			//fseek(fp, sdkeyindex * KEY_UNIT_SIZE, SEEK_SET); //�ļ�ָ��ƫ�Ƶ�ָ��λ��
			int i = 0;
			while (i * KEY_UNIT_SIZE < len) {
				if ((sdkeyindex+ delkeyindex) % KEY_RATIO != 0 && (sdkeyindex+ delkeyindex - 1) % KEY_RATIO != 0 && (sdkeyindex+ delkeyindex) % 2 == (decrypt_flag)) {
					fseek(fp, sdkeyindex * KEY_UNIT_SIZE, SEEK_SET);
					while(fgets(pb, KEY_UNIT_SIZE + 1, fp) == NULL) {
						printf("key supply empty!\n");
						keyfile_write();
						printf("key supply try again!\n");
						fseek(fp, sdkeyindex * KEY_UNIT_SIZE, SEEK_SET); // ���ļ�ָ��ƫ�Ƶ�ָ��λ��
						}
					i++;
					pb += KEY_UNIT_SIZE;
				}
				sdkeyindex++;
			}
			rewind(fp);
		}
        else { //sa��Կ��Ԥ������Կ
			//fseek(fp, keyindex * KEY_UNIT_SIZE, SEEK_SET); //�ļ�ָ��ƫ�Ƶ�ָ��λ��
			int i = 0, plen = 0;
			while (i * KEY_UNIT_SIZE < len) {
				if ((keyindex+ delkeyindex) % KEY_RATIO == 0 || ((keyindex+ delkeyindex) - 1) % KEY_RATIO == 0) {
					fseek(fp, keyindex * KEY_UNIT_SIZE, SEEK_SET);
					fgets(pb, KEY_UNIT_SIZE + 1, fp);
					i++;
					pb += KEY_UNIT_SIZE;
				}
				keyindex++;
			}
			rewind(fp);
		}
	}
	fclose(fp);

}


//sa��Կ������
void getk_handle(const char* spi, const char* keylen, int fd) {
	//�ж��Ƿ��Ѿ�ͬ�������û��ͬ�������Ƚ���˫��ͬ��
	if (!key_sync_flag) {
		bool ret = key_sync();
		if (!ret) {
			perror("key_sync error!\n");
			return;
		}
	}
    int len=atoi(keylen);
	char buf[len+1];
	//��ȡ��Կ
	readkey(buf, '2', len);
	send(fd, buf, len, 0);
	key_sync_flag = true;

}

//�Ự��Կ������
//Ŀǰ���ڷ���strongswan��������ڴ�Сʱ�ŵ��ô�����������ͨ��
void getsk_handle(const char* spi, const char* keylen, const char* syn, const char* key_type, int fd) {
	//���˫��û��ͬ���ӽ�����Կ�ض�Ӧ��ϵ�����Ƚ���ͬ��
	int range = 0;
	if (!(encrypt_flag ^ decrypt_flag)) {
		bool ret = key_index_sync();
		if (!ret) {
			perror("key_index_sync error��\n");
			return;
		}
	}
	//�ж�syn�Ƿ�Ϊ1���������ͬ����������Ҫͬ��,ͬʱ���շ���key_sync_flag�ᱻ����Ϊtrue���������ͬ��
	if (atoi(syn) == 1 && !key_sync_flag) {
		bool ret = key_sync();
		if (!ret) {
			perror("key_sync error!\n");
			return;
		}
	}

	char buf[BUFFER_SIZE];
	if (*key_type == '0') {
		bool ret = derive_sync(); //��������ͬ��
		if (!ret) {
			perror("derive_sync error!\n");
			return;
		}
		readkey(raw_ekey, *key_type, atoi(keylen)); //��ȡ��Կ
		printf("qkey:%s kdp:%d sei:%d sdi:%d \n", raw_ekey, cur_ekeyd, sekeyindex, sdkeyindex);
		sprintf(buf, "%s %d\n", raw_ekey, cur_ekeyd);
	}
	else {
		readkey(raw_ekey, *key_type, atoi(keylen)); //��ȡ��Կ
		printf("qkey:%s kdp:%d sei:%d sdi:%d \n", raw_ekey, cur_ekeyd, sekeyindex, sdkeyindex);
		sprintf(buf, "%s %d\n", raw_ekey, cur_dkeyd);
	}
	
	send(fd, buf, strlen(buf), 0);
}


int establish_connection() {
	static int socket_fd = -1; // ��̬�������ڱ����׽��ֵ��ļ�������
    if (socket_fd == -1) {
        // ��һ�ε��ã������׽���
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd == -1) {
            perror("Failed to create socket");
            // �����׽��ִ���ʧ�ܵ����
			return -1;
        }
        // ��������������׽��ֵĳ�ʼ������
		struct sockaddr_in serv_addr;
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(SERV_PORT);	// ���÷������˿ں�
		inet_pton(AF_INET, remote_ip, &serv_addr.sin_addr.s_addr);// ���÷�����IP��ַ
		int connect_result = connect(socket_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
		if (connect_result == -1) {
			perror("eM_sync connect error!\n");
			return -1;
    	}
		}
    return socket_fd;
}

//������Կ��ֵ����
bool updateM(int seq){
	static struct timeval pre_t, cur_t;
	if(pre_t.tv_sec==0){
		gettimeofday(&pre_t, NULL);
		gettimeofday(&cur_t, NULL);
		return true;
	}
	int fd, ret, tmp_eM;
	char buf[BUFFER_SIZE], rbuf[BUFFER_SIZE], method[32];
	pre_t=cur_t;
	gettimeofday(&cur_t, NULL);
	double duration = (cur_t.tv_sec - pre_t.tv_sec) + (cur_t.tv_usec - pre_t.tv_usec) / 1000000.0;
	int vconsume=WINSIZE*eM/duration; //��Կ�������ʣ���λ �ֽ�/s
		if(vconsume>=KEY_CREATE_RATE/2){
			tmp_eM=(eM/2 >	16)?eM/2:16;			//���Լ���,�½�16
		}
		else{
			tmp_eM=(eM+16 < 128)?eM+16:128;				//�������ӣ��Ͻ�128�ֽ�
		}
	sprintf(buf, "eMsync %d %d\n", tmp_eM,seq);
	fd=establish_connection();
	if (fd == -1) {
	// ����������ʧ�ܵ����
	perror("establish_connection error!\n");
	return false;
	}
// ���ó�ʱʱ��
struct timeval timeout = {1, 0}; // 1s��ʱ
setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));		

ret = send(fd, buf, strlen(buf), 0);
printf("send:%d\tnextseq:%d\tfd:%d\n",tmp_eM,seq,fd);
if (ret < 0) {
    //printf("eM_sync send error!\n");
    return false;
}

ret = read(fd, rbuf, sizeof(rbuf));
if (ret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // ����ǳ�ʱ������ʱ�����
        printf("Timeout on fd %d\n", fd);
		return false;
    } else {
        printf("eM_sync read error!\n");
        return false;
    }
}
	int r_eM;
	sscanf(rbuf, "%[^ ] %d", method, &r_eM);
	printf("read:%d\n",r_eM);

	if (tmp_eM == r_eM) {
		nexteM = tmp_eM;
		return true;
	}
	return false;
}

//otp��Կ������
void getsk_handle_otp(const char* spi,  const char* syn, const char* key_type, int fd) {
	int seq=atoi(syn);
	//���˫��û��ͬ���ӽ�����Կ�ض�Ӧ��ϵ�����Ƚ���ͬ��
	if (!(encrypt_flag ^ decrypt_flag)) {
		bool ret = key_index_sync();
		if (!ret) {
			perror("key_index_sync error��\n");
			return;
		}
	}
	//�ж�syn�Ƿ�Ϊ1���������ͬ����������Ҫͬ��,ͬʱ���շ���key_sync_flag�ᱻ����Ϊtrue���������ͬ��
	if (seq == 1 && !key_sync_flag) {
		bool ret = key_sync();
		if (!ret) {
			perror("key_sync error!\n");
			return;
		}
	}
	static int  ekey_rw=0, dkey_lw=0, dkey_rw=0, olddkey_lw;
	char buf[BUFFER_SIZE+20];
	//��ȡ��Կ
	if (*key_type == '0') {  //������Կ
		if (seq > ekey_rw) {  //�����û�г�ʼ����Կ���߳�����Կ����Χ��Ҫ����ԭʼ��Կ�Լ�syn����
			if(ekeybuff!=NULL) free(ekeybuff);
			ekeybuff=(Keyblock *) malloc(WINSIZE*sizeof(Keyblock));
		bool ret = updateM(seq); //��Կ����ֵMͬ��
		if (!ret) {
			printf("deriveM_sync error!\n");
		}else{
			eM=nexteM;
		}			
			for(int i=0;i<WINSIZE;i++){
				readkey(ekeybuff[i].key, *key_type, eM);
				ekeybuff[i].size=eM;
			}
			//���´���
			ekey_rw = ekey_rw + WINSIZE;

		}
		printf("qkey:%s size:%d sei:%d sdi:%d\n", ekeybuff[(seq-1)%WINSIZE].key, ekeybuff[(seq-1)%WINSIZE].size, sekeyindex, sdkeyindex);
		sprintf(buf, "%s %d\n", ekeybuff[(seq-1)%WINSIZE].key, ekeybuff[(seq-1)%WINSIZE].size);
	}
	else {  //������Կ:���ڽ�����Կά��һ������Կ�Ĵ������ݴ��ȥ����Կ��Ӧ��ʧ�����
		loop:
		if (seq > dkey_rw) {  //�����û�г�ʼ����Կ���߳�����Կ����Χ��Ҫ����ԭʼ��Կ�Լ�syn����,Э���µ���Կ��������
			if(olddkeybuff!=NULL) free(olddkeybuff);
			olddkeybuff=dkeybuff;
			dkeybuff=(Keyblock *) malloc(WINSIZE*sizeof(Keyblock));
			dM=next_dM[seq/WINSIZE]!=0?next_dM[seq/WINSIZE]:dM;
			for(int i=0;i<WINSIZE;i++){
				readkey(dkeybuff[i].key, *key_type, dM);
				dkeybuff[i].size=dM;
			}

			//���´���
			olddkey_lw = dkey_lw;
			dkey_lw = dkey_rw+1;
			dkey_rw = dkey_rw + WINSIZE;
			goto loop;

		}

		if (seq < dkey_lw) {
			printf("oldqkey:%s size:%d sei:%d sdi:%d\n", olddkeybuff[(seq-1)%WINSIZE].key, olddkeybuff[(seq-1)%WINSIZE].size, sekeyindex, sdkeyindex);
			sprintf(buf, "%s %d\n", olddkeybuff[(seq-1)%WINSIZE].key, olddkeybuff[(seq-1)%WINSIZE].size);
		}
		
		else  {
			printf("qkey:%s size:%d sei:%d sdi:%d\n", dkeybuff[(seq-1)%WINSIZE].key, dkeybuff[(seq-1)%WINSIZE].size, sekeyindex, sdkeyindex);
			sprintf(buf, "%s %d\n", dkeybuff[(seq-1)%WINSIZE].key, dkeybuff[(seq-1)%WINSIZE].size);
		}
	}
	send(fd, buf, strlen(buf), 0);
}

//��Կ����ͬ��������
void keysync_handle(const char* tkeyindex, const char* tsekeyindex, const char* tsdkeyindex, int fd) {

	char buf[BUFFER_SIZE];
	sprintf(buf, "keysync %d %d %d\n", keyindex + delkeyindex, sekeyindex + delkeyindex, sdkeyindex + delkeyindex);
	send(fd, buf, BUFFER_SIZE, 0);
	keyindex = max(atoi(tkeyindex), keyindex + delkeyindex) - delkeyindex;		//�޸�
	sekeyindex = max(atoi(tsdkeyindex), sekeyindex + delkeyindex) - delkeyindex;
	sdkeyindex = max(atoi(tsekeyindex), sdkeyindex + delkeyindex) - delkeyindex;
	//renewkey();
	key_sync_flag = true;

}

//�ӽ��ܶ�Ӧ��ϵ����
void kisync_handle(const char* encrypt_i, const char* decrypt_i, int fd) {
	encrypt_flag = atoi(decrypt_i);
	decrypt_flag = atoi(encrypt_i);
	char buf[BUFFER_SIZE];
	sprintf(buf, "kisync %d %d\n", encrypt_flag, decrypt_flag);
    printf("encrypt_flag:%d decrypt_flag:%d\n",encrypt_flag,decrypt_flag);
	send(fd, buf, strlen(buf), 0);
}

//��Կ��������ͬ��
void desync_handle(const char* key_d, int fd) {
	int tmp_keyd = atoi(key_d);
	cur_dkeyd = next_dkeyd;
	next_dkeyd = tmp_keyd;
	char buf[BUFFER_SIZE];
	sprintf(buf, "desync %d\n", next_dkeyd);
	send(fd, buf, strlen(buf), 0);
}

//��Կ����ֵͬ��
void eMsync_handle(const char* tmp_eM,const char* nextseq, int fd) {
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1 && errno == EBADF) {
        printf("fd is invalid\n");
        return;
	}

    printf("receive:%s\tnextseq:%s\n",tmp_eM,nextseq);
    int tmp_dM = atoi(tmp_eM);
    char buf[BUFFER_SIZE],rbuf[BUFFER_SIZE];
    sprintf(buf, "dMsync %d\n", tmp_dM);
	next_dM[atoi(nextseq)/WINSIZE] = tmp_dM;
    send(fd, buf, strlen(buf), 0);
    return ;
}


void* thread_function(void* arg) {
    // ���̵߳Ĵ���
	printf("This is the child thread.\n");
    int epfd, nfds, i;
    struct epoll_event events[MAX_EVENTS];
    int local_port = LOCAL_PORT; // ���ض˿�
    // ���� epoll ʵ��
    epfd = epoll_create1(0);
    if (epfd == -1) {
        perror("epoll_create1 error!\n");
        exit(1);
    }
    // ���ؼ���
    int local_lfd = init_listen_local(local_port, epfd);

    while (1) {
        nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait error!\n");
            exit(1);
        }

        for (i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            // ����������
            if (events[i].events & EPOLLIN && fd == local_lfd) {
                // �����������߼�
                printf("local_connection success!\n");
                do_crecon(local_lfd,epfd);
            }
           else if (events[i].events & EPOLLIN) {
				do_recdata_local(fd, epfd); //��Կ����ͬ���¼�
			}
			else {
				continue;
			}
        }
    }
    close(epfd);
    close(local_lfd);

    pthread_exit(NULL);
}

//���������У�˫�߳�
void epoll_run(int port) {
	pthread_t tid;
    int ret;
    // �������߳�
    ret = pthread_create(&tid, NULL, thread_function, NULL);
    if (ret != 0) {
        fprintf(stderr, "Failed to create thread.\n");
        return ;
    }
    // ���̴߳���
    printf("This is the parent thread.\n");
	int epfd1, nfds1, i;
	struct epoll_event events1[MAX_EVENTS];
	int external_port = port; // �ⲿ�˿�
	// ���� epoll ʵ��
	epfd1 = epoll_create1(0);
	if (epfd1 == -1) {
		perror("epoll_create1 error!\n");
		exit(1);
	}
	// �ⲿ����
	int external_lfd = init_listen_external(external_port, epfd1);
	while (1) {
		nfds1 = epoll_wait(epfd1, events1, MAX_EVENTS, -1);
		if (nfds1 == -1) {
			perror("epoll_wait error!\n");
			exit(1);
		}

		for (i = 0; i < nfds1; i++) {
			int fd = events1[i].data.fd;
			
			// �����ⲿ����
			if (events1[i].events & EPOLLIN && fd == external_lfd) {
				// �����ⲿ��������
				printf("\nexternal_connection success!\n");// ...
				do_crecon(external_lfd,epfd1);
			}
			else if (events1[i].events & EPOLLIN){
				do_recdata_external(fd, epfd1); //��Կͬ���¼�
				}
			else {
			continue;
			}

		}
		} 
	close(epfd1);
	close(external_lfd);
	// �ȴ����߳̽���
    pthread_join(tid, NULL);
}


// �ȽϺ�����������
int compare(const void *a, const void *b) {
    const char *strA = *(const char **)a;
    const char *strB = *(const char **)b;
	 return strcmp(strA,strB);
    // ���ļ���ת��Ϊ���ֲ����бȽ�
    // int numA = atoi(strA);
    // int numB = atoi(strB);

    // return numA - numB;
}
void readFilesInFolder(const char *folderPath,FILE* fp) {
    DIR *dir;
    struct dirent *entry;

    dir = opendir(folderPath);
    if (dir == NULL) {
        printf("\n");
        return;
    }
    //
    const int maxFiles = 1000; // 
    const int maxFileNameLength = 256; // 
    char **fileNames = (char **)malloc(maxFiles * sizeof(char *));
    int numFiles = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char filePath[maxFileNameLength];
        sprintf(filePath, "%s/%s", folderPath, entry->d_name);
        if (entry->d_type == DT_DIR) {
            readFilesInFolder(filePath,fp);
        } else {
            // 
			fileNames[numFiles] = (char *)malloc(sizeof(char)*maxFileNameLength);
            strcpy(fileNames[numFiles],entry->d_name);
            numFiles++;
        }
    }
    closedir(dir);

		//numFiles==1;
	if(numFiles<=1) 
	{	
		sleep(2);
		free(fileNames[0]);
		free(fileNames);
		return ;
	}

    // 
    qsort(fileNames, numFiles, sizeof(const char *), compare);

    // 
    for (int i = 0; i < numFiles-1; i++) {
        printf("filename:%s\n", fileNames[i]);
        char kfilePath[256]; // 
        sprintf(kfilePath, "%s/%s", folderPath,fileNames[i]);
         FILE *file = fopen(kfilePath, "r");
            if (file) {
				 char buffer[1024];
    			size_t bytesRead;
    			while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        			fwrite(buffer, 1, bytesRead, fp);
    			}
                fclose(file);
				//
				remove(kfilePath);

            }
        free(fileNames[i]);
    }

    free(fileNames);
}



//��Կд��
void keyfile_write() {
	//���ȶ����ļ�ָ�룺fp
	FILE* fp;
	printf("key supply starting...\n");
	//ģ�ⲻ��д����Կ����Կ���ļ�
	fp = fopen(KEY_FILE, "a+");
	const char *folderPath = "my_folder"; // �ļ���·��
    readFilesInFolder(folderPath,fp);
	fclose(fp);
}

int main(int argc, char* argv[]) {
	remove(KEY_FILE);
	keyfile_write();
    // //��ʼһ����Կ
    // for(int i=0;i<10;i++)
	//     keyfile_write();

	key_sync_flag = false; //��Կͬ����־����Ϊfalse
	delkeyindex = 0, keyindex = 0, sekeyindex = 0, sdkeyindex = 0;  //��ʼ����Կƫ��

	encrypt_flag = 0, decrypt_flag = 0; //��ʼ���ӽ�����Կ�ض�Ӧ��ϵ
	cur_ekeyd = INIT_KEYD;  //��ʼ����Կ��������
	next_ekeyd = INIT_KEYD;
	cur_dkeyd = INIT_KEYD;  //��ʼ����Կ��������
	next_dkeyd = INIT_KEYD;


	char buf[1024], client_ip[1024];
	if (argc < 2) {
		perror("Missing parameter\n");
		exit(1);
	}
	else if (argc < 3) {
		strcpy(remote_ip, argv[1]);
        //Ĭ�Ϸ������ⲿ�����˿�
		SERV_PORT = EXTERNAL_PORT;
	}
	else {
		strcpy(remote_ip, argv[1]);
		SERV_PORT = atoi(argv[2]);
	}

	epoll_run(SERV_PORT); //������������������ʼ������Կ����

	return 0;
}