#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<pthread.h>
#include<fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/poll.h>
#include<string.h>
#include <sys/epoll.h>
#include<error.h>
#include<errno.h>
#include <dirent.h>
#include<arpa/inet.h>
#include<math.h>




//  ����: gcc km.c -o km -g -pthread 
//���� ./km remoteip

//#define max(a,b) 
#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define  MAXS 1024  //����������
#define  BUFFLEN 1500 //buf��С
#define  DF_SERV_PORT 50000 //Ĭ�Ϸ����������˿�
#define  MAX_KEYFILE_SIZE  40960000  //�����Կ�ļ���С������Կ�ļ������������ʱ�����������Կ 40M
#define  KEY_CREATE_RATE  256000  //��Կÿ�����ɳ��� 256kbps
#define  KEY_UNIT_SIZE    4   //��Կ�����洢��λ4�ֽ�
#define  KEY_RATIO       1000    //SA��Կ��Ự��Կ�ı�ֵ
#define  KEY_FILE   "keyfile.kf"   //��Կ�ļ�
#define  TEMPKEY_FILE   "tempkeyfile.kf"   //��Կ�ļ�
#define  REMOTE_IPADDR "127.0.0.1"   //�Է���������ip��ַ
#define  INIT_KEYD   10000 //��ʼ��Կ��������
#define  up_index  2  //������������
#define  down_index  0.1  //������������
#define  Th1  0.7   //�Ͻ�
#define  Th2  0.3	//�½�

pthread_rwlock_t keywr;
bool key_sync_flag;  //��Կͬ����־
int delkeyindex, keyindex, sekeyindex, sdkeyindex;  //��Կ����������ɾ��������Կ����ʶ��ǰ��sa��Կ,������Կ��������Կ
int encrypt_flag, decrypt_flag;  //������Կ�Լ�������Կ�Ķ�Ӧ��ϵ��0��ʶ������Կ��1��ʶ������Կ
int SERV_PORT;  //�����������˿�
int cur_ekeyd, next_ekeyd, cur_dkeyd, next_dkeyd;   //��¼��ǰ����Կ������������һ����Կ��������
char  raw_ekey[64];//��¼ԭʼ������Կ
char remote_ip[32];  //��¼Զ��ip��ַ

//����OTP����Կ��ṹ��
typedef struct {
    char key[1024];
    int size;
} Keyblock;

//ָ����Կ��ĳ�ʼֵ128�ֽ�
int M=128,nextM=128;

Keyblock *ekeybuff,*dkeybuff,*olddkeybuff;

int get_line(int cfd, char* buf, int size)
{
	int i = 0;
	char c = '\0';
	int n;
	while ((i < size - 1) && (c != '\n')) {
		n = recv(cfd, &c, 1, 0);
		if (n > 0) {
			if (c == '\r') {
				n = recv(cfd, &c, 1, MSG_PEEK);
				if ((n > 0) && (c == '\n')) {
					recv(cfd, &c, 1, 0);
				}
				else {
					c = '\n';
				}
			}
			buf[i] = c;
			i++;
		}
		else {
			c = '\n';
		}
	}
	buf[i] = '\0';

	if (-1 == n)
		i = n;

	return i;
}
void discon(int fd, int epfd) {
	int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
	if (ret < 0) {
		perror("EPOLL_CTL_DEL error...\n");
		exit(1);
	}
	close(fd);

}
void do_crecon(int fd, int epfd) {
	struct sockaddr_in cli_addr;
	char cli_ip[16];
	int client_addr_size, ret;
	struct epoll_event tep;
	int ar = accept(fd, (struct sockaddr_in*)(&cli_addr), &client_addr_size);
	printf("ip address is: %s,port is: %d\n", inet_ntop(AF_INET, &cli_addr.sin_addr.s_addr, cli_ip, sizeof(cli_ip)),
		ntohs(cli_addr.sin_port));
	//����ar socket������
	int flag = fcntl(ar, F_GETFL);
	flag |= O_NONBLOCK;
	fcntl(ar, F_SETFL, flag);
	//�¼���ֵ
	tep.events = EPOLLIN | EPOLLET;
	tep.data.fd = ar;

	//�¼�����
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, ar, &tep);
	if (ret == -1) {
		perror("epoll_ctl_add error!\n");
		exit(1);
	}
}


//�������� 
void con_serv(int* fd, const char* src, int port) {
	int  ret, cr;
	struct sockaddr_in serv_addr, cli_addr;
	socklen_t client_addr_size;

	*fd = socket(AF_INET, SOCK_STREAM, 0);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(SERV_PORT);
	inet_pton(AF_INET, src, &serv_addr.sin_addr.s_addr);

	cr = connect(*fd,(struct sockaddr_in*)(&serv_addr), sizeof(serv_addr)); //���ӶԷ�������
	if (cr < 0) {
		perror("key_sync connect error!\n");
		return ;
	}
}
//�ӽ�����Կ��Ӧ��ϵͬ��
bool key_index_sync() {
	encrypt_flag = 0;
	decrypt_flag = 1;
	char buf[BUFFLEN], rbuf[BUFFLEN], kis[16];
	int fd, ret, tencrypt_index, tdecrypt_index;

	con_serv(&fd, remote_ip, SERV_PORT); //���ӶԷ�������

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
//test1

//������Կ�أ�����ɾ����Կ����
void renewkey() {
	//int delkeyindex, keyindex, sekeyindex, sdkeyindex
	int delindex; 	//Ҫɾ������Կ������
	pthread_rwlock_wrlock(&keywr); //����
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
	pthread_rwlock_unlock(&keywr); //����
}

//��Կͬ��,������Զ�˷�������������ͬ����Կƫ��
bool key_sync() {

	int fd, ret;
	char buf[BUFFLEN], rbuf[BUFFLEN], method[32];
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
	//n = get_line(fd, buf, BUFFLEN);
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
	char buf[BUFFLEN], rbuf[BUFFLEN], method[32];
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
//��ȡ������Կ
void readkey(char* const buf, const char key_type, const char* keylen) {
	int len = atoi(keylen);
	char* pb = buf;
	pthread_rwlock_rdlock(&keywr);  //�϶���
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
					fgets(pb, KEY_UNIT_SIZE + 1, fp);
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
					fgets(pb, KEY_UNIT_SIZE + 1, fp);
					i++;
					pb += KEY_UNIT_SIZE;
				}
				sdkeyindex++;
			}
			rewind(fp);
		}
		else { //sa��Կ��Ԥ�ȹ�����Կ
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
	pthread_rwlock_unlock(&keywr); //����
}

//��ȡ������Կ
void readkey_otp(char* const buf, const char key_type, int size) {
	int len = size;
	char* pb = buf;
	pthread_rwlock_rdlock(&keywr);  //�϶���
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
					fgets(pb, KEY_UNIT_SIZE + 1, fp);
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
					fgets(pb, KEY_UNIT_SIZE + 1, fp);
					i++;
					pb += KEY_UNIT_SIZE;
				}
				sdkeyindex++;
			}
			rewind(fp);
		}
	}
	fclose(fp);
	pthread_rwlock_unlock(&keywr); //����
}

//������Կ����
// void derive_key(char* const buf, const char* raw_key, const char* syn) {
// 	strcpy(buf, raw_key);
// 	//strcat(buf, syn);
// 	//unsigned char sha1[SHA_DIGEST_LENGTH];
// 	//SHA1(buf, strlen(buf), sha1);
// 	//strcpy(buf, sha1);

// 	/*
// 	char* p1 = buf, * p2 = syn;
// 	while (*p1 != ' ' && *p2 != ' ') {
// 		*p1 = *p1 ^ *p2;
// 		p1++;
// 		p2++;
// 	}
// 	*/

// 	//strcat(buf, syn);
// }


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

	char buf[atoi(keylen)];
	//��ȡ��Կ
	readkey(buf, '2', keylen);
	send(fd, buf, atoi(keylen), 0);
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
	//static ekey_lw, ekey_rw, dkey_lw, dkey_rw, olddkey_lw, olddkey_rw;
	
	char buf[BUFFLEN];
	if (*key_type == '0') {
		bool ret = derive_sync(); //��������ͬ��
		if (!ret) {
			perror("derive_sync error!\n");
			return;
		}
		readkey(raw_ekey, *key_type, keylen); //��ȡ��Կ
		printf("qkey:%s kdp:%d sei:%d sdi:%d \n", raw_ekey, cur_ekeyd, sekeyindex, sdkeyindex);
		sprintf(buf, "%s %d\n", raw_ekey, cur_ekeyd);
	}
	else {
		readkey(raw_ekey, *key_type, keylen); //��ȡ��Կ
		printf("qkey:%s kdp:%d sei:%d sdi:%d \n", raw_ekey, cur_ekeyd, sekeyindex, sdkeyindex);
		sprintf(buf, "%s %d\n", raw_ekey, cur_dkeyd);
	}
	
	
	send(fd, buf, strlen(buf), 0);
}


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
	static int  ekey_rw=0, dkey_lw=1, dkey_rw=1024, olddkey_lw;
	char buf[BUFFLEN];
	//��ȡ��Կ
	if (*key_type == '0') {  //������Կ
		if (seq == 1 || seq > ekey_rw) {  //�����û�г�ʼ����Կ���߳�����Կ����Χ��Ҫ����ԭʼ��Կ�Լ�syn����
			if(ekeybuff!=NULL) free(ekeybuff);
			ekeybuff=(Keyblock *) malloc(1024*sizeof(Keyblock));
			M=nextM;
			for(int i=0;i<1024;i++){
				readkey_otp(ekeybuff[i].key, *key_type, M);
				ekeybuff[i].size=M;
			}
			//���´���
			if(seq > ekey_rw){
				ekey_rw = ekey_rw + 1024;
			}
		}
		printf("qkey:%s size:%d", ekeybuff[(seq-1)%1024].key, ekeybuff[(seq-1)%1024].size);
		sprintf(buf, "%s %d\n", ekeybuff[(seq-1)%1024].key, ekeybuff[(seq-1)%1024].size);
	}
	else {  //������Կ:���ڽ�����Կά��һ������Կ�Ĵ������ݴ��ȥ����Կ��Ӧ��ʧ�����
		if (seq == 1 || seq > dkey_rw) {  //�����û�г�ʼ����Կ���߳�����Կ����Χ��Ҫ����ԭʼ��Կ�Լ�syn����,Э���µ���Կ��������
			if(olddkeybuff!=NULL) free(olddkeybuff);
			olddkeybuff=dkeybuff;
			dkeybuff=(Keyblock *) malloc(1024*sizeof(Keyblock));
			M=nextM;
			for(int i=0;i<1024;i++){
				readkey_otp(dkeybuff[i].key, *key_type, M);
				dkeybuff[i].size=M;
			}
			//��Կ��������Э��
			//���´���
			if(seq > dkey_rw){
			olddkey_lw = dkey_lw;
			dkey_lw = dkey_rw+1;
			dkey_rw = dkey_rw + 1024;
			}

		}

		if (seq < dkey_lw) {
			printf("qkey:%s size:%d", olddkeybuff[(seq-1)%1024].key, olddkeybuff[(seq-1)%1024].size);
			sprintf(buf, "%s %d\n", olddkeybuff[(seq-1)%1024].key, olddkeybuff[(seq-1)%1024].size);
		}
		
		else if (seq >= dkey_lw && seq <= dkey_rw) {
			printf("qkey:%s size:%d", dkeybuff[(seq-1)%1024].key, dkeybuff[(seq-1)%1024].size);
			sprintf(buf, "%s %d\n", dkeybuff[(seq-1)%1024].key, dkeybuff[(seq-1)%1024].size);
		}
	}
	send(fd, buf, strlen(buf), 0);
}


void keysync_handle(const char* tkeyindex, const char* tsekeyindex, const char* tsdkeyindex, int fd) {

	char buf[BUFFLEN];
	sprintf(buf, "keysync %d %d %d\n", keyindex + delkeyindex, sekeyindex + delkeyindex, sdkeyindex + delkeyindex);
	send(fd, buf, BUFFLEN, 0);
	keyindex = max(atoi(tkeyindex), keyindex + delkeyindex) - delkeyindex;		//�޸�
	sekeyindex = max(atoi(tsdkeyindex), sekeyindex + delkeyindex) - delkeyindex;
	sdkeyindex = max(atoi(tsekeyindex), sdkeyindex + delkeyindex) - delkeyindex;
	//renewkey();
	key_sync_flag = true;

}
void kisync_handle(const char* encrypt_i, const char* decrypt_i, int fd) {
	encrypt_flag = atoi(decrypt_i);
	decrypt_flag = atoi(encrypt_i);
	char buf[BUFFLEN];
	sprintf(buf, "kisync %d %d\n", encrypt_flag, decrypt_flag);
	send(fd, buf, strlen(buf), 0);

}

void desync_handle(const char* key_d, int fd) {
	int tmp_keyd = atoi(key_d);
	cur_dkeyd = next_dkeyd;
	next_dkeyd = tmp_keyd;
	char buf[BUFFLEN];
	sprintf(buf, "desync %d\n", next_dkeyd);
	send(fd, buf, strlen(buf), 0);
}
void do_recdata(int fd, int epfd) {
	char buf[BUFFLEN], path[BUFFLEN];
	int n = get_line(fd, buf, BUFFLEN);
	if (n < 0) {
		perror("getline error\n");
		exit(1);
	}
	else if (n == 0) {
		printf("client closed...\n");
		discon(fd, epfd);
	}
	else {


		uint8_t method[32] = {}, path[256] = {}, protocol[16] = {}, arg1[64] = {}, arg2[64] = {}, arg3[64] = {}, arg4[64] = {};
		int key_type;
		sscanf(buf, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", method, arg1, arg2, arg3, arg4);
		//��Ӧ��getk   arg1==spi, arg2=keylen(�ֽ�)
		//��Ӧ��getsk  arg1==spi, arg2=keylen(�ֽ�), arg3=syn,arg4=keytype
		//��Ӧ��getskotp  arg1==spi, arg2=syn,arg3=keytype
		//��Ӧ��keysync  arg1=keyindex, arg2=sekeyindex,arg3=sdkeyindex
		//��Ӧ��key_index_sync arg1==encrypt_index, arg2==decrypt_index
		//��Ӧ��derive_sync  arg1==key_d
		printf("recieve:%s %s %s %s %s\n", method, arg1, arg2, arg3, arg4);
		while (1)
		{
			n = get_line(fd, buf, BUFFLEN);
			if (n == 0) {
				discon(fd, epfd);
			}
			if (n == '\n') {
				break;
			}
			else if (n == -1)
			{
				break;
			}
		}
		if (strncasecmp(method, "getk", 4) == 0) {
			//char* p = path + 1;
			getk_handle(arg1, arg2, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "getotpk", 7) == 0) {
			getsk_handle_otp(arg1, arg2, arg3, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "getsk", 5) == 0) {
			getsk_handle(arg1, arg2, arg3, arg4, fd);
			discon(fd, epfd);
		}
		else if (strncasecmp(method, "keysync", 7) == 0) {
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

	}


}
int init_listen(int port, int epfd) {
	int lfd, ret;
	struct epoll_event tep;
	struct sockaddr_in serv_addr;
	socklen_t client_addr_size;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	inet_pton(AF_INET, "0.0.0.0", &serv_addr.sin_addr.s_addr);
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) {
		perror("socket create error!\n");
		exit(1);
	}
	//�˿ڸ���
	int opt = 1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	int br = bind(lfd, (struct sockaddr_in*)&serv_addr, sizeof(serv_addr));
	if (br < 0) {
		perror("bind error!\n");
		exit(1);
	}
	//listen����
	listen(lfd, 128);
	//��Ӽ����¼�����
	tep.events = EPOLLIN;
	tep.data.fd = lfd;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &tep);
	if (ret == -1) {
		perror("epoll_ctl_add error!\n");
		exit(1);
	}
	return lfd;
}
void epoll_run(int port) {
	int epfd, lfd, ret, i;
	struct epoll_event ep[MAXS];
	epfd = epoll_create(MAXS);
	lfd = init_listen(port, epfd);

	while (1) {
		ret = epoll_wait(epfd, ep, MAXS, -1);

		if (ret < 0) {
			perror("epoll_wait error!\n");
			exit(1);
		}
		for (i = 0; i < ret; i++) {
			if (ep[i].events & EPOLLIN && ep[i].data.fd == lfd) {
				do_crecon(lfd, epfd);  //�½������¼�
			}
			else if (ep[i].events & EPOLLIN) {
				do_recdata(ep[i].data.fd, epfd); //��Կ����ͬ���¼�
			}
			else {
				continue;
			}
		}
	}

}
//�ַ�ת��
char transform(int i) {
	if (i < 10) {
		return i + '0';
	}
	else if (i == 10) {
		return 'a';
	}
	else if (i == 11) {
		return 'b';
	}
	else if (i == 12) {
		return 'c';
	}
	else if (i == 13) {
		return 'd';
	}
	else if (i == 14) {
		return 'e';
	}
	else {
		return 'f';
	}
}
//��Կд���߳�
void* thread_write() {
	//���ȶ����ļ�ָ�룺fp
	FILE* fp;
	remove(KEY_FILE);
	printf("key supply starting...\n");
	//ģ�ⲻ��д����Կ����Կ���ļ�
	while (1) {
		char buf[KEY_CREATE_RATE];
		int i = 0;
		srand((unsigned int)time(NULL));
		for (; i < KEY_CREATE_RATE; i++) { //����γ���Կ��
			//srand((unsigned int)time(NULL));
			int ret = i % 16;
			buf[i] = transform(ret);
		}
		//renewkey();  �Ȳ����Ǹ�����Կ��
		pthread_rwlock_wrlock(&keywr); //����
		fp = fopen(KEY_FILE, "a+");
		fseek(fp, 0, SEEK_END); //��λ���ļ�ĩ 
		int nFileLen = ftell(fp); //�ļ�����
		fseek(fp, 0, SEEK_SET); //�ָ����ļ�ͷ
		//�ж��ļ���С�����ļ������趨��ֵ����д��
		if (nFileLen < MAX_KEYFILE_SIZE) {
			fputs(buf, fp);
			//printf("%s\n", buf);
		}
		fclose(fp);
		pthread_rwlock_unlock(&keywr); //����

		sleep(1); //�ȴ�1s
	}

	pthread_exit(0);
}
int main(int argc, char* argv[]) {

	key_sync_flag = false; //��Կͬ����־����Ϊfalse
	delkeyindex = 0, keyindex = 0, sekeyindex = 0, sdkeyindex = 0;  //��ʼ����Կƫ��
	pthread_rwlock_init(&keywr, NULL); //��ʼ����д��
	encrypt_flag = 0, decrypt_flag = 0; //��ʼ���ӽ�����Կ�ض�Ӧ��ϵ
	cur_ekeyd = INIT_KEYD;  //��ʼ����Կ��������
	next_ekeyd = INIT_KEYD;
	cur_dkeyd = INIT_KEYD;  //��ʼ����Կ��������
	next_dkeyd = INIT_KEYD;
	//raw_ekey = NULL, prived_ekey = NULL;  //��ʼ��������Կ

	int fd, ar, ret, count = 0, n, i, epfd;
	struct epoll_event tep, ep[MAXS];
	pthread_t tid, pid;
	char buf[1024], client_ip[1024];
	if (argc < 2) {
		perror("Missing parameter\n");
		exit(1);
		//Ĭ�Ϸ����������˿�
		SERV_PORT = DF_SERV_PORT;
	}
	else if (argc < 3) {
		strcpy(remote_ip, argv[1]);
		SERV_PORT = DF_SERV_PORT;

	}
	else {
		strcpy(remote_ip, argv[1]);
		SERV_PORT = atoi(argv[2]);
	}

	pthread_create(&tid, NULL, thread_write, NULL);  //��Կд���߳�����
	pthread_detach(tid); //�̷߳���

	epoll_run(SERV_PORT); //������������������ʼ������Կ����

	pthread_rwlock_destroy(&keywr); //���ٶ�д��
	return 0;
}