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




//  编译: gcc km.c -o km -g -pthread 
//运行 ./km remoteip

//#define max(a,b) 
#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define  MAXS 1024  //最大监听数量
#define  BUFFLEN 1500 //buf大小
#define  DF_SERV_PORT 50000 //默认服务器监听端口
#define  MAX_KEYFILE_SIZE  40960000  //最大密钥文件大小，当密钥文件大于最大限制时，不再填充密钥 40M
#define  KEY_CREATE_RATE  256000  //密钥每秒生成长度 256kbps
#define  KEY_UNIT_SIZE    4   //密钥基本存储单位4字节
#define  KEY_RATIO       1000    //SA密钥与会话密钥的比值
#define  KEY_FILE   "keyfile.kf"   //密钥文件
#define  TEMPKEY_FILE   "tempkeyfile.kf"   //密钥文件
#define  REMOTE_IPADDR "127.0.0.1"   //对方服务器的ip地址
#define  INIT_KEYD   10000 //初始密钥派生参数
#define  up_index  2  //派生增长因子
#define  down_index  0.1  //派生减少因子
#define  Th1  0.7   //上界
#define  Th2  0.3	//下界

pthread_rwlock_t keywr;
bool key_sync_flag;  //密钥同步标志
int delkeyindex, keyindex, sekeyindex, sdkeyindex;  //密钥索引，用于删除过期密钥，标识当前的sa密钥,加密密钥，解密密钥
int encrypt_flag, decrypt_flag;  //加密密钥以及解密密钥的对应关系，0标识加密密钥，1标识解密密钥
int SERV_PORT;  //服务器监听端口
int cur_ekeyd, next_ekeyd, cur_dkeyd, next_dkeyd;   //记录当前的密钥派生参数和下一个密钥派生参数
char  raw_ekey[64];//记录原始量子密钥
char remote_ip[32];  //记录远程ip地址

//用于OTP的密钥块结构体
typedef struct {
    char key[1024];
    int size;
} Keyblock;

//指定密钥块的初始值128字节
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
	//设置ar socket非阻塞
	int flag = fcntl(ar, F_GETFL);
	flag |= O_NONBLOCK;
	fcntl(ar, F_SETFL, flag);
	//事件赋值
	tep.events = EPOLLIN | EPOLLET;
	tep.data.fd = ar;

	//事件上树
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, ar, &tep);
	if (ret == -1) {
		perror("epoll_ctl_add error!\n");
		exit(1);
	}
}


//发起连接 
void con_serv(int* fd, const char* src, int port) {
	int  ret, cr;
	struct sockaddr_in serv_addr, cli_addr;
	socklen_t client_addr_size;

	*fd = socket(AF_INET, SOCK_STREAM, 0);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(SERV_PORT);
	inet_pton(AF_INET, src, &serv_addr.sin_addr.s_addr);

	cr = connect(*fd,(struct sockaddr_in*)(&serv_addr), sizeof(serv_addr)); //连接对方服务器
	if (cr < 0) {
		perror("key_sync connect error!\n");
		return ;
	}
}
//加解密密钥对应关系同步
bool key_index_sync() {
	encrypt_flag = 0;
	decrypt_flag = 1;
	char buf[BUFFLEN], rbuf[BUFFLEN], kis[16];
	int fd, ret, tencrypt_index, tdecrypt_index;

	con_serv(&fd, remote_ip, SERV_PORT); //连接对方服务器

	sprintf(buf, "kisync %d %d\n", encrypt_flag, decrypt_flag);
	send(fd, buf, strlen(buf), 0);

	ret = read(fd, rbuf, sizeof(rbuf));
	sscanf(rbuf, "%[^ ] %d %d", kis, &tencrypt_index, &tdecrypt_index); //scanf("%[^\n] ", s); 输入一行，回车作为结束符。 行末回车符不处理; %[^ ]表示除了空格都可以读
	close(fd);
	if (tencrypt_index == decrypt_flag && tdecrypt_index == encrypt_flag) {
		//close(fd);
		return true;
	}

	return false;
}
//test1

//更新密钥池，更新删除密钥索引
void renewkey() {
	//int delkeyindex, keyindex, sekeyindex, sdkeyindex
	int delindex; 	//要删除的密钥的索引
	pthread_rwlock_wrlock(&keywr); //上锁
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
		fseek(fp, delindex * KEY_UNIT_SIZE, SEEK_SET); //文件指针偏移到指定位置
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
	pthread_rwlock_unlock(&keywr); //解锁
}

//密钥同步,本地与远端服务器建立连接同步密钥偏移
bool key_sync() {

	int fd, ret;
	char buf[BUFFLEN], rbuf[BUFFLEN], method[32];
	//struct sockaddr_in serv_addr, cli_addr;
	//socklen_t client_addr_size;
	sprintf(buf, "keysync di:%d ei:%d di:%d\n", keyindex + delkeyindex, sekeyindex + delkeyindex, sdkeyindex + delkeyindex);


	con_serv(&fd, remote_ip, SERV_PORT); //连接对方服务器


	ret = send(fd, buf, strlen(buf), 0);
	if (ret < 0) {
		perror("key_sync connect error!\n");
		return false;
	}
	ret = read(fd, rbuf, sizeof(rbuf));
	//n = get_line(fd, buf, BUFFLEN);
	int tkeyindex, tsekeyindex, tsdkeyindex;
	sscanf(rbuf, "%[^ ] %d %d %d", method, &tkeyindex, &tsekeyindex, &tsdkeyindex);		//修改
	keyindex = max(tkeyindex, keyindex + delkeyindex) - delkeyindex;
	sekeyindex = max(tsdkeyindex, sekeyindex + delkeyindex) - delkeyindex;
	sdkeyindex = max(tsekeyindex, sdkeyindex + delkeyindex) - delkeyindex;

	//renewkey();
	close(fd);
	key_sync_flag = true;
	return true;
}




//密钥派生参数协商
bool derive_sync() {
	int fd, ret, tmp_keyd;
	char buf[BUFFLEN], rbuf[BUFFLEN], method[32];
	//通过密钥余量判断接下来的密钥派生参数
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

	con_serv(&fd, remote_ip, SERV_PORT); //连接对方服务器
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
//读取本地密钥
void readkey(char* const buf, const char key_type, const char* keylen) {
	int len = atoi(keylen);
	char* pb = buf;
	pthread_rwlock_rdlock(&keywr);  //上读锁
	FILE* fp = fopen(KEY_FILE, "r");
	if (fp == NULL) {
		perror("open keyfile error!\n");
		exit(1);
	}
	else {
		if (key_type == '0') {  //加密密钥
			//fseek(fp, sekeyindex * KEY_UNIT_SIZE, SEEK_SET); //文件指针偏移到指定位置
			int i = 0;
			while (i * KEY_UNIT_SIZE < len) {
				//这里加上删除密钥索引
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
		else if (key_type == '1') {  //解密密钥
			//fseek(fp, sdkeyindex * KEY_UNIT_SIZE, SEEK_SET); //文件指针偏移到指定位置
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
		else { //sa密钥和预先共享密钥
			//fseek(fp, keyindex * KEY_UNIT_SIZE, SEEK_SET); //文件指针偏移到指定位置
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
	pthread_rwlock_unlock(&keywr); //解锁
}

//读取本地密钥
void readkey_otp(char* const buf, const char key_type, int size) {
	int len = size;
	char* pb = buf;
	pthread_rwlock_rdlock(&keywr);  //上读锁
	FILE* fp = fopen(KEY_FILE, "r");
	if (fp == NULL) {
		perror("open keyfile error!\n");
		exit(1);
	}
	else {
		if (key_type == '0') {  //加密密钥
			//fseek(fp, sekeyindex * KEY_UNIT_SIZE, SEEK_SET); //文件指针偏移到指定位置
			int i = 0;
			while (i * KEY_UNIT_SIZE < len) {
				//这里加上删除密钥索引
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
		else if (key_type == '1') {  //解密密钥
			//fseek(fp, sdkeyindex * KEY_UNIT_SIZE, SEEK_SET); //文件指针偏移到指定位置
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
	pthread_rwlock_unlock(&keywr); //解锁
}

//派生密钥函数
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


//sa密钥请求处理
void getk_handle(const char* spi, const char* keylen, int fd) {
	//判断是否已经同步，如果没有同步，首先进行双方同步
	if (!key_sync_flag) {
		bool ret = key_sync();
		if (!ret) {
			perror("key_sync error!\n");
			return;
		}
	}

	char buf[atoi(keylen)];
	//读取密钥
	readkey(buf, '2', keylen);
	send(fd, buf, atoi(keylen), 0);
	key_sync_flag = true;

}

//会话密钥请求处理
//目前窗口放在strongswan里，超过窗口大小时才调用处理函数，减少通信
void getsk_handle(const char* spi, const char* keylen, const char* syn, const char* key_type, int fd) {
	//如果双方没有同步加解密密钥池对应关系则首先进行同步
	int range = 0;
	if (!(encrypt_flag ^ decrypt_flag)) {
		bool ret = key_index_sync();
		if (!ret) {
			perror("key_index_sync error！\n");
			return;
		}
	}
	//判断syn是否为1，是则进行同步，否则不需要同步,同时接收方的key_sync_flag会被设置为true，避免二次同步
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
		bool ret = derive_sync(); //派生参数同步
		if (!ret) {
			perror("derive_sync error!\n");
			return;
		}
		readkey(raw_ekey, *key_type, keylen); //读取密钥
		printf("qkey:%s kdp:%d sei:%d sdi:%d \n", raw_ekey, cur_ekeyd, sekeyindex, sdkeyindex);
		sprintf(buf, "%s %d\n", raw_ekey, cur_ekeyd);
	}
	else {
		readkey(raw_ekey, *key_type, keylen); //读取密钥
		printf("qkey:%s kdp:%d sei:%d sdi:%d \n", raw_ekey, cur_ekeyd, sekeyindex, sdkeyindex);
		sprintf(buf, "%s %d\n", raw_ekey, cur_dkeyd);
	}
	
	
	send(fd, buf, strlen(buf), 0);
}


void getsk_handle_otp(const char* spi,  const char* syn, const char* key_type, int fd) {
	int seq=atoi(syn);
	//如果双方没有同步加解密密钥池对应关系则首先进行同步
	if (!(encrypt_flag ^ decrypt_flag)) {
		bool ret = key_index_sync();
		if (!ret) {
			perror("key_index_sync error！\n");
			return;
		}
	}
	//判断syn是否为1，是则进行同步，否则不需要同步,同时接收方的key_sync_flag会被设置为true，避免二次同步
	if (seq == 1 && !key_sync_flag) {
		bool ret = key_sync();
		if (!ret) {
			perror("key_sync error!\n");
			return;
		}
	}
	static int  ekey_rw=0, dkey_lw=1, dkey_rw=1024, olddkey_lw;
	char buf[BUFFLEN];
	//读取密钥
	if (*key_type == '0') {  //加密密钥
		if (seq == 1 || seq > ekey_rw) {  //如果还没有初始的密钥或者超出密钥服务范围需要更新原始密钥以及syn窗口
			if(ekeybuff!=NULL) free(ekeybuff);
			ekeybuff=(Keyblock *) malloc(1024*sizeof(Keyblock));
			M=nextM;
			for(int i=0;i<1024;i++){
				readkey_otp(ekeybuff[i].key, *key_type, M);
				ekeybuff[i].size=M;
			}
			//更新窗口
			if(seq > ekey_rw){
				ekey_rw = ekey_rw + 1024;
			}
		}
		printf("qkey:%s size:%d", ekeybuff[(seq-1)%1024].key, ekeybuff[(seq-1)%1024].size);
		sprintf(buf, "%s %d\n", ekeybuff[(seq-1)%1024].key, ekeybuff[(seq-1)%1024].size);
	}
	else {  //解密密钥:对于解密密钥维护一个旧密钥的窗口来暂存过去的密钥以应对失序包。
		if (seq == 1 || seq > dkey_rw) {  //如果还没有初始的密钥或者超出密钥服务范围需要更新原始密钥以及syn窗口,协商新的密钥派生参数
			if(olddkeybuff!=NULL) free(olddkeybuff);
			olddkeybuff=dkeybuff;
			dkeybuff=(Keyblock *) malloc(1024*sizeof(Keyblock));
			M=nextM;
			for(int i=0;i<1024;i++){
				readkey_otp(dkeybuff[i].key, *key_type, M);
				dkeybuff[i].size=M;
			}
			//密钥派生参数协商
			//更新窗口
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
	keyindex = max(atoi(tkeyindex), keyindex + delkeyindex) - delkeyindex;		//修改
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
		//对应于getk   arg1==spi, arg2=keylen(字节)
		//对应于getsk  arg1==spi, arg2=keylen(字节), arg3=syn,arg4=keytype
		//对应于getskotp  arg1==spi, arg2=syn,arg3=keytype
		//对应于keysync  arg1=keyindex, arg2=sekeyindex,arg3=sdkeyindex
		//对应于key_index_sync arg1==encrypt_index, arg2==decrypt_index
		//对应于derive_sync  arg1==key_d
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
	//端口复用
	int opt = 1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	int br = bind(lfd, (struct sockaddr_in*)&serv_addr, sizeof(serv_addr));
	if (br < 0) {
		perror("bind error!\n");
		exit(1);
	}
	//listen上限
	listen(lfd, 128);
	//添加监听事件上树
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
				do_crecon(lfd, epfd);  //新建连接事件
			}
			else if (ep[i].events & EPOLLIN) {
				do_recdata(ep[i].data.fd, epfd); //密钥请求及同步事件
			}
			else {
				continue;
			}
		}
	}

}
//字符转换
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
//密钥写入线程
void* thread_write() {
	//首先定义文件指针：fp
	FILE* fp;
	remove(KEY_FILE);
	printf("key supply starting...\n");
	//模拟不断写入密钥到密钥池文件
	while (1) {
		char buf[KEY_CREATE_RATE];
		int i = 0;
		srand((unsigned int)time(NULL));
		for (; i < KEY_CREATE_RATE; i++) { //随机形成密钥串
			//srand((unsigned int)time(NULL));
			int ret = i % 16;
			buf[i] = transform(ret);
		}
		//renewkey();  先不考虑更新密钥池
		pthread_rwlock_wrlock(&keywr); //上锁
		fp = fopen(KEY_FILE, "a+");
		fseek(fp, 0, SEEK_END); //定位到文件末 
		int nFileLen = ftell(fp); //文件长度
		fseek(fp, 0, SEEK_SET); //恢复到文件头
		//判断文件大小，若文件大于设定的值则不再写入
		if (nFileLen < MAX_KEYFILE_SIZE) {
			fputs(buf, fp);
			//printf("%s\n", buf);
		}
		fclose(fp);
		pthread_rwlock_unlock(&keywr); //解锁

		sleep(1); //等待1s
	}

	pthread_exit(0);
}
int main(int argc, char* argv[]) {

	key_sync_flag = false; //密钥同步标志设置为false
	delkeyindex = 0, keyindex = 0, sekeyindex = 0, sdkeyindex = 0;  //初始化密钥偏移
	pthread_rwlock_init(&keywr, NULL); //初始化读写锁
	encrypt_flag = 0, decrypt_flag = 0; //初始化加解密密钥池对应关系
	cur_ekeyd = INIT_KEYD;  //初始化密钥派生参数
	next_ekeyd = INIT_KEYD;
	cur_dkeyd = INIT_KEYD;  //初始化密钥派生参数
	next_dkeyd = INIT_KEYD;
	//raw_ekey = NULL, prived_ekey = NULL;  //初始化加密密钥

	int fd, ar, ret, count = 0, n, i, epfd;
	struct epoll_event tep, ep[MAXS];
	pthread_t tid, pid;
	char buf[1024], client_ip[1024];
	if (argc < 2) {
		perror("Missing parameter\n");
		exit(1);
		//默认服务器监听端口
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

	pthread_create(&tid, NULL, thread_write, NULL);  //密钥写入线程启动
	pthread_detach(tid); //线程分离

	epoll_run(SERV_PORT); //启动监听服务器，开始监听密钥请求

	pthread_rwlock_destroy(&keywr); //销毁读写锁
	return 0;
}