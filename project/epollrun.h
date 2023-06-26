#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include<fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/un.h>
#include<error.h>
#include <dirent.h>
#include<math.h>

#define MAX_EVENTS 10
#define BUFFER_SIZE 1024
#define BUFFLEN 1500
#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define  LOCAL_PORT 50000 //默认服务器内部监听端口
#define  EXTERNAL_PORT 50001 //默认服务器外部监听端口
#define  MAX_KEYFILE_SIZE  40971520  //最大密钥文件大小，当密钥文件大于最大限制时，不再填充密钥 40M
#define  KEY_CREATE_RATE  12800 //密钥每秒生成长度 12kBps
#define  KEY_UNIT_SIZE    4   //密钥基本存储单位4字节
#define  KEY_RATIO       1000    //SA密钥与会话密钥的比值
#define  KEY_FILE   "keyfile.kf"   //密钥文件
#define  REMOTE_IPADDR "127.0.0.1"   //对方服务器的ip地址
#define  INIT_KEYD   10000 //初始密钥派生参数
#define  up_index  2  //派生增长因子
#define  down_index  0.1  //派生减少因子
#define  Th1  0.7   //上界
#define  Th2  0.3	//下界
#define  WINSIZE 2048 //buffer大小

// 本地监听初始化
int init_listen_local(int port, int epfd);

// 外部监听初始化
int init_listen_external(int port, int epfd);

//处理连接
void do_crecon(int fd, int epfd);

//关闭连接
void discon(int fd, int epfd);

//处理本地事件
void do_recdata_local(int fd, int epfd);

//处理外部事件
void do_recdata_external(int fd, int epfd);

//发起连接 
bool con_serv(int* fd, const char* src, int port);

//加解密密钥对应关系同步
bool key_index_sync();

//密钥同步,本地与远端服务器建立连接同步密钥偏移
bool key_sync();

//密钥派生参数协商
bool derive_sync();

//读取本地密钥
void readkey(char* const buf, const char key_type, int size);

//sa密钥请求处理
void getk_handle(const char* spi, const char* keylen, int fd);

//会话密钥请求处理
void getsk_handle(const char* spi, const char* keylen, const char* syn, const char* key_type, int fd);

//密钥块大小更新
bool updateM(int seq);

//otp密钥请求处理
void getsk_handle_otp(const char* spi,  const char* syn, const char* key_type, int fd);

//密钥偏移同步请求处理
void keysync_handle(const char* tkeyindex, const char* tsekeyindex, const char* tsdkeyindex, int fd);

//加解密对应关系处理
void kisync_handle(const char* encrypt_i, const char* decrypt_i, int fd);

//密钥派生参数同步
void desync_handle(const char* key_d, int fd);

//密钥块阈值同步
void eMsync_handle(const char* tmp_eM,const char* nextseq, int fd);

//密钥写入
void keyfile_write();
