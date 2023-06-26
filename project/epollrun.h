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
#define  LOCAL_PORT 50000 //Ĭ�Ϸ������ڲ������˿�
#define  EXTERNAL_PORT 50001 //Ĭ�Ϸ������ⲿ�����˿�
#define  MAX_KEYFILE_SIZE  40971520  //�����Կ�ļ���С������Կ�ļ������������ʱ�����������Կ 40M
#define  KEY_CREATE_RATE  12800 //��Կÿ�����ɳ��� 12kBps
#define  KEY_UNIT_SIZE    4   //��Կ�����洢��λ4�ֽ�
#define  KEY_RATIO       1000    //SA��Կ��Ự��Կ�ı�ֵ
#define  KEY_FILE   "keyfile.kf"   //��Կ�ļ�
#define  REMOTE_IPADDR "127.0.0.1"   //�Է���������ip��ַ
#define  INIT_KEYD   10000 //��ʼ��Կ��������
#define  up_index  2  //������������
#define  down_index  0.1  //������������
#define  Th1  0.7   //�Ͻ�
#define  Th2  0.3	//�½�
#define  WINSIZE 2048 //buffer��С

// ���ؼ�����ʼ��
int init_listen_local(int port, int epfd);

// �ⲿ������ʼ��
int init_listen_external(int port, int epfd);

//��������
void do_crecon(int fd, int epfd);

//�ر�����
void discon(int fd, int epfd);

//�������¼�
void do_recdata_local(int fd, int epfd);

//�����ⲿ�¼�
void do_recdata_external(int fd, int epfd);

//�������� 
bool con_serv(int* fd, const char* src, int port);

//�ӽ�����Կ��Ӧ��ϵͬ��
bool key_index_sync();

//��Կͬ��,������Զ�˷�������������ͬ����Կƫ��
bool key_sync();

//��Կ��������Э��
bool derive_sync();

//��ȡ������Կ
void readkey(char* const buf, const char key_type, int size);

//sa��Կ������
void getk_handle(const char* spi, const char* keylen, int fd);

//�Ự��Կ������
void getsk_handle(const char* spi, const char* keylen, const char* syn, const char* key_type, int fd);

//��Կ���С����
bool updateM(int seq);

//otp��Կ������
void getsk_handle_otp(const char* spi,  const char* syn, const char* key_type, int fd);

//��Կƫ��ͬ��������
void keysync_handle(const char* tkeyindex, const char* tsekeyindex, const char* tsdkeyindex, int fd);

//�ӽ��ܶ�Ӧ��ϵ����
void kisync_handle(const char* encrypt_i, const char* decrypt_i, int fd);

//��Կ��������ͬ��
void desync_handle(const char* key_d, int fd);

//��Կ����ֵͬ��
void eMsync_handle(const char* tmp_eM,const char* nextseq, int fd);

//��Կд��
void keyfile_write();
