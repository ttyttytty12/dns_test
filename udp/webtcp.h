#ifndef __WEBTCP_H__
#define __WEBTCP_H__ 1
#include<stdio.h> 
#include<string.h> 
#include<ctype.h> 
#include<stdlib.h> 
#include<unistd.h> 
#include<sys/types.h> 
#include<sys/wait.h> 
#include<sys/select.h> 
#include<sys/time.h> 
#include<sys/socket.h> 
#include<sys/stat.h> 
#include<sys/mman.h> 
#include<netinet/in.h> 
#include<arpa/inet.h> 
#include<netdb.h> 
#include<fcntl.h> 
#include<netinet/tcp.h> 
#include<errno.h> 
#include<signal.h> 
#include<ftw.h> 
#include<dirent.h> 
#include<stdarg.h> 
/*IPC USED*/ 
#include<sys/ipc.h> 
#include<sys/msg.h> 
#include<sys/shm.h>
/*gethostip*/
char *gethostip();
int webconnect(char* port, char *address);
#include <netinet/in_systm.h> 
#include <netinet/ip.h> 
#include <netinet/ip_icmp.h> 
#include <linux/if_ether.h> 
#include <linux/if.h> 
#include <linux/sockios.h> 
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> 
#include <netinet/in.h> 
#define ARPHRD_ETHER 1
/*定义IP头结构,基本长度为20字节 */
typedef struct TAG_IPHEAD {
	unsigned char ipvar; //版本号及ip包头长度/4 
	unsigned char iprequ; //服务类型 
	unsigned short hdlen; //数据包的长度 
	unsigned short id; //本包的标志字节 
	unsigned short off; //分段标志及偏移 
	unsigned char ttl; //包的生存时间 
	unsigned char prototype; //协议类型 
	unsigned short cksum; //整个数据包的校验和 
	unsigned int sip; //源ip地址 
	unsigned int dip; //目标IP地址 
}tag_iphead;
/*定义icmp头的结构：基本长度4字节*/ 
typedef struct TAG_ICMPHD {
	unsigned char itype; //类型 
	unsigned char icode; //代码 
	unsigned short icksum; //检验和 
	unsigned short se1; 
	unsigned short se2; 
}tag_icmphd;
/*定义udp伪头部的结构：基本长度12字节 */
typedef struct TAG_TSDUDPHD {
	unsigned int sip; //源IP 
	unsigned int dip; //目的IP 
	unsigned char mzd; //无意义，置0 
	unsigned char prototype; //协议类型： 17 
	unsigned short udphdlen; //UDP头长度 
}tag_tsdudphd;
/*定义udp的头结构：基本长度8字节，自定义数据区长度为8字节，共计16字节*/ 
typedef struct TAG_UDPHD {
	unsigned short sprot; //源端口 
	unsigned short dprot; //目的端口 
	unsigned short len; //udp长度 
	unsigned short cksum; //udp校验和，包括伪头部 
	/* unsigned int data1; //自定义数据 */
	/*unsigned int data2; //自定义数据 */
}tag_udphd;
/*定义的TCP伪头部结构：基本长度12字节 */
typedef struct TAG_TSDTCPHD {
	unsigned int sip; //源IP 
	unsigned int dip; //目的IP 
	unsigned char mzd; //无意义，置0 
	unsigned char prototype; //协议类型：TCP为6 
	unsigned short tcphdlen; //TCP头长度 
}tag_tsdtcphd;
/*定义的TCP头部结构：基本长度20字节*/ 
typedef struct TAG_TCPHD {
	unsigned short sprot; //源端口 
	unsigned short dprot; //目的端口 
	unsigned int squ; //32位序列号 
	unsigned int ack; //32位确认号 
	unsigned char tlen; //前4bit为tcp头长度（实际字节数/4，基本20字节时该值=5），后4bit保留 
	unsigned char tflag; //标志位在低6bit中, 
	unsigned short twin; //滑动窗口大小 
	unsigned short cksum; //校验和 
	unsigned short upoint; //紧急指针 
}tag_tcphd;

#endif
