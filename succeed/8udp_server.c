#include <stdio.h> /* These are the usual header files */
#include <string.h>
#include <unistd.h> /* for close() */
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/nameser_compat.h>
#include <pthread.h>
#define PORT 53 /* Port that will be opened */
#define MAXDATASIZE 100 /* Max number of bytes of data */

struct dnsheader {
	unsigned id:16;		/*%< query identification number */
#if BYTE_ORDER == BIG_ENDIAN
	/* fields in third byte */
	unsigned qr:1;		/*%< response flag */
	unsigned opcode:4;		/*%< purpose of message */
	unsigned aa:1;		/*%< authoritive answer */
	unsigned tc:1;		/*%< truncated message */
	unsigned rd:1;		/*%< recursion desired */
	/* fields in fourth byte */
	unsigned ra:1;		/*%< recursion available */
	unsigned unused:1;		/*%< unused bits (MBZ as of 4.9.3a3) */
	unsigned ad:1;		/*%< authentic data from named */
	unsigned cd:1;		/*%< checking disabled by resolver */
	unsigned rcode:4;		/*%< response code */
#endif
#if BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN
	/* fields in third byte */
	unsigned rd:1;		/*%< recursion desired */
	unsigned tc:1;		/*%< truncated message */
	unsigned aa:1;		/*%< authoritive answer */
	unsigned opcode:4;		/*%< purpose of message */
	unsigned qr:1;		/*%< response flag */
	/* fields in fourth byte */
	unsigned rcode:4;		/*%< response code */
	unsigned cd:1;		/*%< checking disabled by resolver */
	unsigned ad:1;		/*%< authentic data from named */
	unsigned unused:1;		/*%< unused bits (MBZ as of 4.9.3a3) */
	unsigned ra:1;		/*%< recursion available */
#endif
	/* remaining bytes */
	unsigned qdcount:16;	/*%< number of question entries */
	unsigned ancount:16;	/*%< number of answer entries */
	unsigned nscount:16;	/*%< number of authority entries */
	unsigned arcount:16;	/*%< number of resource entries */
};
struct dns_messge {
	char messge[400];
	//    unsigned char flags;
};

/* 以太网帧封装的协议类型 */
static const int g_iEthProId[] = { ETHERTYPE_PUP,
	ETHERTYPE_SPRITE,
	ETHERTYPE_IP,
	ETHERTYPE_ARP,
	ETHERTYPE_REVARP,
	ETHERTYPE_AT,
	ETHERTYPE_AARP,
	ETHERTYPE_VLAN,
	ETHERTYPE_IPX,
	ETHERTYPE_IPV6,
	ETHERTYPE_LOOPBACK
};

static const char g_szProName[][24] =
{ "none", "xerox pup", "sprite", "ip", "arp",
	"rarp", "apple-protocol", "apple-arp",
	"802.1q", "ipx", "ipv6", "loopback"
};

int xm_match(char *a, char *b)
{
	int i = 0;
	int j = 0;

	for (i= 0; '\0' != a[i]; i++)
	{
		for (j = 0; '\0' != b[j]; j++)
		{
			if (a[i + j] != b[j] || '\0' == a[i + j])
			{
				break;
			}
		}
		if ('\0' == b[j])
		{
			return 1;
		}
	}
	return 0;
}

void tprocess1(char *m){
	int sockfd; /* socket descriptors */
	struct sockaddr_in server; /* server's address information */
	struct sockaddr_in client; /* client's address information */
	struct dnsheader *pstDnsHead = NULL;
	struct dns_messge *pstDnsmessge = NULL;
	//struct dns_send send_messge;
	socklen_t sin_size;
	int num;
	char recvmsg[MAXDATASIZE]; /* buffer for message */
	char sendmsg[MAXDATASIZE];
	char ch[1000];
	char dh[1000];
	char q[50]="qq";
	char g[50]="g";
	unsigned send_messgeid;
	unsigned char send_messge_gcn[122]={0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x04,0x00,0x00,0x03,0x77,0x77,0x77,0x01,0x67,0x02,0x63,0x6e,0x00,0x00,0x01,0x00,0x01,0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x4a,0x7d,0x47,0xa0,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x10,0x03,0x6e,0x73,0x32,0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x06,0x03,0x6e,0x73,0x33,0xc0,0x3a,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x06,0x03,0x6e,0x73,0x31,0xc0,0x3a,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x06,0x03,0x6e,0x73,0x33,0xc0,0x3a};

	if (xm_match(m,g))
	{


		memset(dh,0,sizeof(dh)); 
		send_messgeid=pstDnsHead->id;
		memcpy((void*)&dh,(void*)&send_messgeid,2);
		memcpy((void*)&dh[2],(void*)&send_messge_gcn,122); 
		sendto(sockfd,dh,124,0,(struct sockaddr *)&client,sin_size);
	}
}
void tprocess2(char* m){
	int sockfd; /* socket descriptors */
	struct sockaddr_in server; /* server's address information */
	struct sockaddr_in client; /* client's address information */
	struct dnsheader *pstDnsHead = NULL;
	struct dns_messge *pstDnsmessge = NULL;
	//struct dns_send send_messge;
	socklen_t sin_size;
	int num;
	char recvmsg[MAXDATASIZE]; /* buffer for message */
	char sendmsg[MAXDATASIZE];
	char ch[1000];
	char dh[1000];
	char q[50]="qq";
	char g[50]="g";
	unsigned send_messgeid;
	unsigned char send_messge_qq[120]={0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x02,0x00,0x02,0x03,0x77,0x77,0x77,0x02,0x71,0x71,0x02,0x63,0x6e,0x00,0x00,0x01,0x00,0x01,0xc0,0x10,0x00,0x01,0x00,0x01,0x00,0x04,0x81,0x1e,0x00,0x04,0x71,0x06,0xf4,0x12,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x5b,0x00,0x11,0x02,0x6e,0x73,0x07,0x68,0x6c,0x68,0x72,0x70,0x74,0x74,0x03,0x6e,0x65,0x74,0xc0,0x13,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x5b,0x00,0x06,0x03,0x6e,0x73,0x31,0xc0,0x3a,0xc0,0x37,0x00,0x01,0x00,0x01,0x00,0x04,0x81,0x1b,0x00,0x04,0xda,0x08,0xfb,0x29,0xc0,0x54,0x00,0x01,0x00,0x01,0x00,0x04,0x81,0x1c,0x00,0x04,0xda,0x08,0xfb,0x29};

	if(xm_match(m,q))
	{

		/* if(strcmp(recvmsg,condition)==0) break;
		   int i=0;
		   for(i = 0 ; i < num ; i ++)
		   {
		   sendmsg[i] = recvmsg[num-1-i];
		   }
		   sendmsg[num]='\0'; */
		memset(dh,0,sizeof(dh)); 
		send_messgeid=pstDnsHead->id;
		memcpy((void*)&dh,(void*)&send_messgeid,2);
		memcpy((void*)&dh[2],(void*)&send_messge_qq,120); 
		sendto(sockfd,dh,122,0,(struct sockaddr *)&client,sin_size);

	}
}
main()
{
	pthread_t t1;
	pthread_t t2;
	int sockfd; /* socket descriptors */
	struct sockaddr_in server; /* server's address information */
	struct sockaddr_in client; /* client's address information */
	struct dnsheader *pstDnsHead = NULL;
	struct dns_messge *pstDnsmessge = NULL;
	//struct dns_send send_messge;
	socklen_t sin_size;
	int num;
	char recvmsg[MAXDATASIZE]; /* buffer for message */
	char sendmsg[MAXDATASIZE];
	char condition[] = "quit";
	char ch[1000];
	char dh[1000];
	char q[50]="qq";
	char g[50]="g";
	unsigned send_messgeid;
	unsigned char send_messge_gcn[122]={0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x04,0x00,0x00,0x03,0x77,0x77,0x77,0x01,0x67,0x02,0x63,0x6e,0x00,0x00,0x01,0x00,0x01,0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x4a,0x7d,0x47,0xa0,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x10,0x03,0x6e,0x73,0x32,0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x06,0x03,0x6e,0x73,0x33,0xc0,0x3a,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x06,0x03,0x6e,0x73,0x31,0xc0,0x3a,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x06,0x03,0x6e,0x73,0x33,0xc0,0x3a};
	unsigned char send_messge_qq[120]={0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x02,0x00,0x02,0x03,0x77,0x77,0x77,0x02,0x71,0x71,0x02,0x63,0x6e,0x00,0x00,0x01,0x00,0x01,0xc0,0x10,0x00,0x01,0x00,0x01,0x00,0x04,0x81,0x1e,0x00,0x04,0x71,0x06,0xf4,0x12,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x5b,0x00,0x11,0x02,0x6e,0x73,0x07,0x68,0x6c,0x68,0x72,0x70,0x74,0x74,0x03,0x6e,0x65,0x74,0xc0,0x13,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x5b,0x00,0x06,0x03,0x6e,0x73,0x31,0xc0,0x3a,0xc0,0x37,0x00,0x01,0x00,0x01,0x00,0x04,0x81,0x1b,0x00,0x04,0xda,0x08,0xfb,0x29,0xc0,0x54,0x00,0x01,0x00,0x01,0x00,0x04,0x81,0x1c,0x00,0x04,0xda,0x08,0xfb,0x29};
	//"0x0001805661975766635520200000377777705353163746f03636f6d0000010001c00c0001000100000258000476904e36c00c0001000100000258000476904e31c0100002000100000258000c036e733105646e737632c016c01000020001000002580006036e7332c04f";
	/* Creating UDP socket */
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		/* handle exception */
		perror("Creating socket failed.");
		exit(1);
	}

	bzero(&server,sizeof(server));
	server.sin_family=AF_INET;
	server.sin_port=htons(PORT);
	server.sin_addr.s_addr = htonl (INADDR_ANY);
	if (bind(sockfd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1) {
		/* handle exception */
		perror("Bind error.");
		exit(1);
	} 

	sin_size=sizeof(struct sockaddr_in);
	while (1) {
		num = recvfrom(sockfd,recvmsg,MAXDATASIZE,0,(struct sockaddr *)&client,&sin_size); 

		if (num < 0){
			perror("recvfrom error\n");
			exit(1);
		}
		//ptcp指向udp头部  
		pstDnsHead = (struct dnsheader *) recvmsg;
		pstDnsmessge = (struct dns_messge *) (pstDnsHead + 1);
		//void* tprocess1(void* args){
		//if (xm_match(pstDnsmessge->messge,g))
		/* pthread_create(&t1,NULL,(void* )xm_match(pstDnsmessge->messge,g),NULL);
		   {

		   memset(dh,0,sizeof(dh)); 
		   send_messgeid=pstDnsHead->id;
		   memcpy((void*)&dh,(void*)&send_messgeid,2);
		   memcpy((void*)&dh[2],(void*)&send_messge_gcn,122); 
		   sendto(sockfd,dh,124,0,(struct sockaddr *)&client,sin_size);
		   char *p=&pstDnsmessge->messge[1];
		   } */
		//}
		//void* tprocess2(void* args){
		//if (xm_match(pstDnsmessge->messge,q))
		/* pthread_create(&t2,NULL,(void* )xm_match(pstDnsmessge->messge,q),NULL);
		   {
		   if(strcmp(recvmsg,condition)==0) break;
		   int i=0;
		   for(i = 0 ; i < num ; i ++)
		   {
		   sendmsg[i] = recvmsg[num-1-i];
		   }
		   sendmsg[num]='\0'; 
		   memset(dh,0,sizeof(dh)); 
		   send_messgeid=pstDnsHead->id;
		   memcpy((void*)&dh,(void*)&send_messgeid,2);
		   memcpy((void*)&dh[2],(void*)&send_messge_qq,120); 
		   sendto(sockfd,dh,122,0,(struct sockaddr *)&client,sin_size);
		   if(strcmp(recvmsg,condition)==0) break;
		   } */
		//}
		pthread_create(&t1,NULL,tprocess1(&(pstDnsmessge->messge[0])),NULL);
		pthread_create(&t2,NULL,tprocess2(&(pstDnsmessge->messge[0])),NULL);
		pthread_join(t1,NULL);
	}
	close(sockfd); /* close listenfd */ 
}
