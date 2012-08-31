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
#include <time.h>
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
struct funcall {
	struct dns_messge *messge1;
	unsigned send_messgeid;
	struct sockaddr_in client1;
	socklen_t sin_size1;
	int sockfd1;
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

void tprocess1(void *date){
	int sockfd; /* socket descriptors */
	struct sockaddr_in server; /* server's address information */
	struct sockaddr_in client; /* client's address information */
	struct dnsheader *pstDnsHead = NULL;
	struct funcall *dns_messge1 = (struct funcall*)date;
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
	char *match_one;
	unsigned char send_messge_gcn[122]={0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x04,0x00,0x00,0x03,0x77,0x77,0x77,0x01,0x67,0x02,0x63,0x6e,0x00,0x00,0x01,0x00,0x01,0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x4a,0x7d,0x47,0xa0,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x10,0x03,0x6e,0x73,0x32,0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x06,0x03,0x6e,0x73,0x33,0xc0,0x3a,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x06,0x03,0x6e,0x73,0x31,0xc0,0x3a,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x06,0x03,0x6e,0x73,0x33,0xc0,0x3a};

    	match_one= (char *)dns_messge1->messge1;
		memset(dh,0,sizeof(dh)); 
		send_messgeid=dns_messge1->send_messgeid;
		memcpy((void*)&dh,(void*)&send_messgeid,2);
		memcpy((void*)&dh[2],(void*)&send_messge_gcn,122); 
		sendto(dns_messge1->sockfd1,dh,124,0,(struct sockaddr *)&(dns_messge1->client1),dns_messge1->sin_size1);
}
void tprocess2(void* date){
	int sockfd; /* socket descriptors */
	struct sockaddr_in server; /* server's address information */
	struct sockaddr_in client; /* client's address information */
	struct dnsheader *pstDnsHead = NULL;
	struct dns_messge *pstDnsmessge = NULL;
	struct funcall *dns_messge1 = (struct funcall*)date;
	//struct dns_send send_messge;
	socklen_t sin_size;
	int num;
	int thread_id; 
	char recvmsg[MAXDATASIZE]; /* buffer for message */
	char sendmsg[MAXDATASIZE];
	char ch[1000];
	char dh[1000];
	char q[50]="qq";
	char g[50]="g";
	char *match_one;
	unsigned send_messgeid;
	unsigned char send_messge_qq[120]={0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x02,0x00,0x02,0x03,0x77,0x77,0x77,0x02,0x71,0x71,0x02,0x63,0x6e,0x00,0x00,0x01,0x00,0x01,0xc0,0x10,0x00,0x01,0x00,0x01,0x00,0x04,0x81,0x1e,0x00,0x04,0x71,0x06,0xf4,0x12,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x5b,0x00,0x11,0x02,0x6e,0x73,0x07,0x68,0x6c,0x68,0x72,0x70,0x74,0x74,0x03,0x6e,0x65,0x74,0xc0,0x13,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x5b,0x00,0x06,0x03,0x6e,0x73,0x31,0xc0,0x3a,0xc0,0x37,0x00,0x01,0x00,0x01,0x00,0x04,0x81,0x1b,0x00,0x04,0xda,0x08,0xfb,0x29,0xc0,0x54,0x00,0x01,0x00,0x01,0x00,0x04,0x81,0x1c,0x00,0x04,0xda,0x08,0xfb,0x29};
	int time_one_t2,time_two_t2,time_three_t2,time_four_t2,time_five_t2;
	struct timeval tv_one,tv_two,tv_three,tv_four,tv_five;
	gettimeofday(&tv_one, NULL);
//	printf("tv_one_t2 %u:%u\n", tv_one.tv_sec, tv_one.tv_usec);
//thread_id = pthread_self () ;
//printf("--------thread_id2=%d\n",thread_id);//打印线程id。
//pthread_exit (NULL) ;
		memset(dh,0,sizeof(dh)); 
		send_messgeid=dns_messge1->send_messgeid;
		memcpy((void*)&dh,(void*)&send_messgeid,2);
		memcpy((void*)&dh[2],(void*)&send_messge_qq,120); 
		 gettimeofday(&tv_two, NULL);
		 time_one_t2=tv_two.tv_usec-tv_one.tv_usec;
		 printf("--------time_one_t2=%d\n",time_one_t2);
		 sendto(dns_messge1->sockfd1,dh,122,0,(struct sockaddr *)&(dns_messge1->client1),dns_messge1->sin_size1);
		   gettimeofday(&tv_three, NULL);
		   time_two_t2=tv_three.tv_usec-tv_two.tv_usec;
		   printf("--------time_two_t2=%d\n",time_two_t2);
		}
main()
{
	pthread_t t1;
	pthread_t t2;
	int sockfd; /* socket descriptors */
	struct sockaddr_in server; /* server's address information */
	struct sockaddr_in client; /* client's address information */
	struct dnsheader *pstDnsHead = NULL;
	struct dns_messge *pstDnsmessge ;
	struct funcall st_funcall ;
	//struct dns_send send_messge;
	socklen_t sin_size;
	int num;
	int match_mun=0;
	int time_one,time_two,time_three,time_four,time_five;
	struct timeval tv_one,tv_two,tv_three,tv_four,tv_five;
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
//	printf("1main_tprocess=%d\n",num_query);
		   gettimeofday(&tv_one, NULL);
		   printf("tv_one %u:%u\n", tv_one.tv_sec, tv_one.tv_usec);
		num = recvfrom(sockfd,recvmsg,MAXDATASIZE,0,(struct sockaddr *)&client,&sin_size); 

/* 		if (num < 0){
			perror("recvfrom error\n");
			exit(1);
		} */
		//ptcp指向udp头部  
		   gettimeofday(&tv_two, NULL);
		   time_one=tv_two.tv_usec-tv_one.tv_usec;
//		   printf("tv_two %u:%u\n", tv_two.tv_sec, tv_two.tv_usec);
		   printf("time_one=%d\n",time_one);
    		pstDnsHead = (struct dnsheader *) recvmsg;
    		pstDnsmessge = (struct dns_messge *) (pstDnsHead + 1);
			st_funcall.messge1=(struct dns_messge *)pstDnsmessge->messge;
			st_funcall.send_messgeid=pstDnsHead->id;
			st_funcall.client1=client;
			st_funcall.sin_size1=sin_size;
			st_funcall.sockfd1=sockfd;
			
		   gettimeofday(&tv_three, NULL);
		   time_two=tv_three.tv_usec-tv_two.tv_usec;
		   printf("time_two=%d\n",time_two);
//		   printf("tv_three %u:%u\n", tv_three.tv_sec, tv_three.tv_usec);
		if (xm_match(pstDnsmessge->messge,g))
		   {
             match_mun =1;
		   } 

		   else if (xm_match(pstDnsmessge->messge,q))
		   {
		     match_mun =2;

		   } 

		   //		   printf("tv_four %u:%u\n", tv_four.tv_sec, tv_four.tv_usec);
		   switch(match_mun)
		   {
		   case 1:
		   pthread_create(&t1,NULL,(void *)tprocess1,(void *)&st_funcall);
		   gettimeofday(&tv_four, NULL);
		   time_three=tv_four.tv_usec-tv_three.tv_usec;
		   printf("time_three=%d\n",time_three);
		   break;

		   case 2:
		   pthread_create(&t2,NULL,(void *)tprocess2,(void *)&st_funcall);
		   gettimeofday(&tv_five, NULL);
		   time_four=tv_five.tv_usec-tv_three.tv_usec;
		   printf("time_four=%d\n",time_four);
           break;
		   }

		   printf("------------------------------------------------\n");
		   //		   printf("tv_five %u:%u\n", tv_five.tv_sec, tv_five.tv_usec);
	}
	close(sockfd); /* close listenfd */ 
}
