/*@Author: lgh 
 *@Desp:syn,syn-ack,ack
 *|U|A|P|R|S|F|
 * ack 10000
 * rst 100
 * syn 10
 * fin 1
 * */

#include "webtcp.h" 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <pcap.h>
#include <stdarg.h>
#include <errno.h>
#define  ETH_NAME get_devname()
#define debug 1
/*目标机器的mac地址，如果不知道，可以全部填写为0xff，但是为了提高效果，建议先获取其mac */
//unsigned char mac[6]={0,0x1d,0xf,0x4a,0x37,0x34}; 
unsigned char mac[6]={0xff,0xff,0xff,0xff,0xff,0xff}; 
//unsigned char mac[6]={0x00,0x0C,0x29,0x27,0x59,0x97};
char ch[512],dip[64],buffer[1024]; 
unsigned char *iphead, *ethhead;
unsigned short pt; 
struct ifreq ethreq; 
struct	sockaddr_ll sl; 
int count,s;
unsigned short csum(unsigned char*,int); 
void tcp_send(int f,int count);
int analydata(char *data);
void send_synpacket(int f,int count);
int send_ackpacket(int squB);
int send_rstpacket();
unsigned int len;
unsigned int squ1;
char url[1024];
char *hostip;
char errbuf[PCAP_ERRBUF_SIZE];

int err_quit(const char *fmt, ...) { 
	va_list ap; 
	va_start(ap, fmt); 
	vfprintf(stderr, fmt, ap); 	
	va_end(ap); 	
	exit(-1);
} 

char *get_devname(){
	char *device=NULL;
	device = pcap_lookupdev(errbuf); 
	if(device == NULL){ 		
		err_quit("%s", errbuf);
		device = "lo";	
	}
	return device;
}

char *gethostip()
{
	int sock;
	struct sockaddr_in sin;
	struct ifreq ifr;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1)
	{
		perror("socket");
		exit(0);
	}
	strncpy(ifr.ifr_name, ETH_NAME, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
	{
		perror("ioctl");
		exit(0);
	}
	memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
	return inet_ntoa(sin.sin_addr);
}


double delta(struct timeval *t1p, struct timeval *t2p) 
{ 
	register double dt; 

	dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 + 
		(double)(t2p->tv_usec - t1p->tv_usec) / 1000.0; 
	return (dt); 
} 

int main(int argc,char**argv) 
{ 
	int i,j,k,n; 
	struct timeval tvstart,tvend;
	float timeuse;
	hostip=gethostip();
#if  0
	printf("the host ip:%s\n",hostip);
#endif
	if (argc!=4) {
		printf("usage: %s destaddr destport sendcounts\n",argv[0]); 
		return 0; 
	}
	i=strlen(argv[1]); 
	if (i>=64) {
		printf("error to para1\n"); 
		return 0; 
	}
	memset(dip,0,sizeof(dip)); 
	memcpy(dip,argv[1],i); 
	pt=atoi(argv[2]); 
	k=atoi(argv[3]); 
	if (k<=0)
		k=1;
	s=socket(PF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));/*pf_packet*/ 
	if (s==-1) {
		printf("error to create socket\n"); 
		return 0; 
	}

	memset((void *)&ethreq,0,sizeof(ethreq)); 
	strncpy(ethreq.ifr_name, ETH_NAME, IFNAMSIZ); 
	i=ioctl(s,SIOCGIFINDEX,&ethreq);/*把接口的索引存入 ifr_ifindex.*/ 
	if (i!=0) {
		close(s); 
		printf("error to get ifindex\n"); 
		return 0; 
	}
	memset((void*)&sl,0,sizeof(sl)); 
	sl.sll_family=AF_PACKET;/*sll处理。 */ 
	sl.sll_protocol=htons(ETH_P_IP); /* 0x800 只接收发往本机mac的ip类型的数据帧*/
	sl.sll_ifindex=ethreq.ifr_ifindex; 
	sl.sll_pkttype=PACKET_HOST; 
	sl.sll_hatype=ARPHRD_ETHER; 
	sl.sll_halen=sizeof(mac); 
	memcpy(sl.sll_addr,mac,sizeof(mac)); 
	gettimeofday(&tvstart,NULL);
	for(n=0;n<1;n++){
		tcp_send(s,k);
	}
	gettimeofday(&tvend,NULL);
	timeuse=delta(&tvstart,&tvend);
#if 0 
	timeuse=1000000*(tvend.tv_sec-tvstart.tv_sec)+tvend.tv_usec-tvstart.tv_usec;
	timeuse/=1000000;
	printf("USE time: %f\n",timeuse);
	printf("AVG time: %f\n",timeuse/2);
#endif 

#ifndef debug
	printf("USE time: %f ms\n",timeuse);
#endif
	close(s); 
	return 0; 
} 
/*v的最后一个字节必须是0,存入时还要htons();*/ 
unsigned short csum(unsigned char* v,int l) 
{ 
	unsigned int sm=0; 
	int i=l/2+l%2; 
	__asm__ __volatile__ 
		(
		 "lop_1:\n\t" 
		 "lodsw\n\t" 
		 "xchgb %%al,%%ah\n\t" 
		 "movzwl %%ax,%%eax\n\t" 
		 "addl %%eax,%0\n\t" 
		 "loop lop_1\n\t" 
		 "movl %0,%%eax\n\t" 
		 "movl %%eax,%%ebx\n\t" 
		 "andl $0xffff,%%eax\n\t" 
		 "shrl $16,%%ebx\n\t" 
		 "clc\n\t" 
		 "adcw %%bx,%%ax\n\t" 
		 "movzwl %%ax,%%eax\n\t" 
		 "not %%eax\n\t" 
		 "movl %%eax,%0\n\t": 
		 "+m"(sm):"S"(v),"c"(i) 
		); 
	return(unsigned short)sm; 
} 
void tcp_send(int f,int count) 
{ 
	int m=0;
	send_synpacket(f, count);
	memset(buffer,0,sizeof(buffer));
	int nm=0;
	while(nm < 3)
	{
		len = recvfrom(f,buffer,sizeof(buffer),0,NULL,NULL);
		if(len > 0)
		{
			if(analydata(buffer)==1){ 
				break;}
#ifndef debug
			printf("%d-----------Get %d bytes\n",m,len);
#endif
		}
		nm++;//gaidong
		m++;
	}
	return ;
}

int analydata(char *data)
{
	char recip[64];
	struct TAG_IPHEAD *reciphd;
	struct TAG_TCPHD *rectcphd;

	iphead = data;
	reciphd = (struct TAG_IPHEAD *)data; /* Skip Ethernet header */
	rectcphd = (struct TAG_TCPHD*)(data+sizeof(*reciphd));
	if (*iphead==0x45) { /* Double check for IPv4 and no options present */
		sprintf(recip,"%d.%d.%d.%d",iphead[12],iphead[13],iphead[14],iphead[15]);
		if(strcmp(recip,dip)==0){
#ifndef debug
			printf("Source host %d.%d.%d.%d\n",
					iphead[12],iphead[13],
					iphead[14],iphead[15]);
			printf("Dest host %d.%d.%d.%d\n",
					iphead[16],iphead[17],
					iphead[18],iphead[19]);
			printf("Source Port::%d\n",ntohs(rectcphd->sprot));
			printf("DST Port::%d\n",ntohs(rectcphd->dprot));
			printf("rec seq: %ld\n",ntohl(rectcphd->squ));
			//printf("seq: %d\n",rectcphd->squ);
			//printf("ack: %d\n",rectcphd->ack);
			printf("rec ack: %d\n",ntohl(rectcphd->ack));
			//printf("flags: %d\n",ntohs(rectcphd->tflag));
			printf("rec flags: %d\n",rectcphd->tflag);
			//	reptcp.squ=ntohl(rectcphd->ack);/*32位序列号*/ 
			//	reptcp.squ=1;/*32位序列号*/ 
			//reptcp.squ=rectcphd->ack;/*32位序列号*/ 
#endif
			unsigned int squ2=ntohl(rectcphd->squ);/*32位序列号*/ 
			if(rectcphd->tflag == 18 && ntohl(rectcphd->ack) == squ1 + 1){
			printf("open\n");
				send_ackpacket(squ2);
				//send_finpacket();
				//				send_rstpacket();
				return 1;
			}
#ifndef debug
else tcp_send(s, 1); 
#endif
		}
	}
	return 0;//gaidong
}
/*send FIN*/
int send_finpacket()
{
	struct TAG_IPHEAD finip;/*ip头部长度20字节*/
	struct TAG_TSDTCPHD fintsd;/*TCP伪头部结构：基本长度12字节*/
	struct TAG_TCPHD fintcp;/*tcp头部长度20字节*/
	unsigned short finsum;
	char c[512];
	int i,j,k;

	memset(c,0,sizeof(c));
	memset((void*)&finip,0,sizeof(finip));
	memset((void*)&fintsd,0,sizeof(fintsd));
	memset((void*)&fintcp,0,sizeof(fintcp));
	/*ip head*/
	finip.ipvar=0x45;
	finip.iprequ=0;
	finip.hdlen=htons(40);
	finip.id=htons(0x334);
	finip.off=0;
	finip.ttl=64;
	finip.prototype=6;
	finip.cksum=0;

	inet_pton(AF_INET,hostip,&(finip.sip));//ip.sip 
	inet_pton(AF_INET,dip,&(finip.dip)); //ip.dip
	finsum=csum((unsigned char*)&finip,20); 
	finip.cksum=htons(finsum); 
	/*tsd head*/
	fintsd.sip=finip.sip; 
	fintsd.dip=finip.dip; 
	fintsd.mzd=0; 
	fintsd.prototype=6; 
	i=ntohs(finip.hdlen); 
	i-=20; 
	fintsd.tcphdlen=htons(i); 
	memcpy(c,(void*)&fintsd,sizeof(fintsd)); 
	/*tcp head*/
	fintcp.sprot=htons(6602);
	fintcp.dprot=htons(pt);/*htons(80); */
	fintcp.squ=htonl(0x012345679);
	fintcp.ack=htonl(0); /*32位确认号*/
	fintcp.tlen=0x50;
	fintcp.tflag=1; /*标志位1*/
	fintcp.twin=htons(512);
	fintcp.cksum=0;
	fintcp.upoint=0;
	j=sizeof(fintsd);
	memcpy((void*)&c[j],(void*)&fintcp,sizeof(fintcp));
	i=sizeof(fintcp)+j;
	finsum=csum((unsigned char*)c,i);
	fintcp.cksum=htons(finsum);
	i=sizeof(finip);
	memcpy(ch,(void*)&finip,i);
	memcpy((void*)&ch[i],(void*)&fintcp,sizeof(fintcp));
	i+=sizeof(fintcp);	

	k=sendto(s,ch,i,0,(struct sockaddr*)&sl,sizeof(sl));/*发包*/
	if (k<=0) {
		printf("error\n");
	}else printf("bytes of fin sendto: %d\n",k);
	return 1;
}

/*send SYN*/
void send_synpacket(int f,int count)
{
	struct TAG_IPHEAD ip,*recip;/*ip头部长度20字节*/ 
	struct TAG_TSDTCPHD tsd;/*TCP伪头部结构：基本长度12字节*/ 
	struct TAG_TCPHD tcp;/*tcp头部长度20字节*/ 
	unsigned short sum; 
	char c[512]; 
	int i,j,k; 
	struct sockaddr_in fromaddr;
	memset(ch,0,sizeof(ch)); 
	memset(c,0,sizeof(c)); 
	memset((void*)&ip,0,sizeof(ip)); 
	memset((void*)&tsd,0,sizeof(tsd)); 
	memset((void*)&tcp,0,sizeof(tcp)); 
	/*ip head*/
	ip.ipvar=0x45; 
	ip.iprequ=0; 
	ip.hdlen=htons(40); 
	ip.id=htons(0x334); 
	ip.off=0; 
	ip.ttl=64; 
	ip.prototype=6; 
	ip.cksum=0; 
	//ip.sip=htonl(INADDR_ANY);
	inet_pton(AF_INET,hostip,&(ip.sip));//ip.sip 
	inet_pton(AF_INET,dip,&(ip.dip)); //ip.dip
	sum=csum((unsigned char*)&ip,20); 
	ip.cksum=htons(sum); 
	/*tsd head*/
	tsd.sip=ip.sip; 
	tsd.dip=ip.dip; 
	tsd.mzd=0; 
	tsd.prototype=6; 
	i=ntohs(ip.hdlen); 
	i-=20; 
	tsd.tcphdlen=htons(i); 
	memcpy(c,(void*)&tsd,sizeof(tsd)); 
	/*tcp head*/
	tcp.sprot=htons(6602); 
	tcp.dprot=htons(pt);/*htons(80); */
	tcp.squ=htonl(0x12345678);/*32位序列号305419896*/ 
	squ1=ntohl(tcp.squ);
#ifndef debug
	printf("tcp.squ==%d\n",ntohl(tcp.squ));
#endif
	//printf("tcp.squ==%d\n",tcp.squ);
	tcp.ack=htonl(0); /*32位确认号*/
	tcp.tlen=0x50; 
	tcp.tflag=2; /*标志位10syn*/
	tcp.twin=htons(512); 
	tcp.cksum=0; 
	tcp.upoint=0; 
	j=sizeof(tsd); 
	memcpy((void*)&c[j],(void*)&tcp,sizeof(tcp)); 
	i=sizeof(tcp)+j; 
	sum=csum((unsigned char*)c,i); 
	tcp.cksum=htons(sum); 
	i=sizeof(ip); 
	memcpy(ch,(void*)&ip,i); 
	memcpy((void*)&ch[i],(void*)&tcp,sizeof(tcp)); 
	i+=sizeof(tcp); 
	for (j=0;j<count;j++) {
		k=sendto(f,ch,i,0,(struct sockaddr*)&sl,sizeof(sl)); 
		if (k<=0) {
			printf("error\n"); 
		}
#ifndef debug
else printf("bytes of a sendto : %d\n",k);
#endif
	} 
	return;
}
/*send ACK*/
int send_ackpacket(int squB)
{
	struct TAG_IPHEAD ackip;/*ip头部长度20字节*/
	struct TAG_TSDTCPHD acktsd;/*TCP伪头部结构：基本长度12字节*/
	struct TAG_TCPHD acktcp;/*tcp头部长度20字节*/
	unsigned short acksum;
	char c[512];
	int i,j,k;

	memset(c,0,sizeof(c));
	memset((void*)&ackip,0,sizeof(ackip));
	memset((void*)&acktsd,0,sizeof(acktsd));
	memset((void*)&acktcp,0,sizeof(acktcp));
	/*ip head*/
	ackip.ipvar=0x45;
	ackip.iprequ=0;
	ackip.hdlen=htons(40);
	ackip.id=htons(0x334);
	ackip.off=0;
	ackip.ttl=64;
	ackip.prototype=6;
	ackip.cksum=0;

	inet_pton(AF_INET,hostip,&(ackip.sip));//ip.sip 
	inet_pton(AF_INET,dip,&(ackip.dip)); //ip.dip
	acksum=csum((unsigned char*)&ackip,20); 
	ackip.cksum=htons(acksum);
	/*tsd head*/
	acktsd.sip=ackip.sip;
	acktsd.dip=ackip.dip;
	acktsd.mzd=0;
	acktsd.prototype=6;
	i=ntohs(ackip.hdlen);
	i-=20;
	acktsd.tcphdlen=htons(i);
	memcpy(c,(void*)&acktsd,sizeof(acktsd));
	/*tcp head*/
	acktcp.sprot=htons(6602);
	acktcp.dprot=htons(pt);/*htons(80); */
	acktcp.squ=htonl(0x01234567);
	acktcp.ack=htonl(squB+1); /*32位确认号*/
	acktcp.tlen=0x50;
	acktcp.tflag=16; /*标志位10000*/
	acktcp.twin=htons(512);
	acktcp.cksum=0;
	acktcp.upoint=0;
	j=sizeof(acktsd);
	memcpy((void*)&c[j],(void*)&acktcp,sizeof(acktcp));
	i=sizeof(acktcp)+j;
	acksum=csum((unsigned char*)c,i);
	acktcp.cksum=htons(acksum);
	i=sizeof(ackip);
	memcpy(ch,(void*)&ackip,i);
	memcpy((void*)&ch[i],(void*)&acktcp,sizeof(acktcp));
	i+=sizeof(acktcp);

	k=sendto(s,ch,i,0,(struct sockaddr*)&sl,sizeof(sl));/*发包*/
	if (k<=0) {
		printf("error\n");
	}
#ifndef debug
else printf("bytes of ack sendto: %d\n",k);
#endif
	return 1;
}

int send_rstpacket()
{
	struct TAG_IPHEAD rstip;/*ip头部长度20字节*/
	struct TAG_TSDTCPHD rsttsd;/*TCP伪头部结构：基本长度12字节*/
	struct TAG_TCPHD rsttcp;/*tcp头部长度20字节*/
	unsigned short rstsum;
	char c[512];
	int i,j,k;

	memset(c,0,sizeof(c));
	memset((void*)&rstip,0,sizeof(rstip));
	memset((void*)&rsttsd,0,sizeof(rsttsd));
	memset((void*)&rsttcp,0,sizeof(rsttcp));
	/*ip head*/
	rstip.ipvar=0x45;
	rstip.iprequ=0;
	rstip.hdlen=htons(40);
	rstip.id=htons(0x334);
	rstip.off=0;
	rstip.ttl=64;
	rstip.prototype=6;
	rstip.cksum=0;

	inet_pton(AF_INET,hostip,&(rstip.sip));//ip.sip 
	inet_pton(AF_INET,dip,&(rstip.dip)); //ip.dip
	rstsum=csum((unsigned char*)&rstip,20); 
	rstip.cksum=htons(rstsum);
	/*tsd head*/
	rsttsd.sip=rstip.sip;
	rsttsd.dip=rstip.dip;
	rsttsd.mzd=0;
	rsttsd.prototype=6;
	i=ntohs(rstip.hdlen);
	i-=20;
	rsttsd.tcphdlen=htons(i);
	memcpy(c,(void*)&rsttsd,sizeof(rsttsd));
	/*tcp head*/
	rsttcp.sprot=htons(6602);
	rsttcp.dprot=htons(pt);/*htons(80); */
	rsttcp.squ=htonl(0x012345679);
	rsttcp.ack=htonl(0); /*32位确认号*/
	rsttcp.tlen=0x50;
	rsttcp.tflag=4; /*标志位100*/
	rsttcp.twin=htons(512);
	rsttcp.cksum=0;
	rsttcp.upoint=0;
	j=sizeof(rsttsd);
	memcpy((void*)&c[j],(void*)&rsttcp,sizeof(rsttcp));
	i=sizeof(rsttcp)+j;
	rstsum=csum((unsigned char*)c,i);
	rsttcp.cksum=htons(rstsum);
	i=sizeof(rstip);
	memcpy(ch,(void*)&rstip,i);
	memcpy((void*)&ch[i],(void*)&rsttcp,sizeof(rsttcp));
	i+=sizeof(rsttcp);

	k=sendto(s,ch,i,0,(struct sockaddr*)&sl,sizeof(sl));/*发包*/
	if (k<=0) {
		printf("error\n");
	}else printf("bytes of rst sendto: %d\n",k);
	return 1;
}
int send_httpreq(int sfd)
{
	char request[1024]={0},buf[1024];
	unsigned int sendlen,reclen;
	unsigned int addr_len=sizeof(struct sockaddr);
	printf("\n----THE following is the request content:\n");
	sprintf(request,"GET HTTP /1.1\r\nAccept:*/*\r\nAccept-Language:zh-cn\r\nUser-Agent:Mozilla/4.0(compatible;MSIE5.01;Windows NT 5.0)\r\nHost:%s:%d\r\nConnection:Close\r\n\r\n",url,pt);
	printf("%s\n",request);

	//	if(sendlen=send(sfd, request, sizeof(request),0) < 0){
	if(sendlen=sendto(sfd,request,sizeof(request),0,(struct sockaddr*)&sl,sizeof(sl)) < 0) {
		perror("sending socket http ");
	}

	printf("\n----THe following is the response header:\n");
	//	if(reclen= recvfrom(sfd,buf,sizeof(buffer),0,(struct sockaddr *)&sl,&addr_len) < 0){
	if(reclen= recv(sfd, buf, 1024, 0) < 0){
		perror("reading http reponse\n");
	}
	if(reclen == 0)
		printf("ending connection\n");
	else
		printf("%s\n", buf);
}
