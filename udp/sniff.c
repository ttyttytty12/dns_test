#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>   
#include <netinet/ip.h>  
#include <string.h>  
#include <netdb.h>  
#include <netinet/tcp.h>  
#include <netinet/udp.h> 
#include <stdlib.h>  
#include <unistd.h>  
#include <signal.h>  
#include <net/if.h>  
#include <sys/ioctl.h>  
#include <sys/stat.h>  
#include <fcntl.h>  
#include <linux/if_ether.h> 
#include <net/ethernet.h>


void die(char *why, int n)  
{  
  perror(why);  
  exit(n);  
} 

int do_promisc(char *nif, int sock )  
{  
struct ifreq ifr;  
                
strncpy(ifr.ifr_name, nif,strlen(nif)+1);  
   if((ioctl(sock, SIOCGIFFLAGS, &ifr) == -1))  //���flag
   {         
     die("ioctl", 2);  
   }  
   
   ifr.ifr_flags |= IFF_PROMISC;  //����flag��־
  
   if(ioctl(sock, SIOCSIFFLAGS, &ifr) == -1 )  //�ı�ģʽ
   { 
     die("ioctl", 3);  
   }  
}  
//�޸�������PROMISC(����)ģʽ

char buf[40]; 

main()  
{  
struct sockaddr_in addr; 
struct ether_header *peth; 
struct iphdr *pip;         
struct tcphdr *ptcp; 
struct udphdr *pudp;

char mac[16];
int i,sock, r, len;         
char *data; 
char *ptemp; 
char ss[32],dd[32];

if((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)  //����socket
//man socket���Կ������漸�������˼
{
        die("socket", 1);  
}

do_promisc("ETH1", sock);    //eth0Ϊ��������

system("ifconfig");

for(;;)  
{  
     len = sizeof(addr); 

     r = recvfrom(sock,(char *)buf,sizeof(buf), 0, (struct sockaddr *)&addr,&len);  
     //���Ե�ʱ���������һ�����r������ж��Ƿ�ץ����
     buf[r] = 0;  
     ptemp = buf; 
     peth = (struct ether_header *)ptemp;

     ptemp += sizeof(struct ether_header); //ָ�����ethͷ�ĳ���
     pip = (struct ip *)ptemp; //pipָ��ip��İ�ͷ

     ptemp += sizeof(struct ip);//ָ�����ipͷ�ĳ��� 

     switch(pip->protocol)   //���ݲ�ͬЭ���ж�ָ������
     { 
         case IPPROTO_TCP: 
         ptcp = (struct tcphdr *)ptemp;       //ptcpָ��tcpͷ��
         printf("TCP pkt :FORM:[%s]:[%d]��n",inet_ntoa(*(struct in_addr*)&(pip->saddr)),ntohs(ptcp->source)); 
         printf("TCP pkt :TO:[%s]:[%d]��n",inet_ntoa(*(struct in_addr*)&(pip->daddr)),ntohs(ptcp->dest));
         
         break; 
         
         case IPPROTO_UDP: 
         pudp = (struct udphdr *)ptemp;      //ptcpָ��udpͷ��  
              printf("UDP pkt:��n len:%d payload len:%d from %s:%d to %s:%d��n",  
             r,  
             ntohs(pudp->len), 
             inet_ntoa(*(struct in_addr*)&(pip->saddr)), 
             ntohs(pudp->source), 
             inet_ntoa(*(struct in_addr*)&(pip->daddr)), 
             ntohs(pudp->dest) 
         );  
         break; 
         
         case  IPPROTO_ICMP: 
         printf("ICMP pkt:%s��n",inet_ntoa(*(struct in_addr*)&(pip->saddr)));
         break; 
         
         case  IPPROTO_IGMP: 
         printf("IGMP pkt:��n"); 
         break; 
         
         default: 
         printf("Unkown pkt, protocl:%d��n", pip->protocol); 
         break; 
    } //end switch

perror("dump");
 } 
 
}
