#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
struct ether_header
{

//u_int8_t  ether_dhost;	 /*destination eth addr */
//u_int8_t  ether_shost;      /* source ether addr    */
//u_int16_t ether_type;                 /* packet type ID field */
char ether_dhost;
char ether_shost;
char ether_type;
};

struct ether_two
{

//u_int8_t  ether_dhost;	 /*destination eth addr */
//u_int8_t  ether_shost;      /* source ether addr    */
//u_int16_t ether_type;                 /* packet type ID field */
char ether_dhost;
char ether_shost;
char ether_type;
char ether_four;
};
struct ether_three
{
char ether_one;
char ether_two;
};
main()
{
char a[30]="123456789you_are_a_girl";
char *p=a;
char **ptr=&p;
//unsigned short usEthPktType;
struct ether_header *pstEthHead;
struct ether_two *pstIpHead;
struct ether_three *pstTCP;
printf("\nhello world\n");
printf("*p=%c\n",*p);
pstEthHead = (struct ether_header*)a;
printf("\n0x%04c",pstEthHead->ether_type);
printf("\n%c\n",pstEthHead->ether_dhost);
pstIpHead = (struct ether_two *)(pstEthHead + 1);
printf("\n%c\n",pstIpHead->ether_four);
pstTCP = (struct ether_three *)(pstIpHead + pstEthHead);

printf("\n%c\n",pstTCP->ether_one);
}

