#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include "webtcp.h"
#include <stdbool.h>
#include <pcap.h>
#include <stdarg.h>
#include <errno.h>
#define BUFFER 8000
#define SERV_PORT 3333

int
main ()
{
  int sockfd, n;
  socklen_t len;
  socklen_t src_len;
  struct sockaddr_in cliaddr;
  struct sockaddr_ll servaddr_ll;
  struct ifreq ifr;
  char msg[BUFFER];
  sockfd = socket (PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));	/* create a socket */

/* init servaddr */
  bzero (&servaddr_ll, sizeof(servaddr_ll));
  servaddr_ll.sll_family = AF_PACKET;
  //servaddr_ll.sin_addr.s_addr = htonl (INADDR_ANY);
  // servaddr_ll.sin_port = htons (SERV_PORT);

  strcpy(ifr.ifr_name, "ETH1");
  ioctl (sockfd, SIOCGIFINDEX, &ifr);
  servaddr_ll.sll_ifindex = ifr.ifr_ifindex;
  servaddr_ll.sll_protocol = htons (ETH_P_ALL);
/* bind address and port to socket */
  if (bind (sockfd, (struct sockaddr *) &servaddr_ll, sizeof (servaddr_ll)) ==
      -1)
    {
      perror ("bind error");
      exit (1);
    }
  src_len = sizeof (cliaddr);
 // printf("%s\n",111);
  while (1)
    {
      if (recvfrom
	  (sockfd, msg, BUFFER, 0, (struct sockaddr *) &cliaddr,
	   &src_len) < 0)
	{
	  perror ("receive error!\n");
	  exit (0);
	}
      printf("111");
      len = strlen (msg);
     if (sendto
	  (sockfd, msg, len, 0, (struct sockaddr *) &cliaddr,
	   sizeof (struct sockaddr_ll)) < 0)
	{
	  perror ("sendto error!\n");
	  exit (1);
	}
    // printf ("\n", msg);	
    }
  return 0;
}

