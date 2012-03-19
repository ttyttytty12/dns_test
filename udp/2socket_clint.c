#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER 800
#define SERV_PORT 3333
//=====================================================================================
//=====================================================================================
int main(int argc, char **argv)
{
int sockfd;
socklen_t src_len;
socklen_t len;
struct sockaddr_in dest_addr;
char send_msg[BUFFER]="I am UDP!", rece_msg[BUFFER];
/* check args */
if(argc != 2)
{
    printf("usage: udpclient <IPaddress>\n");
        exit(1);
	}
	if((sockfd=socket(AF_INET,SOCK_DGRAM,0))==-1)
	    {
	         perror("socket creat failed!\n");
		      exit(1);
		       }
		       /* init servaddr */
		       bzero(&dest_addr, sizeof(dest_addr));
		       dest_addr.sin_family = AF_INET;
		       dest_addr.sin_port = htons(SERV_PORT);
		       if(inet_aton(argv[1], &dest_addr.sin_addr) < 0)
		       {
		           printf("[%s] is not a valid IPaddress\n", argv[1]);
			       exit(1);
			       }

			       if(connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1)
			       {
			           perror("connect error!\n");
				       exit(1);
				       }

				       len = strlen(send_msg);
				       if(sendto(sockfd, send_msg, len, 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in)) < 0)
				       {
				           perror("sendto error!\n");
					    exit(1);
					    }
					    src_len = sizeof(dest_addr);
					    if(recvfrom(sockfd, rece_msg, len, 0, (struct sockaddr *)&dest_addr, &src_len) < 0)
					     {
					       perror("receive error!\n");
					         exit(0);
						  }
						  printf("%s\n",rece_msg);
						  return 0;
						  }
