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
#define MAX_EVENT 100
#include <sys/epoll.h>
#include <sys/errno.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <assert.h>

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
	char messge1[400];
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
//printf("\nxm_match b=%s\n",b);
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
/*
*线程池里所有运行和等待的任务都是一个CThread_worker
*由于所有任务都在链表里，所以是一个链表结构
*/
typedef struct worker
{
    /*回调函数，任务运行时会调用此函数，注意也可声明成其它形式*/
    void *(*process) (void *arg);
    void *arg;/*回调函数的参数*/
    struct worker *next;

} CThread_worker;


/*线程池结构*/
typedef struct
{
     pthread_mutex_t queue_lock;
     pthread_cond_t queue_ready;

    /*链表结构，线程池中所有等待任务*/
     CThread_worker *queue_head;

    /*是否销毁线程池*/
    int shutdown;
     pthread_t *threadid;
    /*线程池中允许的活动线程数目*/
    int max_thread_num;
    /*当前等待队列的任务数目*/
    int cur_queue_size;

} CThread_pool;


int pool_add_worker (void *(*process) (void *arg), void *arg);
void *thread_routine (void *arg);
static CThread_pool *pool = NULL;


void setnonblocking(int sock)

{
	int opts;
	opts=fcntl(sock,F_GETFL);
	
	if(opts<0)
		
	{
		perror("fcntl(sock,GETFL)");
		exit(1);
	}
	
	opts = opts|O_NONBLOCK;
	if(fcntl(sock,F_SETFL,opts)<0)
	{
		perror("fcntl(sock,SETFL,opts)");
		exit(1);
	}    
}

void
pool_init (int max_thread_num)
{
     pool = (CThread_pool *) malloc (sizeof (CThread_pool));

     pthread_mutex_init (&(pool->queue_lock), NULL);
     pthread_cond_init (&(pool->queue_ready), NULL);

     pool->queue_head = NULL;

     pool->max_thread_num = max_thread_num;
     pool->cur_queue_size = 0;

     pool->shutdown = 0;

     pool->threadid =
         (pthread_t *) malloc (max_thread_num * sizeof (pthread_t));
    int i = 0;
    for (i = 0; i < max_thread_num; i++)
     {
         pthread_create (&(pool->threadid[i]), NULL, thread_routine,NULL);
     }
}


/*向线程池中加入任务*/
int
pool_add_worker (void *(*process) (void *arg), void *arg)
{
    /*构造一个新任务*/
     CThread_worker *newworker =
         (CThread_worker *) malloc (sizeof (CThread_worker));
     newworker->process = process;


     newworker->arg = arg;
char *match_one;
struct funcall *dns_messge1 = (struct funcall*)newworker->arg;
match_one= (char *)dns_messge1->messge1;
//printf("newworker->arg =%s\n",match_one );
     newworker->next = NULL;/*别忘置空*/
     pthread_mutex_lock (&(pool->queue_lock));
//printf("end pthread_mutex_lock-------------------------------------------\n");
    /*将任务加入到等待队列中*/
     CThread_worker *member = pool->queue_head;
    if (member != NULL)
     {
        while (member->next != NULL)
         member = member->next;
         member->next = newworker;
		 

     }
    else
     {
         pool->queue_head = newworker;
     }

     assert (pool->queue_head != NULL);

     pool->cur_queue_size++;
     pthread_mutex_unlock (&(pool->queue_lock));

    /*好了，等待队列中有任务了，唤醒一个等待线程；
     注意如果所有线程都在忙碌，这句没有任何作用*/
     pthread_cond_signal (&(pool->queue_ready));
    return 0;
}



void *
thread_routine (void *arg)
{
     printf ("starting thread 0x%x\n", pthread_self ());
    while (1)
     {
         pthread_mutex_lock (&(pool->queue_lock));
        /*如果等待队列为0并且不销毁线程池，则处于阻塞状态; 注意
         pthread_cond_wait是一个原子操作，等待前会解锁，唤醒后会加锁*/
        while (pool->cur_queue_size == 0 && !pool->shutdown)
         {

//printf("start pthread_cond_wait-------------------------------------------\n");          
		  pthread_cond_wait (&(pool->queue_ready), &(pool->queue_lock));
//printf("end1 pthread_cond_wait-------------------------------------------\n");
		  }

        /*线程池要销毁了*/
        if (pool->shutdown)
         {
            /*遇到break,continue,return等跳转语句，千万不要忘记先解锁*/
             pthread_mutex_unlock (&(pool->queue_lock));
             printf ("thread 0x%x will exit\n", pthread_self ());
             pthread_exit (NULL);
         }

//         printf ("thread 0x%x is starting to work\n", pthread_self ());

        /*assert是调试的好帮手*/
         assert (pool->cur_queue_size != 0);
         assert (pool->queue_head != NULL);
        /*等待队列长度减去1，并取出链表中的头元素*/
         pool->cur_queue_size--;
         CThread_worker *worker = pool->queue_head;
         pool->queue_head = worker->next;
         pthread_mutex_unlock (&(pool->queue_lock));
		 /*test*/

        /*调用回调函数，执行任务*/
         (*(worker->process)) (worker->arg);
         free (worker);
         worker = NULL;
     }
    /*这一句应该是不可达的*/
     pthread_exit (NULL);
}


/*销毁线程池，等待队列中的任务不会再被执行，但是正在运行的线程会一直
把任务运行完后再退出*/
int
pool_destroy ()
{
    if (pool->shutdown)
        return -1;/*防止两次调用*/
     pool->shutdown = 1;

    /*唤醒所有等待线程，线程池要销毁了*/
     pthread_cond_broadcast (&(pool->queue_ready));

    /*阻塞等待线程退出，否则就成僵尸了*/
    int i;
    for (i = 0; i < pool->max_thread_num; i++)
         pthread_join (pool->threadid[i], NULL);
     free (pool->threadid);

    /*销毁等待队列*/
     CThread_worker *head = NULL;
    while (pool->queue_head != NULL)
     {
         head = pool->queue_head;
         pool->queue_head = pool->queue_head->next;
         free (head);
     }
    /*条件变量和互斥量也别忘了销毁*/
     pthread_mutex_destroy(&(pool->queue_lock));
     pthread_cond_destroy(&(pool->queue_ready));
    
     free (pool);
    /*销毁后指针置空是个好习惯*/
     pool=NULL;
    return 0;
}

void *tprocess2(void* date){
	int sockfd; /* socket descriptors */
	struct sockaddr_in server; /* server's address information */
	struct sockaddr_in client; /* client's address information */
	struct dnsheader *pstDnsHead = NULL;
	char *pstDnsmessge = NULL;
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
	char *match_one;
	unsigned send_messgeid;
	unsigned char send_messge_qq[120]={0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x02,0x00,0x02,0x03,0x77,0x77,0x77,0x02,0x71,0x71,0x02,0x63,0x6e,0x00,0x00,0x01,0x00,0x01,0xc0,0x10,0x00,0x01,0x00,0x01,0x00,0x04,0x81,0x1e,0x00,0x04,0x71,0x06,0xf4,0x12,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x5b,0x00,0x11,0x02,0x6e,0x73,0x07,0x68,0x6c,0x68,0x72,0x70,0x74,0x74,0x03,0x6e,0x65,0x74,0xc0,0x13,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x5b,0x00,0x06,0x03,0x6e,0x73,0x31,0xc0,0x3a,0xc0,0x37,0x00,0x01,0x00,0x01,0x00,0x04,0x81,0x1b,0x00,0x04,0xda,0x08,0xfb,0x29,0xc0,0x54,0x00,0x01,0x00,0x01,0x00,0x04,0x81,0x1c,0x00,0x04,0xda,0x08,0xfb,0x29};
	unsigned char send_messge_gcn[122]={0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x04,0x00,0x00,0x03,0x77,0x77,0x77,0x01,0x67,0x02,0x63,0x6e,0x00,0x00,0x01,0x00,0x01,0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,0x4a,0x7d,0x47,0xa0,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x10,0x03,0x6e,0x73,0x32,0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x06,0x03,0x6e,0x73,0x33,0xc0,0x3a,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x06,0x03,0x6e,0x73,0x31,0xc0,0x3a,0xc0,0x10,0x00,0x02,0x00,0x01,0x00,0x00,0x54,0x60,0x00,0x06,0x03,0x6e,0x73,0x33,0xc0,0x3a};
match_one= (char *)dns_messge1->messge1;
//printf ("----------------tprocess2\n");
//printf("proc_pstDnsmessge=%s\n",dns_messge1->messge1);
//printf("pstDnsmessge=%s\n",match_one);
	if(xm_match(match_one,q))
	{

		/* if(strcmp(recvmsg,condition)==0) break;
		   int i=0;
		   for(i = 0 ; i < num ; i ++)
		   {
		   sendmsg[i] = recvmsg[num-1-i];
		   }
		   sendmsg[num]='\0'; */
		memset(dh,0,sizeof(dh)); 
		send_messgeid=dns_messge1->send_messgeid;
		memcpy((void*)&dh,(void*)&send_messgeid,2);
		memcpy((void*)&dh[2],(void*)&send_messge_qq,120); 
		sendto(dns_messge1->sockfd1,dh,122,0,(struct sockaddr *)&(dns_messge1->client1),dns_messge1->sin_size1);

	}
	else if (xm_match(match_one,g))
	{


		memset(dh,0,sizeof(dh)); 
		send_messgeid=dns_messge1->send_messgeid;
		memcpy((void*)&dh,(void*)&send_messgeid,2);
		memcpy((void*)&dh[2],(void*)&send_messge_gcn,122); 
		sendto(dns_messge1->sockfd1,dh,124,0,(struct sockaddr *)&(dns_messge1->client1),dns_messge1->sin_size1);
	}
}

void *
myprocess (void *arg)
{
char *dnsmessge=NULL;
    dnsmessge=(char *)arg;
	printf("messge=%d\n",dnsmessge);
     printf ("threadid is 0x%x, working on task %d\n", pthread_self (),*(int *) arg);
     sleep (1);/*休息一秒，延长任务的执行时间*/
    return NULL;
}

int
main (int argc, char **argv)
{    
     pool_init (3);/*线程池中最多三个活动线程*/

	pthread_t t1;
	pthread_t t2;
	int sockfd,listenfd; /* socket descriptors */
	struct sockaddr_in server; /* server's address information */
	struct sockaddr_in client; /* client's address information */
	struct dnsheader *pstDnsHead = NULL;
	char *pstDnsmessge ;
    struct epoll_event ev;
    struct epoll_event events[20];
 
 	int time_one,time_two,time_three,time_four,time_five;
	struct timeval tv_one,tv_two,tv_three,tv_four,tv_five;
	
	int ret,i,epfd,nfds,packnum=0;
	long int time_all=0;
	ssize_t n;
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
	
	/* Creating UDP socket */
	if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		/* handle exception */
		perror("Creating socket failed.");
		exit(1);
	}
	epfd = epoll_create(8192); 
		//把socket设置为非阻塞方式	
	setnonblocking(listenfd);	
	//设置与要处理的事件相关的文件描述符	
	ev.data.fd=listenfd;
	//设置要处理的事件类型	
	ev.events=EPOLLIN|EPOLLET;
	//注册epoll事件
	
	ret=epoll_ctl(epfd,EPOLL_CTL_ADD,listenfd,&ev);
	printf("epoll_ctl return %d\n",ret);
	
	bzero(&server,sizeof(server));
	server.sin_family=AF_INET;
	server.sin_port=htons(PORT);
	server.sin_addr.s_addr = htonl (INADDR_ANY);
	if (bind(listenfd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1) {
		/* handle exception */
		perror("Bind error.");
		exit(1);
	} 
	memset(recvmsg,0,MAXDATASIZE);
	
	sin_size=sizeof(struct sockaddr_in);
                   perror("starting");
	for (;;) 
	{

/* 		if(errno==EINTR)printf("EINTR");
		if(errno==EFAULT)printf("EINTR");
		if(errno==EINVAL)printf("EINTR");
		if(errno==EBADF)printf("EINTR"); */
		//等待epoll事件的发生

		nfds=epoll_wait(epfd,events,MAX_EVENT,-1);
 

	//					                printf("recvfrom error_%d_",nfds);
/*    if (nfds == -1) {
                   perror("epoll_pwait");
               }  */
			//   				perror("connfd=0\n");


		//处理所发生的所有事件      
		
		for(i=0;i<nfds;++i)	
		{
			if(events[i].events&EPOLLIN)				
			{

			if ( (sockfd = events[i].data.fd) < 0)
					continue;
		if ( (n = recvfrom(sockfd,recvmsg,MAXDATASIZE,0,(struct sockaddr *)&client,&sin_size)) < 0)
				{
						
					if (errno == ECONNRESET)
					{
							
						close(sockfd);						
						events[i].data.fd = -1;
						
					} 
					else 
						printf("readline error\n");
					
				} else if (n == 0)
				{
					perror("connfd=0\n");
					close(sockfd);
					events[i].data.fd = -1;
				}
				//设置用于写操作的文件描述符				
				ev.data.fd=sockfd;				
				//设置用于注测的写操作事件				
				ev.events=EPOLLOUT|EPOLLET;				
				//修改sockfd上要处理的事件为EPOLLOUT				
				epoll_ctl(epfd,EPOLL_CTL_MOD,sockfd,&ev);		
/* 		num = recvfrom(sockfd,recvmsg,MAXDATASIZE,0,(struct sockaddr *)&client,&sin_size); 

		if (num < 0){
			perror("recvfrom error\n");
			exit(1);
		} */
		}
		else if(events[i].events&EPOLLOUT)				
			{
			
				 gettimeofday(&tv_two, NULL);
		 time_one=tv_two.tv_usec-tv_one.tv_usec;
		 tv_one.tv_usec=tv_two.tv_usec;
//		   printf("recvfrom=%u\n",time_one); 
 packnum++;
if(time_one>0)
{
time_all=time_all+time_one;
}
if(packnum>10000)
{
printf("\n10000 time avg %d",time_all/10000);
printf("\n packnum %d",packnum);
packnum=0;
time_all=0;
}	

			
/* 		   gettimeofday(&tv_one, NULL);
		   printf("tv_one %u:%u\n", tv_one.tv_sec, tv_one.tv_usec); */
		   
				if(events[i].data.fd == -1)
					continue;
					
				sockfd = events[i].data.fd;				
				write(sockfd, recvmsg, n);
//				printf("writeline %d\n",epfd);				
				//设置用于读操作的文件描述符				
				ev.data.fd=sockfd;				
				//设置用于注测的读操作事件			
				ev.events=EPOLLIN;	

	pstDnsHead = (struct dnsheader *) recvmsg;
	pstDnsmessge = (char *) (pstDnsHead + 1);
	struct funcall *st_funcall = (struct funcall *) malloc (sizeof (struct funcall));
	struct funcall dns_funcall ;
    strcpy(st_funcall->messge1,pstDnsmessge);
	st_funcall->send_messgeid=pstDnsHead->id;
	st_funcall->client1=client;
	st_funcall->sin_size1=sin_size;
	st_funcall->sockfd1=sockfd;
	
         pool_add_worker (tprocess2, st_funcall);

		 epoll_ctl(epfd,EPOLL_CTL_MOD,sockfd,&ev);	
            }

            }
	    }

  //   free (workingnum);
       pool_destroy ();
    return 0;
}