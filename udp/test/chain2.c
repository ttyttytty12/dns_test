#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
struct dns_messge {
	char messge[200];
	//    unsigned char flags;
};
struct funcall {
	struct dns_messge *messge1;
	int send_messgeid;
	int client1;
	int sin_size1;
	int sockfd1;
	//    unsigned char flags;
	}
typedef struct worker
{
    /*回调函数，任务运行时会调用此函数，注意也可声明成其它形式*/
    void *(*process) (void *arg);
    void *arg;/*回调函数的参数*/
    struct worker *next;

} CThread_worker;
void *process()
{
printf("---------------");
}
int main()
{

 void *process();

struct CThread_worker *head,*p,*member;
struct funcall *arg;
struct funcall dns_funcall;
arg=&dns_funcall;  
struct dns_messge *a;
char b[200]="hello";
char *ptr=b;
char **ptrb=&ptr;


struct funcall *dns_messge1 = (struct funcall*)member->arg;
dns_messge1->messge1=(struct dns_messge *)match_one_four;
member->process = process;
printf("263_pool_add_worker_pstDnsmessge=%s\n",dns_messge1->messge1);

CThread_worker *newworker2 = (CThread_worker *) malloc (sizeof (CThread_worker));
newworker2=member->next;
//member->next=newworker2;
struct funcall *dns_messge7 = (struct funcall*)newworker2->arg;
newworker2->process = process;
dns_messge7->messge1=(struct dns_messge *)match_one3;
 printf("268_pool_add_worker_pstDnsmessge=%s\n",dns_messge7->messge1);
newworker2->next=NULL; 

p =head;
 do 
{
char *match_one11;
struct funcall *dns_messge8 = (struct funcall*)p->arg;
match_one11= (char *)dns_messge8->messge1;
printf("277pool_add_worker_pstDnsmessge=%s\n",match_one11);
p=p->next;
} while(p!=NULL); 
     }
    else
     {
         pool->queue_head = newworker;

struct funcall *dns_messge1 = (struct funcall*)pool->queue_head->arg;
match_one3= (char *)dns_messge1->messge1;
printf("7pool_add_worker_pstDnsmessge=%s\n",match_one3);

     }
}
