#include <stdio.h>
#include <malloc.h>
struct dns_messge {
	char messge[200];
	//    unsigned char flags;
};
typedef struct node
{
 int nDate;
 struct dns_messge *messge1;
 void *(*process) (void *arg);
 struct node *pstnext;
}Node;

void *process()
{

printf("---------------");
}
//链表建立
Node* creat()
{

Node *head = NULL, *p = NULL, *s=NULL;
int Date =0, cycle=1;
char b[200]="hello";
char *ptr=b;
printf("%s\n",b);
head = malloc(sizeof(Node));
p=head;

for(cycle=1;cycle<=5;cycle++)
{
s = (Node*)malloc(sizeof(Node));
s->nDate=Date;
s->process = process;
s->messge1 = (struct dns_messge *)ptr;

Date++;
s->pstnext=NULL;


if(p!=NULL)
{
while(p->pstnext!=NULL)
p=p->pstnext;
p->pstnext=s;

}else
{
p->nDate=Date;
p->process = process;
p->messge1 = (struct dns_messge *)ptr;
Date++;
p->pstnext=NULL;
}
}
printf("start---------%s\n",b);

/*  while(NULL != head)
 {
  printf("\n%d  ", head->nDate); 
  printf("%p ", head->process); 
  printf("-%s \n", head->messge1);
  head = head->pstnext;
 }  */
 printf("end---------%s\n",b);

 return(head);
}


int main()
{
 Node *Head = NULL;   //定义头结点
 Node *Head_New = NULL;
int x;
 //链表建立

 Head = creat();

 printf("echo chain table\r\n");

 //链表输出
 Node *p = Head->pstnext;
 while(NULL != p)
 {
  printf("\n%d  ", p->nDate); 
  printf("%p ", p->process); 
  printf("-%s ", p->messge1->messge);
  p = p->pstnext;
 }
 printf("\r\n");

 return 0;
} 