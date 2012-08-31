#include <stdio.h>
#include <malloc.h>

typedef struct node
{
 int nDate;
 struct node *pstnext;
}Node;

//链表输出
void output(Node *head)
{
 Node *p = head->pstnext;
 while(NULL != p)
 {
  printf("%d  ", p->nDate); 
  p = p->pstnext;
 }
 printf("\r\n");
}
Node* creat()
{
 Node *head = NULL, *p = NULL, *s = NULL;
 int Date = 0, cycle = 1;
 head = (Node*)malloc(sizeof(Node));
 if(NULL == head)
 {
  printf("member error\r\n");
  return NULL;
 }
 head->pstnext = NULL;
 
 p = head;
 while(cycle)
 {
  printf("input number when 0 over\r\n");
  scanf("%d", &Date);
  if(0 != Date)
  {
   s = (Node*)malloc(sizeof(Node));
   if(NULL == s)
   {
    printf("member error\r\n");
    return NULL;
   }
   s->nDate = Date;
   p->pstnext = s;
   p = s;
  }
  else
  {
   cycle = 0;
  }
 }
 p->pstnext = NULL;
 return(head);
}

int main()
{
 Node *Head = NULL;   //定义头结点
 Node *Head_New = NULL;

 //链表建立
 Head = creat();

 printf("echo chain table\r\n");

 //链表输出
 output(Head);

 return 0;
}