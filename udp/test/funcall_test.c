#include<stdio.h>
void fork(int a)
{
int i=5;
//int a;
printf("i=%d\n",i);
printf ("a=%d\n",a);
}
void main()
{
int a=1,b=2;
printf ("a=%d\nb=%d\n",a,b);
fork(a);
}
