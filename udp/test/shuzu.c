#include <stdio.h>
void main()
{
char a[30]="you_are_a_boy's father";
char *p=a;
char **ptr=&p;
printf("\nhello world\n");
printf("*p=%c\n",*p);
printf("**ptr=%c\n",**ptr);
*p++;
*p++;
printf("**ptr=%c\n",**ptr);
}
