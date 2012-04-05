#include <stdio.h>
void main()
{
char a[30]="you_are_a_boy's father";
char *p=a;
char **ptr=&p;
printf("\nhello world\n");
printf("**ptr=%c\n",**ptr);
**ptr++;
printf("**ptr=%c\n",**ptr);
}
