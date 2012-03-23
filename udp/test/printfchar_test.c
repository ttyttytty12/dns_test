#include <stdio.h>
struct dns_messge {
char messge[4];
};
struct dns_messge_two {
struct dns_messge *messge1;
char p;
}
main()
{
char *p="1234";
printf("p=%s\n",p);
struct dns_messge *dnsmessge=NULL;
struct dns_messge_two dnsmessgetwo;
char *two;
dnsmessge=(struct dns_messge *)p;
printf("messge=%s\n",dnsmessge->messge);
two = (char *)dnsmessge->messge;
printf("two=%s\n",two);
dnsmessgetwo.messge1=(struct dns_messge *)dnsmessge->messge;
printf("messgetwo=%s\n",dnsmessgetwo.messge1);
}
