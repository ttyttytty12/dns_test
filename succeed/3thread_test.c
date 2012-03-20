#include <stdio.h>
#include <pthread.h>

struct stu  
{  
    int age;
    char *name;
    char *num;
};  

void thread1(void)
{
    int i;
    for(i=0;i<3;i++)
    {
        printf("This is a pthread1.\n");
        usleep(2);
    }
}

//传递多个参数
void thread2(void *data)
{
    struct stu *stu1=(struct stu*)data;
    int i;
    for(i=0;i<3;i++)
    {
        printf("This is a pthread2. age=%d,name=%s,num=%s\n",stu1->age,stu1->name,stu1->num);
        usleep(1);
    }
}

//传递一个参数
void thread3(void *data)
{
    //int *d=(int *)data;
    char *d=(char *)data;
    int i;
    for(i=0;i<3;i++)
    {
        printf("This is a pthread3. data=%s\n",d);
        usleep(1);
    }
}



int main(void)
{
    pthread_t id1,id2,id3;
    int i,ret;
    ret=pthread_create(&id1,NULL,(void *) thread1,NULL);
    if(ret!=0){
        printf ("Create pthread1 error!\n");

    }
    struct stu student;
    student.age=10;
    student.name="yuguoqing";
    student.num="0415214736";
	printf ("star Create pthread2 !\n");
    ret=pthread_create(&id2,NULL,(void *) thread2,(void *)&student);
	printf ("Create pthread2 ovre!\n");
    if(ret!=0){
        printf ("Create pthread2 error!\n");
    }

    //int data=123; 传递整数应为(void *)&data
    char *data;
    data="i am yu";       
    ret=pthread_create(&id3,NULL,(void *) thread3,(void *)data);
    if(ret!=0){
        printf ("Create pthread3 error!\n");
    }
    sleep(1);

    return (0);
}