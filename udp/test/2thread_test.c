#include <pthread.h> 
#include <stdio.h> 
#include <sys/time.h> 
#include <string.h> 
#define MAX 10
pthread_t thread[2]; 
pthread_mutex_t mut; 
int number=0, i;
void *thread1(void *x) 
{ 
int *y=(int *)x;

        printf ("thread1 : I'm thread 1\n");
		printf ("x=%d\n",y);

        printf("thread1 :�������ڵ������������\n"); 
        pthread_exit(NULL); 
}
void *thread2() 
{ 
int i=0;
        printf("thread2 : I'm thread 2\n");
        for (i = 0; i < MAX; i++) 
        { 
                printf("thread2 : number = %d\n",number); 
                pthread_mutex_lock(&mut); 
                        number++; 
                pthread_mutex_unlock(&mut); 
                sleep(3); 
        }

        printf("thread2 :�������ڵ������������\n"); 
        pthread_exit(NULL); 
}
void thread_create(void) 
{ 
        int temp; 
		int *ptr;
		int a=5;
		ptr=5;
        memset(&thread, 0, sizeof(thread));          //comment1 
        /*�����߳�*/ 
        if((temp = pthread_create(&thread[0], NULL, thread1, (void *)ptr)) != 0)       //comment2
                 printf("�߳�1����ʧ��!\n"); 
        else 
                printf("�߳�1������\n");
        if((temp = pthread_create(&thread[1], NULL, thread2, NULL)) != 0)  //comment3
                 printf("�߳�2����ʧ��"); 
        else 
                printf("�߳�2������\n"); 
}
void thread_wait(void) 
{ 
        /*�ȴ��߳̽���*/ 
        if(thread[0] !=0) {                   //comment4 
                pthread_join(thread[0],NULL); 
                printf("�߳�1�Ѿ�����\n"); 
        } 
        if(thread[1] !=0) {                //comment5 
                pthread_join(thread[1],NULL); 
                printf("�߳�2�Ѿ�����\n"); 
        } 
}
int main() 
{ 
        /*��Ĭ�����Գ�ʼ��������*/ 
        pthread_mutex_init(&mut,NULL);
        printf("����������Ŷ�������ڴ����̣߳��Ǻ�\n"); 
        thread_create(); 
        printf("����������Ŷ�������ڵȴ��߳�������񰢣��Ǻ�\n"); 
        thread_wait();
// ���������û��pthread_join���̻߳�ܿ�����Ӷ�ʹ�������̽������Ӷ�ʹ�������߳�û�л��Ὺʼִ�оͽ����ˡ�����pthread_join�����̻߳�һֱ�ȴ�ֱ���ȴ����߳̽����Լ��Ž�����ʹ�������߳��л���ִ�С�
        return 0; 
}