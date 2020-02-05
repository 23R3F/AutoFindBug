#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


char msg[0x20]="hello world!";

typedef struct mystruct
{
    char name[0x10];
    unsigned long addr;
    char sth[0x20];
    void (*do_func)();
}mystruct;

void bye()
{
    puts("bye~");
    exit(0);
}
void vul()
{
    unsigned int cho;
    char ch[0x10]={0};
    unsigned int times=4;

    mystruct *my=malloc(sizeof (struct mystruct));
    my->addr=&msg;
    my->do_func=&bye;

    while(times--)
    {
        puts("input:");
        read(0,ch,4);
        cho=atoi(ch);
        switch(cho)
        {
            case 1:
                puts("input your name:");
                read(0,my->name,0x18);
                break;
            case 2:
                printf("this is the msg:%s\n", my->addr);
                break;
            case 3:
                puts("change msg");
                read(0,my->addr,0x20);
                break;
            case 4:
                puts("say sth:");
                read(0,my->sth,0x10);
                if (!strcmp(my->sth,"pop_rbp"))
                {
                    asm("push $0x666;pop %rbp;");
                }
                else 
                {
                    if (!strcmp(my->sth,"pop_rsp"))
                    {
                        asm("push $0x666;pop %rsp;");
                    }
                    else
                    {
                        if(!strcmp(my->sth,"error_pc"))
                        {
                            my->do_func=0x666666666666;
                        }
                    } 
                        
                }
                my->do_func();
                break;
        }

    }
}


int main(int argc, char const *argv[])
{
    vul();
    return 0;
}