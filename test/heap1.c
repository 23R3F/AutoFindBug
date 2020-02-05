#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


void heap_bug()
{
    char c[8]={0};
    unsigned int flag=4;
    unsigned long *ptr=malloc(0x50);
    *ptr=0;
    while(flag--){  
        puts("input:");
        read(0,c,4);
        switch(atoi(c)){
            case 1: 
                puts("malloc!");
                *ptr=malloc(0x30);
                break;
            case 2:
                if (*ptr){
                    puts("free!");
                    free(*ptr);
                }
                break;
            case 3:
                if (*ptr)
                {
                    puts("edit!");
                    read(0,*ptr,0x10);
                }
                break;

            case 4:
                if (*ptr)
                {
                    puts("show!");
                    write(1,*ptr,0x10);
                }
        }

    }
}

int main(int argc, char const *argv[])
{
    heap_bug();
    return 0;
}