#include <stdio.h>
#include <string.h>

int main()
{
    char name[0x10]={0};
    char string[0x20]={0};
    unsigned int len=0;

    puts("input the username:");
    read(0,name,0x10);
    puts("input the num:");
    read(0,string,8);
    len=atoi(string);

    if (strstr(name,"admin"))
    {
        puts("welcome~");
        printf(name);
    }
    else
    {
        if (strstr(name,"over"))
        {
            if (len==0x100)
            {   
                puts("input name again");
                read(0,name,len);
            }
        }
        if (strstr(name,"fmt"))
        {
            printf(name);
        }
        
    }
    puts("input the string:");
    read(0,string,0x50);

    return 0;
}