#include <stdio.h>

void test()
{
	char name[0x10];
	read(0,name,0x20);
}
void main()
{
	test();
}
