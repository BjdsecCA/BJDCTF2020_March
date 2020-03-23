#include <stdio.h>

int main(){
	long addr;
	init();
	printf("Give me your one gadget:");
	scanf("%ld", &addr);
	void (*p)() = addr;
    p();
	return 0;
}

void init(){
	setvbuf(stdout,0,2,0);
	setvbuf(stdin,0,1,0);
	printf("here is the gift for u:%p\n",printf);
}
