#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(){
    char cmd[0x100] = {0};
    puts("Welcome to Pwn-Game by TaQini.");
    puts("Your ID:");
    system("id");
    printf("$ ");
    gets(cmd);
    if( strstr(cmd, "n")
       ||strstr(cmd, "e")
       ||strstr(cmd, "p")
       ||strstr(cmd, "b")
       ||strstr(cmd, "u")
       ||strstr(cmd, "s")
       ||strstr(cmd, "h")
       ||strstr(cmd, "i")
       ||strstr(cmd, "f")
       ||strstr(cmd, "l")
       ||strstr(cmd, "a")
       ||strstr(cmd, "g")
       ||strstr(cmd, "|")
       ||strstr(cmd, "/")
       ||strstr(cmd, "$")
       ||strstr(cmd, "`")
       ||strstr(cmd, "-")
       ||strstr(cmd, "<")
       ||strstr(cmd, ">")
       ||strstr(cmd, ".")){
        exit(0);    
    }else{
        system(cmd);
    }
    return 0;
}
