#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

char *read_n(char *, unsigned int);
void init();
int check1(char *);
int check2(char *);

void init(){
    unsigned int i,fd;
    setvbuf(stdin,0,1,0);
    setvbuf(stdout,0,2,0);
    fd = open("/dev/urandom",O_RDONLY);
    int randint[0x38];
    char room[0x38][0x20];
    char xiaoheiwo[0x20];
    unsigned int index;
    read(fd, &index, 1);
    index %= 0x30;
    if(fd < 0){
        exit(-1);
    }
    chdir("/tmp");
    puts("\033[01;31m正在送imagin去小黑窝~\033[01;32m");
    for ( i = 0; i < 0x30; ++i ) {
        read(fd, &randint[i], 4);
        snprintf(room[i], 0x20, "R0OM#%010u", randint[i]);
        printf("%s\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b", room[i]);
        usleep(20000);
        mkdir(room[i], 0755);
    }
    usleep(50000);
    snprintf(xiaoheiwo, 0x20, "R0OM#%010u", randint[index]);
    chdir(xiaoheiwo);
    puts("\033[01;34mLevel Up !\033[01;34m \033[01;37m获得道具\033[01;32m ls \033[01;37m");
    char find[0x30];
    memset(find, 0, 0x30);
    read_n(find, 0x30);
    if ( check1(find) != -1 ){
        system(find);
    }
}

char *read_n(char *buf, unsigned int len) {
    char *ptr; 
    unsigned int i; 
    for ( i = 0; ; ++i ) {
        if ( i >= len )
            break;
        if ( read(0, (i + buf), 1uLL) < 0 )
            exit(-1);
        if ( buf[i] == '\n' ) {
            ptr = i + buf;
            *ptr = 0;
            return ptr;
        }
    }
    return ptr;
}

int check1(char *cmd){
    int i;
    for ( i = 0; i < strlen(cmd); ++i ) {
        if (   (cmd[i] <= '`' || cmd[i] > 'z')
            && (cmd[i] <= '@' || cmd[i] > 'Z')
            &&  cmd[i] != '/'
            &&  cmd[i] != ' '
            &&  cmd[i] != '-' ) {
            return -1;
        }
    }
    if (   strstr(cmd, "sh") 
        || strstr(cmd, "cat") 
        || strstr(cmd, "cd") 
        || strstr(cmd, "chdir") 
        || strstr(cmd, "flag")
        || strstr(cmd, "imagin")
        || strstr(cmd, "pwd")
        || strstr(cmd, "export") ){
        return -1;
    }
    else{
        return 0;
    }
}

int check2(char *cmd) {
    if (   strchr(cmd, '*')
        || strstr(cmd, "sh")
        || strstr(cmd, "cat")
        || strstr(cmd, "..")
        || strchr(cmd, '&')
        || strchr(cmd, '|')
        || strchr(cmd, ';')
        || strchr(cmd, '=')
        || strchr(cmd, '>')
        || strchr(cmd, '<') ) {
        return -1;
    }
    else {
        return 0;
    }
}

int main(int argc, char *argv){
    init();

    char imagin[0x50];
    char where[0x50];
    char cmd[0x20];
    memset(imagin, 0, 0x50);
    memset(where, 0, 0x50);
    memset(cmd, 0, 0x20);

    getcwd(imagin, 0x50);

    puts("\033[01;34m[你得到了一些关于imagin的线索]\033[01;32m");
    usleep(400000);
    printf("不过");
    int i=0;
    for(i=0;i<6;i++){
        putchar('.');
        usleep(200000);
    }
    usleep(300000);
    puts("Ta在哪里呢?\033[01;37m");
    read_n(where, 0x50);
    if ( strcmp(where, imagin) ) {
        // puts(where);
        // puts(imagin);
        puts("\033[35m你没有找到imagin，灰头土脸的离开了\033[0m");
        exit(0);
    }
    puts("\033[43;31m恭喜你找到了imagin的小黑窝！氮素Ta已经被藕送走啦！哈哈哈哈\033[0m");
    puts("");
    puts("\033[01;34mLevel Up !\033[01;34m \033[01;37m获得道具\033[01;36m 残缺的shell \033[01;37m");
    read_n(cmd,0x20);
    if ( check2(cmd) == -1 ){
        puts("\033[01;31m你的shell貌似没有这个功能\033[01;32m");
        exit(0);
    }
    puts("\033[01;31m你成功地修复了shell，快去找imagin叭~\033[01;32m");    
    system(cmd);
    return 0;
}
