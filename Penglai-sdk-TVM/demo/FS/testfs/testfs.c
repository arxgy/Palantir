#include "eapp.h"
#include "print.h"
#include <string.h>
#include <fcntl.h>
#include "fscallargs.h"
#include <stdio.h>
#include<sys/stat.h>
#include<unistd.h>

int EAPP_ENTRY main(){
    unsigned long* args;
    EAPP_RESERVE_REG;
    FILE *f;
    int status;
    char buf[52] = {0};
    eapp_print("before fopen\n");
    f = fopen("/create.txt","w+");
    struct stat st;
    status = stat("/create.txt", &st);
    if(!status){
        eapp_print("stat succeed: file length: %d\n",st.st_size);
    }
    char str[] = "create file and write\n";
    fseek(f,0,SEEK_SET);
    memset(buf,0,53);
    fgets(buf,52,f);
    eapp_print("read after seek: %s\n",buf);
    fputs(str,f);
    eapp_print("after fwrite\n");
    fclose(f);
    f = fopen("/create.txt","r");
    memset(buf,0,52);
    eapp_print("fopen /create.txt for read\n");
    char* res = fgets(buf,52,f);
    if(res == NULL){
        eapp_print("fgets failed\n");
    }
    eapp_print("read writed content: %s\n",buf);
    fclose(f);
    EAPP_RETURN(0);
}