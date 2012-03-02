#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

int32_t spawn_monitored(char *outfile, char *errfile, char *argv[]){
    printf("NULL oracle - exiting.");
    exit(-1);
}

int32_t monitored_signal(uint32_t signals, uint8_t status, int32_t pid)
{
    return -1;
}
int32_t monitored_exit  (int32_t  exit){ return -1; }
int32_t term_monitored ( int32_t id ) { return -1; }
