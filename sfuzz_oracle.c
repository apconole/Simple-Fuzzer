/**
 * SFUZZ oracle
 * this file implements the API side of the oracle.
 * sfuzz_oracle_daemon.c holds the implementation of the oracle daemon
 * sfuzz_oracle_client.c holds the implementation of a generic querying 
 *                       client
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "sfuzz_oracle.h"

/**
 * IMPORTANT NOTE:
 * We need to use ptrace() on unix-y systems
 * and the mswin debug facilities on windows
 */

int main(int argc, char *argv[])
{
    char outfile[1024], errfile[1024];
    
    if ( argc < 2 )
    {
        printf("[%s] %s command [arguments]\n",
               argv[0], argv[0]);
        return -1;
    }

    //wait for sfuzz connection ... 
    int ctr_respawn = 0;
    do
    {
        printf(" [%s] === spawning!\n", argv[0]);
        snprintf(outfile, 1024, "%s_%d.stdout", argv[1], ctr_respawn);
        snprintf(errfile, 1024, "%s_%d.stderr", argv[1], ctr_respawn);
        ++ctr_respawn;
    }while(-1 == spawn_monitored(outfile, errfile, ctr_respawn-1, &argv[1]));

    return 0;
}
