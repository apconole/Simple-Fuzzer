/**
 * SFUZZ oracle
 * this file implements the API side of the oracle.
 * sfuzz_oracle_daemon.c holds the implementation of the oracle daemon
 * sfuzz_oracle_client.c holds the implementation of a generic querying 
 *                       client
 */

#ifndef FAKE_ORACLE
#define FAKE_ORACLE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#ifndef __WIN32__
#include <sys/resource.h>
#endif
#include "sfuzz_oracle.h"

void cleanup( struct sfuzz_oracle_debugger *d)
{

}

#if FAKE_ORACLE
extern int32_t spawn_monitored(char *outfile, char *errfile, uint32_t id,char *argv[]);
#endif

/**
 *
 */

int32_t run_debugger(struct sfuzz_oracle_debugger *debug)
{
#if FAKE_ORACLE
    return spawn_monitored( debug-> outfile_name, debug -> errfile_name, 
                            debug -> reboot_ctr, debug -> args );
#else

    if(! debug ) return -1;

    if( debug -> state != SFO_DEBUG_READY )
        return -1;

    /* start the debuged app */
    spawn_debug_app( debug );

    if( debug -> state != SFO_DEBUG_LOADED )
        return -1;

    /* application is spawned ( but not in debuggable state yet )*/

    establish_contact(); // this gets us sync'd with sfuzz

    start_debug( debug );

    if( debug -> state != SFO_DEBUG_ATTACHED )
    {
        indicate_test_error();
        return -1;
    }

    do
    {
        event_pend( debug );
    } while ( debug -> state == SFO_DEBUG_ATTACHED );

    /* we're in an ended state */
    if( debug -> state == SFO_DEBUG_CRASHED )
    {
        handle_crash( debug );
    }
    
    if( debug -> state == SFO_DEBUG_END )
    {
        return -1;
    }

    debug -> state = SFO_DEBUG_READY;

    return 0;
#endif
}

int main(int argc, char *argv[])
{
    
    struct sfuzz_oracle_debugger sfuzz_debugger;
    
    if ( argc < 2 )
    {
        printf("[%s] %s command [arguments]\n",
               argv[0], argv[0]);
        return -1;
    }

    sfuzz_debugger.state = SFO_DEBUG_EMPTY;
    sfuzz_debugger.path_to_exe = argv[1];

#if FAKE_ORACLE
    sfuzz_debugger.args  = &argv[1];
#else
    if( argc > 2 )
        sfuzz_debugger.args        = &argv[2];
#endif
    //wait for sfuzz connection ... 
    sfuzz_debugger.reboot_ctr = 0;
    do
    {
        printf(" [%s] === spawning!\n", argv[0]);

        ++(sfuzz_debugger.reboot_ctr);

        snprintf(sfuzz_debugger.outfile_name, 1024, "%s_%d.stdout",
                 argv[1], sfuzz_debugger.reboot_ctr);
        snprintf(sfuzz_debugger.errfile_name, 1024, "%s_%d.stderr", 
                 argv[1], sfuzz_debugger.reboot_ctr);

        
    }while(-1 == run_debugger(&sfuzz_debugger));

    cleanup( &sfuzz_debugger );

    return 0;
}
