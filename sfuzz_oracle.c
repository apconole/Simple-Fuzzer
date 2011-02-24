/**
 * SFUZZ oracle
 * this file implements the API side of the oracle.
 * sfuzz_oracle_daemon.c holds the implementation of the oracle daemon
 * sfuzz_oracle_client.c holds the implementation of a generic querying 
 *                       client
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

/**
 * IMPORTANT NOTE:
 * We need to use ptrace() on unix-y systems
 * and the mswin debug facilities on windows
 */

int spawn_monitored(char *argv[])
{
    int exit_status = 0;
    pid_t child;
    int pipeForStdOut[2], pipeForStdErr[2];
    const struct rlimit inf = {
        RLIM_INFINITY, RLIM_INFINITY };

    printf("[] Attempting to spawn a monitored task.\n");
    
    setrlimit(RLIMIT_CORE, &inf);

    if(pipe(pipeForStdOut) != 0)
    {
        printf("[] stdout-pipe: Abort!\n");
        exit(-1);
    }

    if(pipe(pipeForStdErr) != 0)
    {
        printf("[] stderr-pipe: Abort!\n");
        exit(-1);
    }

    switch(child = fork())
    {
    case 0:
        /*CHILD*/

        /*take care of output / input*/
        close(0); close(1); close(2);
        if(open("/dev/null", O_RDONLY) != 0)
            exit(-1);

        close(pipeForStdOut[0]); /* don't leave this dangling */
        if(dup2(pipeForStdOut[1], 1) < 0)
        {
            exit(-1); /* maybe we can log or something ? */
        }

        close(pipeForStdErr[0]);
        if(dup2(pipeForStdErr[1], 2) < 0)
        {
            exit(-1); /* see above .. */
        }

        /* force core dumping */
        setrlimit(RLIMIT_CORE, &inf);

        execvp(argv[0], argv);

    case -1:
        fprintf(stderr, 
                "[SFUZZ-ORACLE] There was an error attempting to spawn a "
                "child.\n");
        fprintf(stderr,
                "Debugging not available!\n");
        exit(-1);

    default:
        do
        {
            int istatus;
            pid_t status = waitpid(-1, &istatus, WNOHANG);
            if(status == -1) { exit_status = 1; 
                fprintf
                    (stderr,
                     "[SFUZZ-ORACLE] Unable to obtain status. Attempting "
                     "to kill\n");
                kill(child, SIGTERM); /* send sigterm */
                goto endit;
            } else if(status != 0)
            {
                if (WIFEXITED(istatus))
                {
                    printf("[%u] Exited (possibly normal), status[%d]\n",
                           status, WEXITSTATUS(istatus));
                    exit_status = 1;
                }
                if (WIFSIGNALED(istatus))
                {
                    printf("[%u] Terminated due to signal #%d [%s]. %s.\n",
                           status, WTERMSIG(istatus),
                           strsignal(WTERMSIG(istatus)),
#ifdef WCOREDUMP
# if WCOREDUMP
                           WCOREDUMP(istatus) ? "Core dumped" :
                           "No core available");
# else
                           "Unable to check for core status");
# endif /* WCOREDUMP */
#else
                           "Unable to check for core status");
#endif /* !defined WCOREDUMP */

                    exit_status = 1;
                }
                
                if (WIFSTOPPED(istatus))
                {
                    printf("[%u] Signaled to stop by #%d [%s].\n", status,
                           WSTOPSIG(istatus), strsignal(WSTOPSIG(istatus)));
                }
                if (WIFCONTINUED(istatus))
                {
                    printf("[%u] Continued\n", status);
                }
            } 
            else
            {
                char buf[1024] = {0};
                ssize_t buf_read = 0;
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 100000; /* 100MS do a read / write */
                select(0, NULL, NULL, NULL, &tv);
                if((buf_read = read(pipeForStdOut[0], buf, sizeof(buf) - 1))
                   > 0)
                {
                    printf("-- %s --\n", buf);
                }

                if((buf_read = read(pipeForStdErr[0], buf, sizeof(buf) - 1))
                   > 0)
                {
                    printf("-- %s --\n", buf);
                }
                
            }
        } while(!exit_status);
    }
endit:
    close(pipeForStdOut[0]); close(pipeForStdErr[0]);
    close(pipeForStdOut[0]); close(pipeForStdErr[1]);

    return -1;
}


int main(int argc, char *argv[])
{
    if ( argc < 2 )
    {
        printf("[%s] %s command [arguments]\n",
               argv[0], argv[0]);
        return -1;
    }

    while(-1 != spawn_monitored(&argv[1]));
    return 0;
}
