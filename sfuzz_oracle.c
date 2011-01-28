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
    int exit = 0;
    pid_t child;
    static int fdi = -1, fdo = -1, fde = -1;
    const struct rlimit inf = {
        RLIM_INFINITY, RLIM_INFINITY };

    static FILE *c_stdin = NULL, *c_stdout = NULL, *c_stderr = NULL;

    printf("[] Attempting to spawn a monitored task.\n");
    
    setrlimit(RLIMIT_CORE, &inf);
    if(fdi < 0)
    {
        fdi = open("/dev/null", O_RDONLY);
        if(fdi) c_stdin = fdopen(fdi, "r");
    }

    if(fdo < 0)
    {
        fdo = open("monitored.stdout", O_WRONLY|O_CREAT, S_IRUSR | S_IWUSR);
        if(fdo) c_stdout = fdopen(fdo, "w");
    }

    if(fde < 0)
    {
        fde = open("monitored.stderr", O_WRONLY|O_CREAT, S_IRUSR | S_IWUSR);
        if(fde) c_stderr = fdopen(fde, "w");
    }

    switch(child = fork())
    {
    case 0:
        /*CHILD*/
        close(0); close(1); close(2);

        if(c_stdout) setlinebuf(c_stdout);
        if(c_stderr) setlinebuf(c_stderr);

        if(fdi > 0 && fdi != 0)
            dup2(fdi, 0);
        if(fdo > 0 && fdo != 1)
            dup2(fdo, 1);
        if(fde > 0 && fde != 2)
            dup2(fde, 2);

        /* force core dumping */
        setrlimit(RLIMIT_CORE, &inf);

        execvp(argv[0], argv);

    case -1:
        fprintf(stderr, 
                "[SFUZZ-ORACLE] There was an error attempting to spawn a "
                "child.\n");
        fprintf(stderr,
                "Debugging not available!\n");
        return -1;

    default:
        do
        {
            int istatus;
            pid_t status = waitpid(-1, &istatus, 0);
            if(status == -1) { exit = 1; 
                fprintf
                    (stderr,
                     "[SFUZZ-ORACLE] Unable to obtain status. Attempting "
                     "to kill\n");
                kill(child, SIGTERM); /* send sigterm */
                return -1;
            } else if(status != 0)
            {
                if (WIFEXITED(istatus))
                {
                    printf("[%u] Exited (possibly normal), status[%d]\n",
                           status, WEXITSTATUS(istatus));
                    exit = 1;
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

                    exit = 1;
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
        } while(!exit);
    }
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
