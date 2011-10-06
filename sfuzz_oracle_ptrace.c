#include <sys/prctl.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <sys/ptrace.h>
#include <sys/user.h>  
#include <fcntl.h>

#include "sfuzz_oracle.h"

char *globname;

int32_t monitored_signal(uint32_t sign, uint8_t status, int32_t pid)
{
    int corefd;
    switch(status)
    {
    case MONITORED_STATUS_STOPPED:
        if( sign == SIGTRAP ) sign = 0;
        ptrace(PT_CONTINUE, pid, 0, sign);
        return 0;
    case MONITORED_STATUS_KILLED:
        // here we should do something ...
        // like find the corefile
        if( (corefd = open("core", O_RDONLY)) != -1 )
        {
            char dest_buf[1024];
            close(corefd);
            //yes, system call is bad, etc..
            snprintf( dest_buf, 1024, "mv core %s_%d.core",
                      globname, pid );
            if(system(dest_buf) < 0) 
                abort();
            
        }
        return 0;
    case MONITORED_STATUS_CONT :
    default:
        return 0;
    }

    return 0;
}

int32_t monitored_exit  (int32_t  exit)
{
    return 0;
}

int32_t term_monitored( int32_t i )
{
    return kill ( i, SIGTERM );
}

int32_t spawn_monitored(char *outfile, char *errfile, uint32_t id,char *argv[])
{
    int exit_status = 0;
    pid_t child;
    const struct rlimit inf = {
        RLIM_INFINITY, RLIM_INFINITY };

    printf("[] Attempting to spawn a monitored task.\n");

    setrlimit(RLIMIT_CORE, &inf);
    setenv("MALLOC_CHECK_", "3", 1);

    if (prctl(PR_SET_PDEATHSIG, (long)SIGKILL, 0L, 0L, 0L) == -1) {
        
        exit(-1);
    }

    globname = argv[0];

    switch(child = fork())
    {
    case 0:
        /*CHILD*/

        /*take care of output / input*/
        close(0); close(1); close(2);
        if(open("/dev/null" , O_RDONLY ) != 0)
            exit(1);

        if(open(outfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG) != 1)
            exit(2);

        if(open(errfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG) != 2)
            exit(3);

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
        
        if(ptrace(PT_ATTACH, child, NULL, NULL) == -1)
        {
            term_monitored(child);
            fprintf(stderr, "[SFUZZ-ORACLE] Unable to ptrace attach.\n");
            exit(-1);
        }

        int istatus;
        pid_t status = waitpid(-1, &istatus, WUNTRACED);
        if(status != child) 
        {
            term_monitored(child);
            fprintf(stderr, "[SFUZZ-ORACLE] Error attaching.\n");
            exit(-1);
        }

        if(ptrace(PT_CONTINUE, child, NULL, NULL) == -1)
        {
            term_monitored(child);
            fprintf(stderr, "[SFUZZ-ORACLE] Error continuing.\n");
            exit(-1);
        }

        fprintf(stdout, "[SFUZZ-ORACLE] attached [%u].\n", child);

        do
        {
            status = waitpid(-1, &istatus, WNOHANG);
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
                    monitored_exit( WEXITSTATUS(istatus) );
                    exit_status = 1;
                }
                if (WIFSIGNALED(istatus))
                {
                    monitored_signal( WTERMSIG(istatus), MONITORED_STATUS_KILLED , id);
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
                    monitored_signal(WSTOPSIG(istatus), MONITORED_STATUS_STOPPED, status);
                }
                if (WIFCONTINUED(istatus))
                {
                    printf("[%u] Continued\n", status);
                    monitored_signal(status, MONITORED_STATUS_CONT, status);
                }
            } 
            else
            {
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 100000; /* 100MS do a read / write */
                select(0, NULL, NULL, NULL, &tv);
            }
        } while(!exit_status);
    }
endit:
    return -1;
}


