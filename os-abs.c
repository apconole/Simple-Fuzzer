#include <stdio.h>

#include "options-block.h"
#include "os-abs.h"

#ifdef __WIN32__
#include "winsock.h"
#else
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

extern char *get_time_as_log();
#include <sys/types.h>
#include <unistd.h>

int mssleep(unsigned long int sleepTimeInMS)
{
    struct timeval tv;

    tv.tv_sec = sleepTimeInMS / 1000;
    tv.tv_usec = (sleepTimeInMS % 1000) * 1000;

    return select(0, NULL, NULL, NULL, &tv);
}

void os_send_tcp(option_block *opts, char *str, int len)
{
    FILE *log = stdout;
    struct timeval tv;
    fd_set fds;
#ifdef __WIN32__
    WSADATA wsda;
#endif
    int sockfd;
    struct sockaddr_in server;
    int ret;
    
#ifdef __WIN32__
    WSAStartup(0x0101, &wsda);
#endif
    if(opts->fp_log)
        log = opts->fp_log;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        fprintf(stderr,"[%s] error: unable to acquire socket.\n",
                get_time_as_log());
        fprintf(log,"[%s] error: unable to acquire socket.\n",
                get_time_as_log());
        return;
    }

    server.sin_family = AF_INET;
    server.sin_port   = htons(opts->port);
    server.sin_addr.s_addr = opts->host; /*should be in network order*/
    
    if(connect(sockfd, (struct sockaddr *)&server, sizeof(struct sockaddr)) < 0)
    {
        fprintf(stderr,"[%s] error: unable to connect to remote system.\n",
                get_time_as_log());
        fprintf(log,"[%s] error: unable to connect to remote system.\n",
                get_time_as_log());
        return;
    }

    ret = send(sockfd, str, len, 0);
    
    if(ret < 0)
    {
        fprintf(stderr,"[%s] error: tcp send() failed.\n", get_time_as_log());
        fprintf(log,"[%s] error: tcp send() failed.\n", get_time_as_log());
        return;
    }
    fprintf(log, "[%s] info: tx fuzz - scanning for reply.\n",
            get_time_as_log());

    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);
    tv.tv_sec  = 0;
    tv.tv_usec = 100000; /*give up to 100ms for a check.*/

    ret = select(sockfd+1, &fds, NULL, NULL, &tv);
    if(ret > 0)
    {
        if(FD_ISSET(sockfd, &fds))
        {
            char buf[8192] = {0};
            read(sockfd, &buf, 8192);
            fprintf(log, "[%s] read:\n%s\n===============================================================================\n", 
                    get_time_as_log(),
                    buf);
        }
    }

#ifdef __WIN32__
    WSACleanup();
    closesocket(sockfd);
#else
    close(sockfd);
#endif
    mssleep(opts->reqw_inms);
}

void os_send_udp(option_block *opts, char *str, int len)
{
    FILE *log = stdout;

#ifdef __WIN32__
    WSADATA wsda;
#endif
    int sockfd;
    struct sockaddr_in server;
    int ret;
    
#ifdef __WIN32__
    WSAStartup(0x0101, &wsda);
#endif
    if(opts->fp_log)
        log = opts->fp_log;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        fprintf(stderr,"[%s] error: unable to acquire socket.\n",
                get_time_as_log());
        fprintf(log,"[%s] error: unable to acquire socket.\n",
                get_time_as_log());
        return;
    }

    server.sin_family = AF_INET;
    server.sin_port   = htons(opts->port);
    server.sin_addr.s_addr = opts->host; /*should be in network order*/

    ret = sendto(sockfd, str, len, 0,
               (struct sockaddr *)&server, sizeof(struct sockaddr));
    
    if(ret < 0)
    {
        fprintf(stderr,"[%s] error: udp send() failed.\n", get_time_as_log());
        fprintf(log,"[%s] error: udp send() failed.\n", get_time_as_log());
        return;
    }

#ifdef __WIN32__
    WSACleanup();
    closesocket(sockfd);
#else
    close(sockfd);
#endif
    mssleep(opts->reqw_inms);
}
