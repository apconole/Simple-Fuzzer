#include <stdio.h>

#include "options-block.h"
#include "os-abs.h"

#ifdef __WIN32__
#include "winsock.h"
typedef char * caddr_t;
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

#include <errno.h>
#endif

extern char *get_time_as_log();
#include <sys/types.h>
#include <unistd.h>

int atoip(const char *pIpStr)
{
    struct hostent *ent;
    struct sockaddr_in sa;
#ifdef __WIN32__
    WSADATA wsda;

    WSAStartup(0x101, &wsda);
#endif
    int t = inet_addr(pIpStr);
    
    if(inet_addr(pIpStr) == -1)
    {
        ent = gethostbyname(pIpStr);
        if(ent != NULL)
        {
            if(ent->h_addrtype != AF_INET)
            {
                fprintf(stderr, "[%s] error: address/host '%s' not of AF_INET.\n",
                        get_time_as_log(), pIpStr);
                exit(-1);
            }
            else
            {
                memcpy ((caddr_t) & sa.sin_addr, ent->h_addr, ent->h_length);
                t = sa.sin_addr.s_addr;
            }
        }
        else
        {
            fprintf(stderr, "[%s] error: address/host '%s' unknown.\n",
                    get_time_as_log(), pIpStr);
            exit(-1);
        }
    }

#ifdef __WIN32__
    WSACleanup();
#endif

    return t;
}

char *process_error()
{
#ifndef __WIN32__
    switch(errno)
    {
/*
    case EACCESS:
        return "EACCESS";
*/
    case EPERM:
        return "EPERM";
    case EADDRINUSE:
        return "EADDRINUSE";
    case EAFNOSUPPORT:
        return "EAFNOSUPPORT";
    case EAGAIN:
        return "EAGAIN";
    case EALREADY:
        return "EALREADY";
    case EBADF:
        return "EBADF";
    case ECONNREFUSED:
        return "ECONNREFUSED";
    case EINPROGRESS:
        return "EINPROGRESS";
    case EINTR:
        return "EINTR";
    case EISCONN:
        return "EISCONN";
    case ENETUNREACH:
        return "ENETUNREACH";
    case ENOTSOCK:
        return "ENOTSOCK";
    case ETIMEDOUT:
        return "ETIMEDOUT";
    default:
        perror("connect()");
    }
#endif
    return "unknown";
}

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
    
    if(opts->sockfd != -1)
    {
        sockfd = opts->sockfd;
    }
    else
    {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        opts->sockfd = sockfd;
        
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
        
        if(connect(sockfd, 
                   (struct sockaddr *)&server, sizeof(struct sockaddr)) < 0)
        {
            fprintf(stderr,
                    "[%s] error: unable to connect to remote system [%s].\n",
                    get_time_as_log(), process_error());
            fprintf(log,
                    "[%s] error: unable to connect to remote system [%s].\n",
                    get_time_as_log(), process_error());
            return;
        }
    }

    ret = send(sockfd, str, len, 0);
    
    if(ret < 0)
    {
        fprintf(stderr,"[%s] error: tcp send() failed.\n", get_time_as_log());
        fprintf(log,"[%s] error: tcp send() failed.\n", get_time_as_log());
        return;
    }
    if(!opts->quiet)
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

    if(opts->close_conn)
    {
#ifdef __WIN32__
        WSACleanup();
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        opts->sockfd = -1;
    }
    
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

int isws(char c)
{
    /*comment out the following for only replacing stuff with no whitespace*/
    return 1;
    return ((c == ' ') || (c == '\n') || (c == '\r') || (c == '\t') ||
            (c == '\b'));
}

int strrepl(char *buf, size_t buflen, char *old, char *new)
{
    char *f;
    char *str = buf;
    int   repls = 0;

    int   origl = strlen(buf);
    int   oldl  = strlen(old);
    int   newl  = strlen(new);

    if((buf == NULL) || (old == NULL) || (new == NULL) || (buflen == 0))
        return -1;

    while((f = strstr(str, old)) != NULL)
    {
        if(!isws(*(f+oldl)))
        {
            str = f + oldl;
            continue;
        }
        ++repls;

        origl -= oldl;

        if(origl < 0)
            origl = 0;

        origl += newl;

        memmove(f+newl, f+oldl, strlen(f+oldl)+1);
        memcpy(f, new, newl);

        str = f + oldl;
    }
    return origl;
}
