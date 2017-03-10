/**
 * Simple Fuzz
 * Copyright (c) 2010, Aaron Conole <apconole@yahoo.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/***
 * Simple Fuzzer server-side plugin (turns SFUZZ into a server instead of a
 * client).
 */

#include <stdio.h>
#include "options-block.h"
#include "os-abs.h"
#include "sfuzz-plugin.h"
#include "sfuzz.h"

#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
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

#include <sys/types.h>
#include <unistd.h>
#include "sfuzz-plugin.h"

static inline int mssleep(unsigned long int sleepTimeInMS)
{
    struct timeval tv;

    tv.tv_sec = sleepTimeInMS / 1000;
    tv.tv_usec = (sleepTimeInMS % 1000) * 1000;

    return select(0, NULL, NULL, NULL, &tv);
}


char *srv_plugin_name()
{
    return "Simple Fuzzer server-side plugin";
}

char *srv_plugin_version()
{
    return "0.1";
}

int srv_plugin_capex()
{
    /*note: you may provide any number of hooks by |'ing together
            each capability to provide. */
    return PLUGIN_PROVIDES_TRANSPORT_TYPE;
}

int srv_plugin_send(option_block *opts, void *d, size_t i)
{
#ifdef __WIN32__
    WSADATA wsaData;
#endif
    FILE *log = stdout;
    struct timeval tv;
    fd_set fds;
    int sockfd = -1;
    int acceptfd = -1;
    int len = i;
    char *str = d;

    struct addrinfo hints, *servinfo, *p;

    int ret;
    int snt = 0;
    unsigned long int to = MAX(100, opts->time_out);

    if(opts->fp_log)
        log = opts->fp_log;

#ifdef __WIN32__
    if(WSAStartup(MAKEWORD(1,1), &wsaData) != 0)
    {
        fprintf(stderr, "[%s]: error: Unable to init winsock!\n",
                "00:00:00");
        fprintf(log, "[%s]: error: Unable to init winsock!\n",
                "00:00:00");
        return -1;
    }
#endif

    
    if(opts->sockfd != -1)
    {
        sockfd = opts->sockfd;
    }
    else
    {
        memset(&hints, 0, sizeof(hints));

        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if(getaddrinfo(opts->host_spec, opts->port_spec, &hints, &servinfo) != 0)
        {
            fprintf(stderr, "[%s]: error: unable to get addrinfo\n",
                    "00:00:00");
            fprintf(log, "[%s]: error: unable to get addrinfo\n",
                    "00:00:00");
#ifdef __WIN32__
            WSACleanup();
#endif
            return -1;
        }
        
        for(p = servinfo; p!= NULL && sockfd == -1; p = p->ai_next)
        {
            int optval = 1;
            sockfd = socket(p->ai_family, p->ai_socktype,
                            p->ai_protocol);
            if(sockfd < 0)
                continue;

            opts->sockfd = sockfd;

            (void)setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, 
                             sizeof(optval));
            
            if(bind(sockfd, 
                    p->ai_addr, p->ai_addrlen) < 0)
            {
#ifdef __WIN32__
                closesocket(sockfd);
#else
                close(sockfd);
#endif
                sockfd = -1;
                continue;
            }

            if(listen(sockfd, 1) < 0)
            {                
#ifdef __WIN32__
                closesocket(sockfd);
#else
                close(sockfd);
#endif
                sockfd = -1;
                continue;
            }
        }
        freeaddrinfo(servinfo);
    }

    if(sockfd == -1)
    {
        fprintf(stderr,
                "[%s] error: unable to connect to remote system [%s].\n",
                "00:00:00", process_error());
        fprintf(log,
                "[%s] error: unable to connect to remote system [%s].\n",
                "00:00:00", process_error());
#ifdef __WIN32__
        WSACleanup();
#endif
        return -1;
    }

    acceptfd = accept(sockfd, NULL, 0);
    while(len)
    {
        ret = send(acceptfd, str + snt, len, 0);
    
        if(ret < 0)
        {
            fprintf(stderr,"[%s] error: tcp send() failed.\n", "00:00:00");
            fprintf(log,"[%s] error: tcp send() failed.\n", "00:00:00");
#ifdef __WIN32__
            closesocket(sockfd);
            closesocket(acceptfd);
            WSACleanup();
#else
            close(sockfd);
            close(acceptfd);
#endif
            return -1;
        }
        len -= ret;
        snt += ret;
    }
    

    if(opts->verbosity != QUIET)
        fprintf(log, "[%s] info: tx fuzz - (%d bytes) - scanning for reply.\n",
                "00:00:00", snt);
    
    FD_ZERO(&fds);
    FD_SET(acceptfd, &fds);

    tv.tv_sec  = to / 1000;
    tv.tv_usec = (to % 1000) * 1000; /*time out*/

    mssleep(opts->reqw_inms);

    ret = select(acceptfd+1, &fds, NULL, NULL, &tv);
    if(ret > 0)
    {
        if(FD_ISSET(acceptfd, &fds))
        {
            char buf[8193] = {0};
            int r_len = 0;
            r_len = read(acceptfd, &buf, 8192);
            buf[8192] = 0;
            if(opts->verbosity != QUIET)
                fprintf(log, "[%s] read:\n%s\n===============================================================================\n", 
                        "00:00:00",
                        buf);
            if((opts->s_syms_count) && (opts->repl_pol))
            {
                for(ret = 0; ret < opts->s_syms_count; ++ret)
                {
                    sym_t *pSym = &(opts->s_syms[ret]);
                    int    cpy_len = pSym->is_len;

                    if((opts->repl_pol == 2) &&
                       pSym->increment)
                        continue;

                    if(cpy_len > r_len)
                        continue;
                    memset(pSym->sym_val, 0, 1024);
                    memcpy(pSym->sym_val, buf+(pSym->offset),cpy_len);
                    pSym->sym_val[cpy_len] = 0;
                    pSym->s_len = cpy_len;
                    pSym->increment = 1;
                }
            }
        }
    }
    
    if(opts->close_conn)
    {
        opts->sockfd = -1;
    }
    
    if((opts->close_conn) && (!opts->forget_conn))
    {
#ifdef __WIN32__
        closesocket(sockfd);
        closesocket(acceptfd);
#else
        close(sockfd);
        close(acceptfd);
#endif
    }
    
#ifdef __WIN32__
    WSACleanup();
#endif
    return 0;
}

void plugin_init(plugin_provisor *pr)
{
  if(pr == NULL)
  {
      /*this is checked by the calling function, but
        I'd like to reinforce the idea of paranoia*/
      fprintf(stderr, 
              "<srv_plugin:init> null plugin object (perhaps a bug?!)\n");
      return;
  }

  pr->capex   = srv_plugin_capex;
  pr->name    = srv_plugin_name;
  pr->version = srv_plugin_version;
  pr->trans   = srv_plugin_send;
}

