/**
 * Simple Fuzz
 * Copyright (c) 2009-2015, Aaron Conole <apconole@yahoo.com>
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

#include <stdio.h>

#include "options-block.h"
#include "os-abs.h"
#include "sfuzz-plugin.h"
#include "sfuzz-plugin-internal.h"

#ifdef __WIN32__
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#include <wspiapi.h>
#endif
#include <sys/time.h>
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
#include <sys/un.h>

#include <errno.h>
#endif

#include <sys/types.h>
#include <unistd.h>

unsigned char convertAsciiHexCharToBin(char asciiHexChar)
{
    unsigned char binByte = 0xFF;
    if((asciiHexChar >= '0') && (asciiHexChar <= '9'))
    {
        binByte = asciiHexChar - '0';
    }
    else if((asciiHexChar >= 'a') && (asciiHexChar <= 'f'))
    {
        binByte = asciiHexChar - 'a' + 0x0A;
    }
    else if((asciiHexChar >= 'A') && (asciiHexChar <= 'f'))
    {
        binByte = asciiHexChar - 'A' + 0x0A;
    }
    return binByte;
}


unsigned int ascii_to_bin(unsigned char *str_bin)
{
    /*converts an ascii string to binary*/
    unsigned char *out = malloc(8192);
    unsigned char *str = malloc(8192);
    int size_no_ws = 0;
    int outBufIdx = 0;
    int binBufIdx = 0;

    int rewind = strlen((const char *)str_bin);

    unsigned char firstNibble;
    unsigned char secondNibble;

    if( !str || !out ) goto out_end;

    *str = 0;
    
    while(*str_bin != 0)
        if(*str_bin++ != ' ')
        {
            if(*(str_bin-1) == 'x')
            {
                *(str_bin-2) = *(str_bin-1)=' ';
                --size_no_ws;
                continue;
            }
            
            str[size_no_ws] = *(str_bin-1);
            size_no_ws++;
        }

    str_bin -= rewind;

    if((size_no_ws % 2) != 0)
    {
        firstNibble = 0;
        secondNibble = convertAsciiHexCharToBin(str[0]);
        if(secondNibble == 0xFF)
        {
            free(out);
            free(str);
            return -1;
        }
        out[outBufIdx] = ((firstNibble<<4)&0xF0) | (secondNibble &0xF);
        outBufIdx++;
        binBufIdx = 1;
    }
    
    for(; binBufIdx < size_no_ws; binBufIdx += 2)
    {
        firstNibble = convertAsciiHexCharToBin(str[binBufIdx]);
        secondNibble = convertAsciiHexCharToBin(str[binBufIdx+1]);
        
        if((firstNibble == 0xFF) || (secondNibble == 0xFF))
        {
            free(out);
            free(str);
            return -1;
        }
        out[outBufIdx] = ((firstNibble<<4)&0xF0)|(secondNibble&0xF);
        outBufIdx++;
    }

/*debugging
  dump(out, outBufIdx);
*/
    memcpy(str_bin, out, outBufIdx);

 out_end:
    free(out);
    free(str);

    return outBufIdx;

}


char *get_time_as_log()
{
    static char buffer[40];
    struct timeval tv;
    time_t curtime;

    gettimeofday(&tv, NULL);
    curtime = tv.tv_sec;

/* enable once I figure out how to get relative time working.
    curtime = curtime - birth;
*/

    strftime(buffer, 40, "%H:%M:%S", localtime(&curtime));
    
    return buffer;
}

/* this is going to be crappy! */
int atoip(const char *pIpStr)
{
#ifdef __WIN32__
    WSADATA wsaData;
#endif
    struct addrinfo hints, *servinfo, *p;
    int t = 0;
#ifdef __WIN32__
    if(WSAStartup(MAKEWORD(2,0), &wsaData) != 0)
    {
        fprintf(stderr, "[%s]: error: Unable to init winsock!\n",
                get_time_as_log());
        return -1;
    }
#endif

    memset(&hints, 0, sizeof(hints));

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(pIpStr, NULL, &hints, &servinfo) != 0)
        return 0;

    for(p = servinfo; p != NULL; p = p->ai_next)
    {
        if(p->ai_family == AF_INET)
        {
            t = ((struct sockaddr_in*)(p->ai_addr))->sin_addr.s_addr;
            break;
        }
        else if(p->ai_family == AF_INET6)
            t = 1; /* for IPv6 we treat it as a "true" value */
        else
            t = 0;
    }

    freeaddrinfo(servinfo);
#ifdef __WIN32__
    WSACleanup();
#endif    
    return t;
}

int mssleep(unsigned long int sleepTimeInMS)
{
    struct timeval tv;

    tv.tv_sec = sleepTimeInMS / 1000;
    tv.tv_usec = (sleepTimeInMS % 1000) * 1000;

    return select(0, NULL, NULL, NULL, &tv);
}

int os_send_tcp(option_block *opts, char *str, size_t len)
{
#ifdef __WIN32__
    WSADATA wsaData;
#endif
    FILE *log = stdout;
    struct timeval tv;
    fd_set fds;
    int sockfd = -1;

    struct addrinfo hints, *servinfo, *p;

    int ret;
    int snt = 0;
    unsigned long int to = MAX(100, opts->time_out);

    if(opts->fp_log)
        log = opts->fp_log;

#ifdef __WIN32__
    if(WSAStartup(MAKEWORD(2,0), &wsaData) != 0)
    {
        fprintf(stderr, "[%s]: error: Unable to init winsock!\n",
                get_time_as_log());
        fprintf(log, "[%s]: error: Unable to init winsock!\n",
                get_time_as_log());
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
                    get_time_as_log());
            fprintf(log, "[%s]: error: unable to get addrinfo\n",
                    get_time_as_log());
#ifdef __WIN32__
            WSACleanup();
#endif
            return -1;
        }
        
        for(p = servinfo; p!= NULL; p = p->ai_next)
        {
            sockfd = socket(p->ai_family, p->ai_socktype,
                            p->ai_protocol);
            if(sockfd < 0)
                continue;

            opts->sockfd = sockfd;
            
            if(connect(sockfd, 
                       p->ai_addr, p->ai_addrlen) < 0)
            {
#ifdef __WIN32__
                closesocket(sockfd);
#else
                close(sockfd);
#endif
                opts->sockfd = sockfd = -1;
                continue;
            }
            break; /* faster than setting p = NULL; (I think)*/
        }
        freeaddrinfo(servinfo);
    }

    if(sockfd == -1)
    {
        fprintf(stderr,
                "[%s] error: unable to connect to remote system [%s].\n",
                get_time_as_log(), process_error());
        fprintf(log,
                "[%s] error: unable to connect to remote system [%s].\n",
                get_time_as_log(), process_error());
#ifdef __WIN32__
        WSACleanup();
#endif
        return -1;
    }

    while(len)
    {
        ret = send(sockfd, str + snt, len, 0);
    
        if(ret < 0)
        {
            fprintf(stderr,"[%s] error: tcp send() failed.\n", get_time_as_log());
            fprintf(log,"[%s] error: tcp send() failed.\n", get_time_as_log());
#ifdef __WIN32__
            WSACleanup();
#endif
            return -1;
        }
        len -= ret;
        snt += ret;
    }
    

    if(opts->verbosity != QUIET)
        fprintf(log, "[%s] info: tx fuzz - (%d bytes) - scanning for reply.\n",
                get_time_as_log(), snt);
    
    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);

    tv.tv_sec  = to / 1000;
    tv.tv_usec = (to % 1000) * 1000; /*time out*/

    mssleep(opts->reqw_inms);

    ret = select(sockfd+1, &fds, NULL, NULL, &tv);
    if(ret > 0)
    {
        if(FD_ISSET(sockfd, &fds))
        {
            char buf[8193] = {0};
            int r_len = 0;
            r_len = read(sockfd, &buf, 8192);
            buf[8192] = 0;
            if(opts->verbosity != QUIET)
                fprintf(log, "[%s] read:\n%s\n===============================================================================\n", 
                        get_time_as_log(),
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
#ifndef NOPLUGIN
            if((g_plugin != NULL) &&
               ((g_plugin->capex() & PLUGIN_PROVIDES_POST_FUZZ) ==
                PLUGIN_PROVIDES_POST_FUZZ))
            {
                g_plugin->post_fuzz(opts, buf, r_len);
            }
#endif
        }
    }
    
    if(opts->close_conn)
        opts->sockfd = -1;
    
    if((opts->close_conn) && (!opts->forget_conn))
    {
#ifdef __WIN32__
        closesocket(sockfd);
#else
        close(sockfd);
#endif
    }
    
#ifdef __WIN32__
    WSACleanup();
#endif
    return 0;
}

int os_send_udp(option_block *opts, char *str, size_t len)
{
#ifdef __WIN32__
    WSADATA wsaData;
#endif

    FILE *log = stdout;
    struct timeval tv;
    fd_set fds;
    unsigned long int to = MAX(100, opts->time_out);
    struct addrinfo hints, *servinfo, *p;
    int sockfd = -1;
    int ret;
    
    if(opts->fp_log)
        log = opts->fp_log;
    
#ifdef __WIN32__
    if(WSAStartup(MAKEWORD(2,0), &wsaData) != 0)
    {
        fprintf(stderr, "[%s]: error: Unable to init winsock!\n",
                get_time_as_log());
        fprintf(log, "[%s]: error: Unable to init winsock!\n",
                get_time_as_log());
        return -1;
    }
#endif

    memset(&hints, 0, sizeof(hints));
    
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    
    if(getaddrinfo(opts->host_spec, opts->port_spec, &hints, &servinfo) != 0)
    {
        fprintf(stderr, "[%s]: error: unable to get addrinfo\n",
                get_time_as_log());
        fprintf(log, "[%s]: error: unable to get addrinfo\n",
                get_time_as_log());
#ifdef __WIN32__
        WSACleanup();
#endif
        return -1;
    }

    for(p = servinfo; p!= NULL; p = p->ai_next)
    {
        sockfd = socket(p->ai_family, p->ai_socktype,
                        p->ai_protocol);
        if(sockfd < 0)
            continue;

        opts->sockfd = sockfd;
        break; /* p won't be equal to NULL in this case */
    }

    if(p == NULL)
    {
        fprintf(stderr,"[%s] error: unable to acquire socket.\n",
                get_time_as_log());
        
        fprintf(log,"[%s] error: unable to acquire socket.\n",
                get_time_as_log());
        freeaddrinfo(servinfo);
#ifdef __WIN32__
        WSACleanup();
#endif
        return -1;
    }
    
    ret = sendto(sockfd, str, len, 0,
                 p->ai_addr, p->ai_addrlen);

    freeaddrinfo(servinfo);
    
    if(ret < 0)
    {
        fprintf(stderr,"[%s] error: udp send() failed.\n", get_time_as_log());
        fprintf(log,"[%s] error: udp send() failed.\n", get_time_as_log());
#ifdef __WIN32__
        WSACleanup();
#endif
        return -1;
    }

    if(opts->verbosity != QUIET)
        fprintf(log, "[%s] info: tx fuzz - scanning for reply.\n",
                get_time_as_log());
    
    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);

    tv.tv_sec  = to / 1000;
    tv.tv_usec = (to % 1000) * 1000; /*time out*/

    mssleep(opts->reqw_inms);

    ret = select(sockfd+1, &fds, NULL, NULL, &tv);
    if(ret > 0)
    {
        if(FD_ISSET(sockfd, &fds))
        {
            char buf[8193] = {0};
            int r_len = 0;
            r_len = read(sockfd, &buf, 8192);
            buf[8192] = 0;
            if(opts->verbosity != QUIET)
                fprintf(log, "[%s] read:\n%s\n===============================================================================\n", 
                        get_time_as_log(),
                        buf);
#ifndef NOPLUGIN
            if((g_plugin != NULL) &&
               ((g_plugin->capex() & PLUGIN_PROVIDES_POST_FUZZ) ==
                PLUGIN_PROVIDES_POST_FUZZ))
            {
                g_plugin->post_fuzz(opts, buf, r_len);
            }
#endif

            
        }
    }
#ifdef __WIN32__
    closesocket(sockfd);
    WSACleanup();
#else
    close(sockfd);
#endif
    return 0;
}

int os_send_unix_stream(option_block *opts, char *str, size_t len)
{
#ifdef __WIN32__
    return -1;
#endif

    FILE *log = stdout;
    struct sockaddr_un sa_unix;
    int sockfd = -1;

    if(opts->fp_log)
        log = opts->fp_log;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd != -1)
    {
        sa_unix.sun_family = AF_UNIX;
        snprintf(sa_unix.sun_path, sizeof(sa_unix.sun_path), "%s",
                 opts->host_spec);
        if(connect(sockfd, (const struct sockaddr *)&sa_unix,
                   sizeof sa_unix) < 0)
        {
            close(sockfd);
            fprintf(log, "[%s] error: unable to connect to unix socket [%s]\n",
                    get_time_as_log(), process_error());
            return -1;
        }

        // connected - send
        if (send(sockfd, str, len, 0) < 0){
            // handle the failure case...
        }

        if (opts->verbosity != QUIET)
            fprintf(log, "[%s] info: tx fuzz - scanning for reply.\n",
                    get_time_as_log());

        close(sockfd);
        return 0;
        
    }
    return -1;
}

int os_send_unix_dgram(option_block *opts, char *str, size_t len)
{
#ifdef __WIN32__
    return -1;
#endif

    FILE *log = stdout;
    struct sockaddr_un sa_unix;
    int sockfd = -1;
    
    if(opts->fp_log)
        log = opts->fp_log;

    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd != -1)
    {
        sa_unix.sun_family = AF_UNIX;
        snprintf(sa_unix.sun_path, sizeof(sa_unix.sun_path), "%s",
                 opts->host_spec);

        if (sendto(sockfd, str, len, 0,
                   (const struct sockaddr *)&sa_unix, sizeof sa_unix) < 0 ) {
            // handle the failure case...
        }

        if (opts->verbosity != QUIET)
            fprintf(log, "[%s] info: tx fuzz - scanning for reply.\n",
                    get_time_as_log());

        close(sockfd);
        return 0;
    }
    return -1;
}

void *__internal_memmem(const void *hs, size_t hsl, const void *nd, size_t ndl)
{
    const char *start;
    const char *l_occurance = (const char *)hs+hsl-ndl;

    if(ndl == 0)
        return (void *)hs;

    if(hsl < ndl)
        return NULL;

    for(start = (const char *)hs; start <= l_occurance; ++start)
        if((start[0] == ((const char *)nd)[0]) &&
           !memcmp((const void *)&start[1],
                   (const void *)((const char *)nd+1),
                   ndl-1))
            return (void *)start;
    return NULL;
}

int strrepl(char *buf, size_t buflen, char *old, char *new)
{
    char *f;
    char *str = buf;
    int   repls = 0;

    int   origl;
    int   oldl;
    int   newl;

    if((buf == NULL) || (old == NULL) || (new == NULL) || (buflen == 0))
        return -1;

    newl = strlen(new);
    oldl = strlen(old);
    origl = strlen(buf);
    
    while((f = strstr(str, old)) != NULL)
    {
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

int smemrepl(char *buf, size_t buflen, size_t maxlen, char *old, char *new, int newl)
{
    char *f;
    char *str = buf;
    int   repls = 0;

    int   origl = buflen;
    int   oldl;

    if((buf == NULL) || (old == NULL) || (new == NULL) || (buflen == 0)) {
        fprintf(stderr, "FATAL: invalid arguments passed, cowardly aborting\n");
        exit(1);
    }
    oldl  = strlen(old);
    
    while((f = __internal_memmem(str, (buf + buflen) - str, old, oldl)) 
          != NULL)
    {
        ++repls;

        if( ( (f+newl) < buf) || ( (f+newl) > (buf + maxlen) ) )
            return origl;
        else if ( (((f+oldl) < buf)) || ( (f+oldl) > (buf+maxlen)) )
            return origl;
        else if ( origl - (f - buf ) > maxlen ) return origl;

        if(origl - oldl < 0)
        {
            origl = 0;
            return 0;
        }

        memmove(f+newl, f+oldl, (buf + origl) - (f+oldl) );

        memcpy(f, new, newl);

        str = f + newl;

        origl -= oldl;
        origl += newl;
    }
    return origl;
}

void dump(void* b, int len, FILE *dump){
    unsigned char *buf = b;
    int i, cnt=0;
    char str[17];
    FILE *out = stdout;
    memset(str, 0, 17);

    if(dump != NULL)
        out = dump;

    for ( i = 0; i < len; i++ ){
        if ( cnt % 16 == 0 ){
            fprintf(out, "  %s\n%04X: ", str, cnt);
            memset(str, 0, 17);
        }
        if ( buf[cnt] < ' '  ||  buf[cnt] >= 127 )
            str[cnt%16] = '.';
        else
            str[cnt%16] = buf[cnt];
        fprintf(out, "%02X ", buf[cnt++]);
    }
    fprintf(out, "  %*s\n\n", 16+(16-len%16)*2, str);
}

#ifdef __WIN32__

/*this is a "workaround" for the fact that windows isn't 'compliant' and
  has it's own dynamic loading functions. basically, we'll just wrap them
  here.
  It's noteworthy that these are very quick 'n dirty, and shouldn't be taken
  as a terribly good replacement. just something that works.
*/

/*return a handle to a .dll/.so file*/
void *dlopen(char *name, int opts)
{
    HMODULE hModule;
    UINT uMode;

    /*disable the critical error dialog.*/
    uMode = SetErrorMode( SEM_FAILCRITICALERRORS );
    
    if( name == NULL )
    {
        hModule = GetModuleHandle( NULL );
    }
    else
    {
        strrepl(name, strlen(name), "/", "\\");
        hModule = LoadLibraryEx( (LPSTR) name, NULL,
                                 LOAD_WITH_ALTERED_SEARCH_PATH);
    }

    SetErrorMode ( uMode );
    return (void *)hModule;
}

/*get an entrypoint in the function.*/
void *dlsym(void *handle, const char *symbol_name)
{
    FARPROC symbol = GetProcAddress(handle, symbol_name);
    
    return (void *) symbol;
}

/*should make this better*/
char *dlerror()
{
    return "Windows not supported for error reporting!";
}
#endif
