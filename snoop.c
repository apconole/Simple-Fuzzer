/**
 * Simple Fuzz
 * Copyright (c) 2009, Aaron Conole <apconole@yahoo.com>
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

#ifdef __WIN32__
#include "windows.h"
#include "winsock2.h"

#ifndef SIO_RCVALL
//#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#define SIO_RCVALL  0x98000001
#endif

#define ERROR_PRINT _PANIC_

#define INCREMENT_CAP   0
#define SOCK_FAM_TYPE   AF_INET
#define SOCK_PROTO_TYPE IPPROTO_RAW
typedef unsigned int uint;
#else
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#define ERROR_PRINT perror

#ifdef __LINUX__
#include <netinet/if_ether.h>
#define INCREMENT_CAP   14
#define SOCK_FAM_TYPE   PF_PACKET
#define SOCK_PROTO_TYPE htons(ETH_P_IP)
#endif
#endif

int debug = 0;
int addr=0;

#include "os-abs.h"

#define IP_SIZE  4
#define ETH_SIZE 6

typedef enum { eETH_ADDR, eIP_ADDR } EAddress;

typedef unsigned char uchar;

/*--------------------------------------------------------------------*/
/* This structure defines the fields within the ip frame. Since this  */
/* program gets the lowest-level packet, fragmented packets are not   */
/* reassembled.  The first few fields contain the MAC addresses of the*/
/* source and destination. Note that this structure is set for little-*/
/* endian format.                                                    */
/* So I cheated and stole someone else's ip header... sue me          */
/*--------------------------------------------------------------------*/
struct ip_packet {
    uint header_len:4;       /* header length in words in 32bit words */
    uint version:4;          /* 4-bit version */
    uint serve_type:8;       /* how to service packet */
    uint packet_len:16;      /* total size of packet in bytes */
    uint ID:16;              /* fragment ID */
    uint frag_offset:13;     /* to help reassembly */
    uint more_frags:1;       /* flag for "more frags to follow" */
    uint dont_frag:1;        /* flag to permit fragmentation */
    uint __reserved:1;       /* always zero */
    uint time_to_live:8;     /* maximum router hop count */
    uint protocol:8;         /* ICMP, UDP, TCP */
    uint hdr_chksum:16;      /* ones-comp. checksum of header */
    uchar IPv4_src[IP_SIZE]; /* IP address of originator */
    uchar IPv4_dst[IP_SIZE]; /* IP address of destination */
    uchar options[0];        /* up to 40 bytes */
    uchar data[0];           /* message data up to 64KB */
};

void DebugPrint(char *buf){
#ifdef DEBUG
    printf("DEBUG - %s\n", buf);
#endif /* DEBUG */
}

#include "sfuzz-plugin.h"

plugin_provisor *g_plugin;

void PrintAddr(char* msg, unsigned char *addr, EAddress is_ip){
    int i;
    static struct {
        int len;
        char *fmt;
        char delim;
    } addr_fmt[] = {{ETH_SIZE, "%x", ':'}, {IP_SIZE, "%d", '.'}};

    if(msg != NULL)
        printf("%s", msg);
    for ( i = 0; i < addr_fmt[is_ip].len; i++ ){
        printf(addr_fmt[is_ip].fmt, addr[i]);
        if ( i < addr_fmt[is_ip].len-1 )
            putchar(addr_fmt[is_ip].delim);
    }
}



char *GetProtocol(int value){
    switch (value){
    case IPPROTO_IP: return "IP";
    case IPPROTO_ICMP: return "ICMP";
    case IPPROTO_IGMP: return "IGMP";
#ifndef __WIN32__
    case IPPROTO_PIM: return "PIM";
    case IPPROTO_RSVP: return "RSVP";
    case IPPROTO_GRE: return "GRE";
    case IPPROTO_IPIP: return "IPIP";
    case IPPROTO_EGP: return "EGP";
#endif
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_PUP: return "PUP";
    case IPPROTO_UDP: return "UDP";
    case IPPROTO_IDP: return "IDP";
    case IPPROTO_IPV6: return "IPV6/4";
    case IPPROTO_RAW: return "RAW";
    default: return "???";
    }
}

int ipcmp(uchar *ipstruct_addr, int addr)
{
    int ipstr_addr = *((int*)ipstruct_addr);
    if(debug)
        printf("[%X]:[%X]\n", addr, ipstr_addr);
    
    return (addr)?(addr == ipstr_addr) : 1;
}

void DumpPacket(char *buffer, int len){
    struct ip_packet *ip=(void*)(buffer);

    if(!ipcmp(ip->IPv4_src, addr) &&
       !ipcmp(ip->IPv4_dst, addr))
        return;

    do{
        printf("-------------------------------------------------\n");
        dump(buffer, len, NULL);
//        PrintAddr("Destination EtherID=", ip->hw_header.dst_eth, eETH_ADDR);
//        PrintAddr(", Source EtherID=", ip->hw_header.src_eth, eETH_ADDR);
        printf("\nIPv%d: header-len=%d, type=%d, packet-size=%d, ID=%d\n",
               ip->version, ip->header_len*4, ip->serve_type,
               ntohs(ip->packet_len), ntohs(ip->ID));
        printf("frag=%c, more=%c, offset=%d, TTL=%d, protocol=%s\n",
               (ip->dont_frag? 'N': 'Y'),
               (ip->more_frags? 'N': 'Y'),
               ip->frag_offset,
               ip->time_to_live, GetProtocol(ip->protocol));
        printf("checksum=%d, ", ntohs(ip->hdr_chksum));
        PrintAddr("source=", ip->IPv4_src, eIP_ADDR);
        PrintAddr(", destination=", ip->IPv4_dst, eIP_ADDR);
        printf("\n");
        fflush(stdout);
    }while(0);
}

void PANIC(char *msg);

#ifdef __WIN32__
void _PANIC_(char *msg)
{
    int err = WSAGetLastError();
    printf("%s: ", msg);
    switch(err)
    {
    case WSA_IO_PENDING:
        printf("completion to be indicated later.\n");
        break;
    case WSAEINVAL:
        printf("invalid option\n");
        break;
    case WSAEWOULDBLOCK:
        printf("non-blocking socket performing blocking operation.\n");
        break;
    case WSAENOPROTOOPT:
        printf("invalid protocol option\n");
        break;
    case WSAENOTSOCK:
        printf("not a socket.\m");
        break;
    case WSAEINPROGRESS:
        printf("function is in progress.\n");
        break;
    case WSAEOPNOTSUPP:
        printf("option not supported.\n");
        break;
    case WSAEFAULT:
        printf("WSAEFAULT!\n");
        break;
    case WSAENETDOWN:
        printf("network down.\n");
        break;
    default:
        printf("unknown or no error [%d].\n", err);
    }
}
#endif

#define PANIC(msg){ERROR_PRINT(msg);exit(0);}

int main(int argc, char *argv[])
{
    int sd=-1, bytes_read;
    char data[1024];
    
    struct sockaddr_in sa;
    uint sl;

#ifdef __WIN32__
    int ON = 1;
    WSADATA wsaData;

    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    if(argc > 1)
    {
        addr = atoip(argv[1]);
        printf("Filtering on addr[%s] [", argv[1]);
        PrintAddr(NULL, (unsigned char *)&addr, eIP_ADDR);
        printf("].\n");
    }
    
    /*doesn't work with OS X*/
    sd = socket(SOCK_FAM_TYPE, SOCK_RAW, SOCK_PROTO_TYPE);
    if ( sd < 0 )
        PANIC("Snooper socket");

#ifdef __WIN32__
    printf("Seems you're using windows. Due to a wacky way in which WINSOCK\n");
    printf("works, you need to enter the IP address of your local interface\n");
    printf("on which you'd like to sniff.\n");
    printf(": ");
    fflush(stdout);
    fgets(data, 1024, stdin);

    memset(&sa, 0, sizeof(sa));
    sa.sin_addr.s_addr = atoip(data);
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    
    if(bind(sd, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR)
        PANIC("bind");
    
    if(ioctlsocket(sd, SIO_RCVALL, &ON) == SOCKET_ERROR)
        PANIC("SIO_RCVALL");
#endif

    do {
        sl = sizeof(struct sockaddr_in);
        bytes_read = recvfrom(sd, data, sizeof(data), 0, &sa, &sl);
        
        if ( bytes_read > 0 )
        {
            DumpPacket(data+INCREMENT_CAP, bytes_read);
        }
        else if(bytes_read == -1)
            PANIC("Snooper read");

    } while ( bytes_read > 0 );

    return 0;
}
