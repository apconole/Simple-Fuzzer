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

#define __LITTLE_ENDIAN__

#define INCREMENT_CAP   0
#define SOCK_FAM_TYPE   AF_INET
#define SOCK_PROTO_TYPE IPPROTO_RAW
typedef unsigned int uint;
#else
#include <sys/param.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#define ERROR_PRINT perror

#ifdef __BYTE_ORDER
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define __LITTLE_ENDIAN__
# else
#  if __BYTE_ORDER == __BIG_ENDIAN
#   define __BIG_ENDIAN__
#  else
#   error "Unknown byte order"
#  endif
# endif /* __BYTE_ORDER */
#endif

#ifdef __LINUX__
#include <netinet/if_ether.h>
#define SOCK_FAM_TYPE   PF_PACKET
#define SOCK_PROTO_TYPE htons(ETH_P_ALL)
#endif
#endif

int debug = 0;

#include "os-abs.h"

#define IP_SIZE  4

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define ETH_SRC_FILTER       0x00000001
#define ETH_DST_FILTER       0x00000002
#define ETH_TYPE_FILTER      0x00000004
#define ETH_VLAN_FILTER      0x00000008
#define IP_SRC_FILTER        0x00000010
#define IP_DST_FILTER        0x00000020
#define IP_PROTO_FILTER      0x00000040
#define UDP_TCP_SPORT_FILTER 0x00000080
#define UDP_TCP_DPORT_FILTER 0x00000100

typedef unsigned char uchar;


uint  filter_mask = 0;
uchar eth_src_is_mac_filter[ETH_ALEN];
uchar eth_dst_is_mac_filter[ETH_ALEN];
uint  eth_type_is_filter;
uint  eth_vlan_is_filter;
uint  ip_src_is_filter;
uint  ip_dst_is_filter;
uint  ipproto_is_filter;
uint  udp_tcp_sport_is_filter;
uint  udp_tcp_dport_is_filter;


typedef enum { eETH_ADDR, eIP_ADDR } EAddress;


/*--------------------------------------------------------------------*/
/* This structure defines the fields within the ip frame. Since this  */
/* program gets the lowest-level packet, fragmented packets are not   */
/* reassembled.  The first few fields contain the MAC addresses of the*/
/* source and destination. Note that this structure is set for little-*/
/* endian format.                                                    */
/* So I cheated and stole someone else's ip header... sue me          */
/*--------------------------------------------------------------------*/
#pragma pack(1)
struct ip_packet {
#ifdef __LITTLE_ENDIAN__
    uint header_len:4;       /* header length in words in 32bit words */
    uint version:4;          /* 4-bit version */
#else
    uint version:4;
    uint header_len:4;
#endif
    uint serve_type:8;       /* how to service packet */
    uint packet_len:16;      /* total size of packet in bytes */
    uint ID:16;              /* fragment ID */

#ifdef __LITTLE_ENDIAN__
    uint frag_offset:13;     /* to help reassembly */
    uint more_frags:1;       /* flag for "more frags to follow" */
    uint dont_frag:1;        /* flag to permit fragmentation */
    uint __reserved:1;       /* always zero */
#else
    uint __reserved:1;
    uint more_frags:1;
    uint dont_frag:1;
    uint frag_offset:13;
#endif

    uint time_to_live:8;     /* maximum router hop count */
    uint protocol:8;         /* ICMP, UDP, TCP */
    uint hdr_chksum:16;      /* ones-comp. checksum of header */

    uchar IPv4_src[IP_SIZE]; /* IP address of originator */
    uchar IPv4_dst[IP_SIZE]; /* IP address of destination */

    uchar options[0];        /* up to 40 bytes */
    uchar data[0];           /* message data up to 64KB */
};

struct tcpudp_port_header 
{
    uint srcPort: 16;
    uint dstPort: 16;    
};

typedef struct _udpHdr
{
    uint srcPort: 16;
    uint dstPort: 16;
    uint udpPktLen: 16;
    uint chksum: 16;
}udpHdr;

typedef union _optsUnion
{
    struct
    {
#ifdef __LITTLE_ENDIAN__
        uint fin:1;
        uint syn:1;
        uint rst:1;
        uint psh:1;
        uint ack:1;
        uint urg:1;
        uint res:2;
#elif defined __BIG_ENDIAN__
        uint res:2;
        uint urg:1;
        uint ack:1;
        uint psh:1;
        uint rst:1;
        uint syn:1;
        uint fin:1;
#else
#error "Set Big/Little Endianness"
#endif
    }flags;
    uchar options;
}opts;

typedef struct _tcpHdr
{
    uint srcPort:16;
    uint dstPort:16;
    uint seqNum;
    uint ackNum;
#ifdef __LITTLE_ENDIAN__
    uint  reserved   : 4; // 4 bits
    uint  dataOffset : 4; // 4 bits
#elif defined __BIG_ENDIAN__
    uint  dataOffset : 4; // 4 bits
    uint  reserved   : 4; // 4 bits    
#else
#error "Set Big/Little endianness"
#endif
    opts options;
    uint window: 16;
    uint cksum: 16;
    uint urgp: 16;
} tcpHdr;


struct eth_packet {
    uchar dst_mac[ETH_ALEN];
    uchar src_mac[ETH_ALEN];
    uint  eth_type:16;
};

struct eth_8021q_packet {
    uchar dst_mac[ETH_ALEN];
    uchar src_mac[ETH_ALEN];
    uint  eth_type:16;
    uint  priority: 3;
    uint  cfi: 1;
    uint  vlan_id: 12;
    uint  ether_type;
};
#pragma pack()

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
    } addr_fmt[] = {{ETH_ALEN, "%x", ':'}, {IP_SIZE, "%d", '.'}};

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

char *GetEtherType(int eth_type)
{
    switch(eth_type)
    {
    case ETH_P_IP:    return "IPv4";
    case ETH_P_8021Q: return "802.1Q";
    case ETH_P_ARP:   return "ARP";
    case ETH_P_LOOP:  return "EthLoop";
    case ETH_P_X25:   return "X.25";
    case ETH_P_RARP:  return "RARP";
    case ETH_P_IPV6:  return "IPv6";
    case ETH_P_TIPC:  return "TIPC";
    default: return "???";
    }
}

int eth_contains_ip(struct eth_packet *eth_pkt)
{
    if(ntohs(eth_pkt->eth_type) == ETH_P_8021Q)
        return 18;
    else if (ntohs(eth_pkt->eth_type) == ETH_P_IP)
        return 14;

    return 0;
}

int ipcmp(uchar *ipstruct_addr, int addr)
{
    int ipstr_addr = *((int*)ipstruct_addr);
    if(debug)
        printf("IPAddrFilter: in[%X],flt[%X]\n", addr, ipstr_addr);
    
    return (addr)?(addr == ipstr_addr) : 1;
}

int ethmask_cmp(uchar *retr_addr, uchar *filter_addr)
{
    int i =0 ;
    if(debug)
        printf("EtherAddrFilter: in[%06X],flt[%06X]\n", retr_addr,
               filter_addr);

    for(;i<ETH_ALEN;++i)
    {
        if(filter_addr[i] != retr_addr[i])
            return 0;
    }
    return 1;
}

int ethtype_cmp(uint retr_type, uint filter_type)
{
    return (retr_type == filter_type);
}

int ethvlan_cmp(struct eth_packet *eth_pkt, uint vlan_tag)
{
    struct eth_8021q_packet *q_pkt = (void *)(eth_pkt);
    uint retr_id;
    if(!ethtype_cmp(ntohs(eth_pkt->eth_type), ETH_P_8021Q))
        return 0;
    
    retr_id = q_pkt->vlan_id;

    return (ntohs(retr_id) == vlan_tag);
}

int udptcp_sport_cmp(struct ip_packet *ip, uint filter_port)
{
    uchar *buffer = (void *)ip;
    struct tcpudp_port_header *hdr = (void *)(buffer + (ip->header_len*4));
    if((ip->protocol != IPPROTO_TCP) &&
       (ip->protocol != IPPROTO_UDP))
        return 0;

    return (ntohs(hdr->srcPort) == filter_port);
}

int udptcp_dport_cmp(struct ip_packet *ip, uint filter_port)
{
    uchar *buffer = (void *)ip;
    struct tcpudp_port_header *hdr = (void *)(buffer + (ip->header_len*4));
    if((ip->protocol != IPPROTO_TCP) &&
       (ip->protocol != IPPROTO_UDP))
        return 0;

    return (ntohs(hdr->dstPort) == filter_port);
}

#pragma pack(1)
struct arp_packet {
    uint  hw_type    : 16;
    uint  proto_type : 16;
    uchar alen;
    uchar proto_alen;
    uint  opcode     : 16;
};
#pragma pack()

void PrintExtraEtherInfo(struct eth_packet *eth_pkt)
{
    struct eth_8021q_packet *q_pkt = (void *)(eth_pkt);
    if(ethtype_cmp(ntohs(eth_pkt->eth_type), ETH_P_8021Q))
    {
        printf(",vlan_prio=%d,cfi=%c,vlan_id=%d\nVlanEtherType=%s",
               q_pkt->priority, q_pkt->cfi ? 'T' : 'F', 
               ntohs(q_pkt->vlan_id),GetEtherType(ntohs(q_pkt->ether_type)));
        return;
    }

    if(ethtype_cmp(ntohs(eth_pkt->eth_type), ETH_P_ARP))
    {
        printf("no arp decode yet\n");
    }

}

#define FILTER_CHK_MASK(a,b) (((uint)a&(uint)b) == (uint)b)
#define FILTER_SET_MASK(a,b) (!FILTER_CHK_MASK(a,b)?a |= b : a)

void DumpPacket(char *buffer, int len)
{
    struct eth_packet *eth_pkt=(void *)(buffer);
    struct ip_packet *ip = NULL;

    /* filter out the cruft - in userspace I know! */
    if(FILTER_CHK_MASK(filter_mask, ETH_SRC_FILTER))
    {
        if(!ethmask_cmp(eth_pkt->src_mac, eth_src_is_mac_filter))
            return;
    }

    if(FILTER_CHK_MASK(filter_mask, ETH_DST_FILTER))
    {
        if(!ethmask_cmp(eth_pkt->dst_mac, eth_dst_is_mac_filter))
            return;
    }

    if(FILTER_CHK_MASK(filter_mask, ETH_TYPE_FILTER))
    {
        if(!ethtype_cmp(ntohs(eth_pkt->eth_type), eth_type_is_filter))
            return;
    }

    if(FILTER_CHK_MASK(filter_mask, ETH_VLAN_FILTER))
    {
        if(!ethvlan_cmp(eth_pkt, eth_vlan_is_filter))
            return;
    }

    if(eth_contains_ip(eth_pkt))
    {
        ip = (void *)(buffer + eth_contains_ip(eth_pkt));

        if(FILTER_CHK_MASK(filter_mask, IP_SRC_FILTER))
        {
            if(!ipcmp(ip->IPv4_src, ip_src_is_filter))
                return;
        }
        
        if(FILTER_CHK_MASK(filter_mask, IP_DST_FILTER))
        {
            if(!ipcmp(ip->IPv4_dst, ip_dst_is_filter))
                return;
        }
        
        if(FILTER_CHK_MASK(filter_mask, IP_PROTO_FILTER))
        {
            if(ip->protocol != ipproto_is_filter)
                return;
        }
        
        if(FILTER_CHK_MASK(filter_mask, UDP_TCP_SPORT_FILTER))
        {
            if(!udptcp_sport_cmp(ip, udp_tcp_sport_is_filter))
                return;
        }
        
        if(FILTER_CHK_MASK(filter_mask, UDP_TCP_DPORT_FILTER))
        {
            if(!udptcp_sport_cmp(ip, udp_tcp_dport_is_filter))
                return;
        }
    }

    do{
        printf("-------------------------------------------------\n");
        dump(buffer, len, NULL);
    
        PrintAddr("Destination EtherID=", eth_pkt->dst_mac, eETH_ADDR);
        PrintAddr(", Source EtherID=", eth_pkt->src_mac, eETH_ADDR);    
        printf("\nEthertype=%s", GetEtherType(ntohs(eth_pkt->eth_type)));
        PrintExtraEtherInfo(eth_pkt);

        if(eth_contains_ip(eth_pkt))
        {
            printf("\nIPv%d: header-len=%d, type=%d, packet-size=%d, ID=%d\n",
                   ip->version, ip->header_len*4, ip->serve_type,
                   ntohs(ip->packet_len), ntohs(ip->ID));
            printf("no-frag=%c, more=%c, offset=%d, TTL=%d, protocol=%s\n",
                   (ip->dont_frag? 'N': 'Y'),
                   (ip->more_frags? 'N': 'Y'),
                   ip->frag_offset,
                   ip->time_to_live, GetProtocol(ip->protocol));
            printf("checksum=%d, ", ntohs(ip->hdr_chksum));
            PrintAddr("source=", ip->IPv4_src, eIP_ADDR);
            PrintAddr(", destination=", ip->IPv4_dst, eIP_ADDR);
        }
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

extern unsigned int ascii_to_bin(char *);

int main(int argc, char *argv[])
{
    int sd=-1, bytes_read;
    char rdata[2048];
    char *data;
    char infomercial[15]={0};
    char *lastarg = NULL;
    struct sockaddr_in sa;
    uint sl;

#ifdef __WIN32__
    int ON = 1;
    WSADATA wsaData;

    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    if(argc > 1)
    {
        while(--argc)
        {
            if(strncmp("--", argv[argc], 2))
                lastarg = argv[argc];
            else
            {
                if((lastarg == NULL) &&
                   strchr(argv[argc],'='))
                {
                    lastarg = strchr(argv[argc],'=');
                    ++lastarg;
                }
                
                if(!strncmp("--vlan-id", argv[argc], 9) && lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, ETH_VLAN_FILTER);
                    eth_vlan_is_filter = strtol(lastarg,NULL,0);
                } else if(!strncmp("--eth-src", argv[argc], 9) &&
                          lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, ETH_SRC_FILTER);
                    memcpy(infomercial, lastarg, 12);
                    ascii_to_bin(infomercial);
                    memcpy(eth_src_is_mac_filter, infomercial, 6);
                } else if(!strncmp("--eth-dst", argv[argc], 9) &&
                          lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, ETH_DST_FILTER);
                    memcpy(infomercial, lastarg, 12);
                    ascii_to_bin(infomercial);
                    memcpy(eth_dst_is_mac_filter, infomercial, 6);
                } else if(!strncmp("--eth-type", argv[argc], 10) &&
                          lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, ETH_TYPE_FILTER);
                    eth_type_is_filter = strtol(lastarg, NULL, 0);
                } else if(!strncmp("--ip-src", argv[argc], 7) &&
                          lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, IP_SRC_FILTER);
                    ip_src_is_filter = atoip(lastarg);
                } else if(!strncmp("--ip-dst", argv[argc], 7) &&
                          lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, IP_DST_FILTER);
                    ip_dst_is_filter = atoip(lastarg);
                } else if(!strncmp("--ip-proto", argv[argc], 10) &&
                          lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, IP_PROTO_FILTER);
                    ipproto_is_filter = strtol(lastarg, NULL, 0);
                } else if(!strncmp("--ip-sport", argv[argc], 10) &&
                          lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, UDP_TCP_SPORT_FILTER);
                    udp_tcp_sport_is_filter = strtol(lastarg, NULL, 0);
                } else if(!strncmp("--ip-dport", argv[argc], 10) &&
                          lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, UDP_TCP_DPORT_FILTER);
                    udp_tcp_dport_is_filter = strtol(lastarg, NULL, 0);
                } else
                {
                    printf("UNKNOWN OPTION, %s,%s\n", argv[argc], lastarg);
                }
                lastarg = NULL;
            }
        }
    }
    
    /*doesn't work with OS X*/
    sd = socket(SOCK_FAM_TYPE, SOCK_RAW, SOCK_PROTO_TYPE);
    if ( sd < 0 )
        PANIC("Snooper socket");

#ifdef __WIN32__
    printf("Seems you're using windows.\n");
    printf("A few things to let you know:\n");
    printf("1 - All packets will be IP, and unless you're an admin, you might\n"
           "    not see anything at all. Even if you are, you might not see them\n");
    printf("2 - Due to a wacky way in which WINSOCK works, you need to enter\n"
           "    the IP address of your local interface on which you'd like to\n"
           " sniff.\n");
    printf("> ");
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
        data = rdata;
#ifdef __WIN32__
        data[0] = 0x11;
        data[1] = 0x11;
        data[2] = 0x11;
        data[3] = 0x11;
        data[4] = 0x11;
        data[5] = 0x11;

        data[6]  = 0x22;
        data[7]  = 0x22;
        data[8]  = 0x22;
        data[9]  = 0x22;
        data[10] = 0x22;
        data[11] = 0x22;

        data[12] = 0x08;
        data[13] = 0x00;

        data += 14;
#endif
        sl = sizeof(struct sockaddr_in);
        bytes_read = recvfrom(sd, data, sizeof(data), 0, (struct sockaddr *)&sa, (socklen_t *)&sl);
        
        if ( bytes_read > 0 )
        {
            DumpPacket(data, bytes_read);

        }
        else if(bytes_read == -1)
            PANIC("Snooper read");

    } while ( bytes_read > 0 );

    return 0;
}
