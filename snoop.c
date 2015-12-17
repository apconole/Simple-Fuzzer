/**
 * Simple Fuzz
 * Copyright (c) 2009-2011, Aaron Conole <apconole@yahoo.com>
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

#define DEBUG_MODE 0

#include <stdio.h>
#include <fcntl.h>

#ifdef __WIN32__
# include "windows.h"
# include "winsock2.h"



struct timezone {
    int tz_minuteswest;     /* minutes west of Greenwich */
    int tz_dsttime;         /* type of DST correction */
};

extern int gettimeofday(struct timeval *, struct timezone *);
extern time_t time(time_t *);

typedef unsigned int uint32_t;

/* if we don't have mstcpip "special" codes */
# ifndef SIO_RCVALL
#  define SIO_RCVALL  _WSAIOW(IOC_VENDOR,1)
# endif /* SIO_RCVALL */

# define ERROR_PRINT _PANIC_

# define __LITTLE_ENDIAN__
/* the following defines are taken from if_ether.h
 * credit must be given to:
 * Author:      Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *              Donald Becker, <becker@super.org>
 *              Alan Cox, <alan@redhat.com>
 *              Steve Whitehouse, <gw7rrm@eeshack3.swan.ac.uk>
 */
# define ETH_P_IP        0x0800          /* Internet Protocol packet     */
# define ETH_P_X25       0x0805          /* CCITT X.25                   */
# define ETH_P_ARP       0x0806          /* Address Resolution packet    */
# define ETH_P_BPQ       0x08FF          /* G8BPQ AX.25 Ethernet Packet  [ NOT AN OFFICIALLY REGISTERED ID ] */
# define ETH_P_IEEEPUP   0x0a00          /* Xerox IEEE802.3 PUP packet */
# define ETH_P_IEEEPUPAT 0x0a01          /* Xerox IEEE802.3 PUP Addr Trans packet */
# define ETH_P_DEC       0x6000          /* DEC Assigned proto           */
# define ETH_P_DNA_DL    0x6001          /* DEC DNA Dump/Load            */
# define ETH_P_DNA_RC    0x6002          /* DEC DNA Remote Console       */
# define ETH_P_DNA_RT    0x6003          /* DEC DNA Routing              */
# define ETH_P_LAT       0x6004          /* DEC LAT                      */
# define ETH_P_DIAG      0x6005          /* DEC Diagnostics              */
# define ETH_P_CUST      0x6006          /* DEC Customer use             */
# define ETH_P_SCA       0x6007          /* DEC Systems Comms Arch       */
# define ETH_P_RARP      0x8035          /* Reverse Addr Res packet      */
# define ETH_P_ATALK     0x809B          /* Appletalk DDP                */
# define ETH_P_AARP      0x80F3          /* Appletalk AARP               */
# define ETH_P_8021Q     0x8100          /* 802.1Q VLAN Extended Header  */
# define ETH_P_IPX       0x8137          /* IPX over DIX                 */
# define ETH_P_IPV6      0x86DD          /* IPv6 over bluebook           */
# define ETH_P_PAUSE     0x8808          /* IEEE Pause frames. See 802.3 31B */
# define ETH_P_SLOW      0x8809          /* Slow Protocol. See 802.3ad 43B */
# define ETH_P_WCCP      0x883E          /* Web-cache coordination protocol
                                         * defined in draft-wilson-wrec-wccp-v2-00.txt */
# define ETH_P_PPP_DISC  0x8863          /* PPPoE discovery messages     */
# define ETH_P_PPP_SES   0x8864          /* PPPoE session messages       */
# define ETH_P_MPLS_UC   0x8847          /* MPLS Unicast traffic         */
# define ETH_P_MPLS_MC   0x8848          /* MPLS Multicast traffic       */
# define ETH_P_ATMMPOA   0x884c          /* MultiProtocol Over ATM       */
# define ETH_P_ATMFATE   0x8884          /* Frame-based ATM Transport
                                          * over Ethernet
                                         */
# define ETH_P_AOE       0x88A2          /* ATA over Ethernet            */
# define ETH_P_TIPC      0x88CA          /* TIPC                         */

# define INCREMENT_CAP   0
# define SOCK_FAM_TYPE   AF_INET
# define SOCK_PROTO_TYPE IPPROTO_RAW

typedef unsigned int uint;
typedef unsigned short ushort;

struct timespec {
    long tv_sec;
    long tv_nsec;
};

#else /* ! __WIN32__ */

# include <stdint.h>
# include <sys/param.h>
# include <sys/socket.h>
# include <resolv.h>
# include <arpa/inet.h>
# include <net/ethernet.h>
# include <errno.h>
# include <sys/types.h>
# include <string.h>
# include <netinet/in_systm.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <netinet/ip.h>
# include <unistd.h>
# include <sys/select.h>
# include <sys/time.h>

# define ERROR_PRINT perror

# ifdef __BYTE_ORDER
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define __LITTLE_ENDIAN__ 1
#  else
#   if __BYTE_ORDER == __BIG_ENDIAN
#    define __BIG_ENDIAN__ 1
#   else
#    error "Unknown byte order"
#   endif
#  endif /* __BYTE_ORDER */
# endif

# ifdef __linux__
//#  include <netpacket/packet.h>
#  include <features.h>
#  include <linux/if.h>
#  include <linux/if_ether.h>
#  include <linux/if_packet.h>
#  include <sys/ioctl.h>
#  include <sched.h>
#  define SOCK_FAM_TYPE   PF_PACKET
#  define SOCK_PROTO_TYPE htons(ETH_P_ALL)
# endif /*__LINUX__*/

# include <signal.h>
# include <time.h>
# include <unistd.h>

#endif /* !__WIN32__ */


#include "os-abs.h"

#define IP_SIZE  4

#ifndef ETH_ALEN
# define ETH_ALEN 6
#endif /*ETH_ALEN*/

#define ETH_SRC_FILTER       0x00000001
#define ETH_DST_FILTER       0x00000002
#define ETH_TYPE_FILTER      0x00000004
#define ETH_VLAN_FILTER      0x00000008
#define IP_SRC_FILTER        0x00000010
#define IP_DST_FILTER        0x00000020
#define IP_PROTO_FILTER      0x00000040
#define UDP_TCP_SPORT_FILTER 0x00000080
#define UDP_TCP_DPORT_FILTER 0x00000100
#define ARBITRARY_U8_FILTER  0x00000200
#define ARBITRARY_U16_FILTER 0x00000400
#define ARBITRARY_U32_FILTER 0x00000800
#define ARBITRARY_MSK_FILTER 0x00001000
#define IP_TOS_BYTE_FILTER   0x00002000
#define STRING_FILTER        0x00004000

typedef unsigned char uchar;

uint  filter_mask = 0;

uchar eth_src_is_mac_filter[ETH_ALEN];
uchar eth_src_not = 0;

uchar eth_dst_is_mac_filter[ETH_ALEN];
uchar eth_dst_not = 0;

uint  eth_type_is_filter;
uchar eth_type_not = 0;

uint  eth_vlan_is_filter;
uchar eth_vlan_not = 0;

uint  need_IP = 0;
uint  ip_src_is_filter;
uchar ip_src_not = 0;

uint  ip_dst_is_filter;
uchar ip_dst_not = 0;

uchar ip_addr_or = 0;

uint  ipproto_is_filter;
uchar ipproto_not = 0;

uint  udp_tcp_sport_is_filter;
uchar udp_tcp_sport_not = 0;

uint  udp_tcp_dport_is_filter;
uchar udp_tcp_dport_not = 0;

uint  arbitrary_u8_filter_pos = 0;
uchar arbitrary_u8_filter;
uchar arbitrary_u8_not = 0;

uint   arbitrary_u16_filter_pos = 0;
ushort arbitrary_u16_filter;
uchar  arbitrary_u16_not = 0;

uint  arbitrary_u32_filter_pos = 0;
uint  arbitrary_u32_filter;
uchar arbitrary_u32_not = 0;

uint  arbitrary_msk_filter_pos = 0;
uint  arbitrary_msk_filter;
uchar arbitrary_msk_not = 0;

uchar ip_tos_byte_filter;
uchar ip_tos_byte_filter_not = 0;

uchar string_filter[1024] = {0};
uchar string_filter_not   = 0;

typedef enum { eETH_ADDR, eIP_ADDR } EAddress;

uint peak_rate = 0;
uint avg_rate = 0;
uint avg_samples = 0;
uint min_rate = 0xffffffff;
uint current_second_bytes = 0;

struct histogram_row
{
    uint  pkt_size;
    uint  pkt_count;
    uint32_t time_slice;
};

#define MAX_NUM_ROWS 1522

struct histogram_row histogram[MAX_NUM_ROWS+1];
struct histogram_row burst_hist[65535];

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
#else /*!__LITTLE_ENDIAN__ */
    uint version:4;
    uint header_len:4;
#endif/*!__LITTLE_ENDIAN__ */
    uint serve_type:8;       /* how to service packet */
    uint packet_len:16;      /* total size of packet in bytes */
    uint ID:16;              /* fragment ID */

#ifdef __LITTLE_ENDIAN__
    uint frag_offset:13;     /* to help reassembly */
    uint more_frags:1;       /* flag for "more frags to follow" */
    uint dont_frag:1;        /* flag to permit fragmentation */
    uint __reserved:1;       /* always zero */
#else/*!__LITTLE_ENDIAN__ */
    uint __reserved:1;
    uint more_frags:1;
    uint dont_frag:1;
    uint frag_offset:13;
#endif/*!__LITTLE_ENDIAN__ */

    uint time_to_live:8;     /* maximum router hop count */
    uint protocol:8;         /* ICMP, UDP, TCP */
    uint hdr_chksum:16;      /* ones-comp. checksum of header */

    union
    {
        uint  addr:32;
        uchar IPv4_src[IP_SIZE]; /* IP address of originator */
    } ip_src;

    union
    {
        uint  addr:32;
        uchar IPv4_dst[IP_SIZE]; /* IP address of destination */
    } ip_dst;

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
    uint cksum: 16;
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
# error "Set Big/Little Endianness"
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
# error "Set Big/Little endianness"
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
    uint  ether_type:16;
};

struct tcp_pseudo /*the tcp pseudo header*/
{
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned char zero;
    unsigned char proto;
    unsigned short length;
} pseudohead;

#pragma pack()

inline unsigned int endian_swap_32(unsigned int x)
{
    x = (x>>24)               |
        ((x<<8) & 0x00ff0000) |
        ((x>>8) & 0x0000ff00) |
        (x<<24)               ;
    return x;
}

inline unsigned short endian_swap_16(unsigned short x)
{
    x = (x>>8)|
        (x<<8);
    return x;
}

void DebugPrint(char *buf){
#if DEBUG_MODE
    printf("DEBUG - %s\n", buf);
#endif /* DEBUG */
}

#include "sfuzz-plugin.h"

long checksum(unsigned short *addr, unsigned int count) {
    /* Compute Internet Checksum for "count" bytes
     *         beginning at location "addr".
     */
    register long sum = 0;


    while( count > 1 ) {
        /*  This is the inner loop */
        sum += * addr++;
        count -= 2;
    }
    /*  Add left-over byte, if any */
    if( count > 0 )
        sum += * (unsigned char *) addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

long get_udp_checksum(struct ip_packet * myip, udpHdr * myudp)
{
    long res;
    unsigned short total_len = ntohs(myip->packet_len);

    int udpdatalen = total_len - sizeof(udpHdr) - (myip->header_len*4);
    
    pseudohead.src_addr=myip->ip_src.addr;
    pseudohead.dst_addr=myip->ip_dst.addr;
    pseudohead.zero=0;
    pseudohead.proto=IPPROTO_TCP;
    pseudohead.length=htons(sizeof(udpHdr) + udpdatalen );

    int totaludp_len = sizeof(struct tcp_pseudo) + sizeof(udpHdr) + udpdatalen;
    unsigned short * udp = (unsigned short*)malloc(totaludp_len);

    memcpy((unsigned char *)udp,&pseudohead,sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)udp+sizeof(struct tcp_pseudo),(unsigned char *)myudp,sizeof(udpHdr));
    memcpy((unsigned char *)udp+sizeof(struct tcp_pseudo)+sizeof(udpHdr), (unsigned char *)myip+(myip->header_len*4)+(sizeof(udpHdr)), udpdatalen);

    res = checksum(udp,totaludp_len);
    free(udp);
    return res;
}

long get_tcp_checksum(struct ip_packet * myip, tcpHdr * mytcp)
{
    long res = 0;
    unsigned short total_len = ntohs(myip->packet_len);

    int tcpopt_len = mytcp->dataOffset*4 - 20;
    int tcpdatalen = total_len - (mytcp->dataOffset*4) - (myip->header_len*4);

    pseudohead.src_addr=myip->ip_src.addr;
    pseudohead.dst_addr=myip->ip_dst.addr;
    pseudohead.zero=0;
    pseudohead.proto=IPPROTO_TCP;
    pseudohead.length=htons(sizeof(tcpHdr) + tcpopt_len + tcpdatalen);

    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(tcpHdr) + tcpopt_len + tcpdatalen;
    unsigned short * tcp = (unsigned short*)malloc(totaltcp_len);

    memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)mytcp,sizeof(tcpHdr));
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo)+sizeof(tcpHdr), (unsigned char *)myip+(myip->header_len*4)+(sizeof(tcpHdr)), tcpopt_len);
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo)+sizeof(tcpHdr)+tcpopt_len, (unsigned char *)mytcp+(mytcp->dataOffset*4), tcpdatalen);

    res = checksum(tcp,totaltcp_len);
    free(tcp);
    return res;
}

plugin_provisor *g_plugin;

void WriteAddr(char *buf, unsigned int buflen,
               char *msg, unsigned char *addr, EAddress is_ip){
    int i,l = 0;
    static struct {
        int len;
        char *fmt;
        char delim;
    } addr_fmt[] = {{ETH_ALEN, "%x", ':'}, {IP_SIZE, "%d", '.'}};

    if(msg != NULL)
        l += snprintf(buf, buflen, "%s", msg);
    for ( i = 0; i < addr_fmt[is_ip].len; i++ ){
        if(l < buflen) l += snprintf(buf+l, buflen - l,
                                     addr_fmt[is_ip].fmt, addr[i]);
        if ( i < addr_fmt[is_ip].len-1 )
            if(l < buflen){ buf[l++] = addr_fmt[is_ip].delim; }
    }
}

void PrintAddr(char* msg, unsigned char *addr, EAddress is_ip)
{
    char buf[8192] = {0};
    WriteAddr(buf, 8192, msg, addr, is_ip);
    printf("%s",buf);
}

char *GetProtocol(uint value){
    static char protohex[5] = {0};
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
    default: 
        snprintf(protohex, 5, "0x%02x", value);
        return protohex;
    }
}

char *GetEtherType(int eth_type)
{
    static char protohex[7] = {0};
    switch(eth_type)
    {
    case ETH_P_IP:    return "IPv4";
    case ETH_P_8021Q: return "802.1Q";
    case ETH_P_ARP:   return "ARP";
#ifndef __WIN32__
    case ETH_P_LOOP:  return "EthLoop";
#endif
    case ETH_P_X25:   return "X.25";
    case ETH_P_RARP:  return "RARP";
    case ETH_P_IPV6:  return "IPv6";
    case ETH_P_TIPC:  return "TIPC";
    default:
        snprintf(protohex, 5, "0x%04x", eth_type);
        return protohex;
    }
}

int eth_contains_ip(struct eth_packet *eth_pkt)
{
    if(ntohs(eth_pkt->eth_type) == ETH_P_8021Q)
    {
        int lctr = 1;
        struct eth_8021q_packet *eth_vlan_pkt = 
            (struct eth_8021q_packet *)eth_pkt;
        while(ntohs(eth_vlan_pkt->ether_type) == ETH_P_8021Q)
        {
            ++lctr;
            char *cur_ptr = (char *)eth_vlan_pkt;
            cur_ptr += 4;
            eth_vlan_pkt = (struct eth_8021q_packet *)cur_ptr;
        }
        if(ntohs(eth_vlan_pkt->ether_type) != ETH_P_IP)
            return 0;
        
        return 14 + (lctr * 4);
    }
    else if (ntohs(eth_pkt->eth_type) == ETH_P_IP)
        return 14;
    
    return 0;
}

int ipcmp(uchar *ipstruct_addr, int addr)
{
    int ipstr_addr = *((int*)ipstruct_addr);
#if DEBUG_MODE
        printf("IPAddrFilter: in[%X],flt[%X]\n", addr, ipstr_addr);
#endif

    return (addr) ? ((addr == ipstr_addr) ? 1 : 0) : 1;
}

int ethmask_cmp(uchar *retr_addr, uchar *filter_addr)
{
    int i =0 ;
#if DEBUG_MODE
        printf("EtherAddrFilter: in[%06X],flt[%06X]\n", 
               (unsigned int)retr_addr,
               (unsigned int)filter_addr);
#endif

    for(;i<ETH_ALEN;++i)
    {
        if(filter_addr[i] != retr_addr[i])
            return 0;
    }
    return 1;
}

int ethtype_cmp(uint retr_type, uint filter_type)
{
    return (retr_type == filter_type) ? 1 : 0;
}

int ethvlan_cmp(struct eth_packet *eth_pkt, uint vlan_tag)
{
    struct eth_8021q_packet *q_pkt = (void *)(eth_pkt);
    uint retr_id;
    if(!ethtype_cmp(ntohs(eth_pkt->eth_type), ETH_P_8021Q))
        return 0;

    retr_id = q_pkt->vlan_id;

    return (ntohs(retr_id) == vlan_tag) ? 1 : 0;
}

int udptcp_sport_cmp(struct ip_packet *ip, uint filter_port)
{
    uchar *buffer = (void *)ip;
    struct tcpudp_port_header *hdr = (void *)(buffer + (ip->header_len*4));
    if((ip->protocol != IPPROTO_TCP) &&
       (ip->protocol != IPPROTO_UDP))
        return 0;

    return (ntohs(hdr->srcPort) == filter_port) ? 1 : 0;
}

int udptcp_dport_cmp(struct ip_packet *ip, uint filter_port)
{
    uchar *buffer = (void *)ip;
    struct tcpudp_port_header *hdr = (void *)(buffer + (ip->header_len*4));
    if((ip->protocol != IPPROTO_TCP) &&
       (ip->protocol != IPPROTO_UDP))
        return 0;

    return (ntohs(hdr->dstPort) == filter_port) ? 1 : 0;
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

#define ARP_NETROM 0
#define ARP_ETHER  1
#define ARP_EETHER 2
#define ARP_AX25   3
#define ARP_PRONET 4
#define ARP_CHAOS  5
#define ARP_BLANK  6
#define ARP_ARCNET 7
#define ARP_APPLET 8

#define ARP_REQUEST 1
#define ARP_REPLY   2

char *arp_hwtype_tostr(unsigned short hwtype)
{
    switch (hwtype)
    {
    case ARP_NETROM:
        return "NetRom";
    case ARP_ETHER:
        return "Ethernet";
    case ARP_EETHER:
        return "ExpEther";
    case ARP_AX25:
        return "AX.25";
    case ARP_PRONET:
        return "ProNet";
    case ARP_CHAOS:
        return "CHAOS";
    case ARP_BLANK:
        return "\"blank\"";
    case ARP_ARCNET:
        return "ARCNET";
    case ARP_APPLET:
        return "APPLETalk";
    default:
        return "unknown";
    }
}

char *arp_target_proto(struct arp_packet *arp)
{
    unsigned char *tgt_proto_start;
    static char buf[80] = {0};
    if((ntohs(arp->hw_type) != ARP_ETHER) || (ntohs(arp->proto_type) != ETH_P_IP))
    {
        return "???";
    }

    tgt_proto_start = ((unsigned char *) arp);
    tgt_proto_start += sizeof(struct arp_packet);
    tgt_proto_start += 16;
    
    WriteAddr(buf, 80, NULL, tgt_proto_start, eIP_ADDR);
    return buf;
}

char *arp_target_hw(struct arp_packet *arp)
{
    unsigned char *tgt_hw_start;
    static char buf[80] = {0};
    if((ntohs(arp->hw_type) != ARP_ETHER) || (ntohs(arp->proto_type) != ETH_P_IP))
    {
        return "???";
    }

    tgt_hw_start = ((unsigned char *) arp);
    tgt_hw_start += sizeof(struct arp_packet);
    tgt_hw_start += 10;
    
    WriteAddr(buf, 80, NULL, tgt_hw_start, eETH_ADDR);
    return buf;
}

char *arp_sender_proto(struct arp_packet *arp)
{
    unsigned char *snd_proto_start;
    static char buf[80] = {0};
    if((ntohs(arp->hw_type) != ARP_ETHER) || (ntohs(arp->proto_type) != ETH_P_IP))
    {
        return "???";
    }

    snd_proto_start = ((unsigned char *) arp) ;
    snd_proto_start += sizeof(struct arp_packet);
    snd_proto_start += 6;
    
    WriteAddr(buf, 80, NULL, snd_proto_start, eIP_ADDR);
    return buf;
}

char *arp_sender_hw(struct arp_packet *arp)
{
    unsigned char *snd_hw_start;
    static char buf[80] = {0};
    if((ntohs(arp->hw_type) != ARP_ETHER) || (ntohs(arp->proto_type) != ETH_P_IP))
    {
        return "???";
    }

    snd_hw_start = ((unsigned char *) arp);
    snd_hw_start += sizeof(struct arp_packet);
    
    WriteAddr(buf, 80, NULL, snd_hw_start, eETH_ADDR);
    return buf;
}


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
        char *tmp = (char *)eth_pkt;
        tmp += sizeof(struct eth_packet);
        struct arp_packet *arp = (struct arp_packet *) tmp;
        printf("\nARP HW Type: %x[%s]\n", ntohs(arp->hw_type), 
               arp_hwtype_tostr(ntohs(arp->hw_type)));
        if(ntohs(arp->opcode) == ARP_REQUEST)
        {
            printf("Who has ");
            printf("(%s)", GetEtherType(ntohs(arp->proto_type)));
            printf(" : %s; tell %s @ %s",
                   arp_target_proto(arp),
                   arp_sender_proto(arp), arp_sender_hw(arp));
        }
        else if(ntohs(arp->opcode) == ARP_REPLY)
        {
            printf("(%s)", GetEtherType(ntohs(arp->proto_type)));
            printf(" : tell %s @ %s that %s is reached \n\tvia %s",
                   arp_target_proto(arp), arp_target_hw(arp), 
                   arp_sender_proto(arp), arp_sender_hw(arp));
        }
        else
            printf(", ARP OPCODE unknown :%d", ntohs(arp->opcode));
        
        printf("\n");
    }

}

#define FILTER_CHK_MASK(a,b) (((uint)a&(uint)b) == (uint)b)
#define FILTER_SET_MASK(a,b) (!FILTER_CHK_MASK(a,b)?a |= b : a)

void *__internal_memmem(const void *hs, size_t hsl, const void *nd, size_t ndl);

char DumpPacket(char *buffer, int len, int quiet)
{
    struct eth_packet *eth_pkt=(void *)(buffer);
    struct ip_packet *ip = NULL;

    if(FILTER_CHK_MASK(filter_mask, STRING_FILTER))
    {
        void *truth;
        size_t ndl = strlen((const char *)string_filter);
        size_t mmlen = (size_t) len;
        truth = __internal_memmem(buffer, mmlen, string_filter, ndl);

        if(truth != NULL)
        {
            if(string_filter_not)
                return -1;
        }else if(truth == NULL)
            return -1;
        
    }

    if(FILTER_CHK_MASK(filter_mask, ARBITRARY_MSK_FILTER))
    {
        uint ff = ntohl(*((uint*)(buffer+arbitrary_msk_filter_pos)));
        if(len < arbitrary_msk_filter_pos+4)
            return -1;
        uchar truth = (FILTER_CHK_MASK(ff, arbitrary_msk_filter));
        
        if(truth)
        {
            if(arbitrary_msk_not)
                return -1;
        }else if (!truth)
            return -1;
    }
    
    if(FILTER_CHK_MASK(filter_mask, ARBITRARY_U8_FILTER))
    {
        if(len < arbitrary_u8_filter_pos+1)
            return -1;
        if((buffer[arbitrary_u8_filter_pos] == arbitrary_u8_filter))
        {
            if(arbitrary_u8_not)
                return -1;
        }else if (!arbitrary_u8_not)
            return -1;
    }

    if(FILTER_CHK_MASK(filter_mask, ARBITRARY_U16_FILTER))
    {
        if(len < arbitrary_u16_filter_pos+2)
            return -1;
        if((ntohs(*((ushort*)(buffer+arbitrary_u16_filter_pos))) ==
            arbitrary_u16_filter))
        {
            if(arbitrary_u16_not)
                return -1;
        }else if(!arbitrary_u16_not)
            return -1;
    }

    if(FILTER_CHK_MASK(filter_mask, ARBITRARY_U32_FILTER))
    {
        if(len < arbitrary_u32_filter_pos+4)
            return -1;
        if((ntohl(*((uint*)(buffer+arbitrary_u32_filter_pos))) == 
            arbitrary_u32_filter))
        {
            if(arbitrary_u32_not)
                return -1;
        }
        else if (!arbitrary_u32_not)
            return -1;
    }

    /* filter out the cruft - in userspace I know! */
    if(FILTER_CHK_MASK(filter_mask, ETH_SRC_FILTER))
    {
        if(ethmask_cmp(eth_pkt->src_mac, eth_src_is_mac_filter))
        {
            if(eth_src_not)
                return -1;
        }else if(!eth_src_not)
            return -1;
    }

    if(FILTER_CHK_MASK(filter_mask, ETH_DST_FILTER))
    {
        if(ethmask_cmp(eth_pkt->dst_mac, eth_dst_is_mac_filter))
        {
            if(eth_dst_not)
                return -1;
        }else if (!eth_dst_not)
            return -1;
    }
    
    if(FILTER_CHK_MASK(filter_mask, ETH_TYPE_FILTER))
    {
        if(ethtype_cmp(ntohs(eth_pkt->eth_type), eth_type_is_filter))
        {
            if(eth_type_not)
                return -1;
        }else if(!eth_type_not)
            return -1;
        

    }

    if(FILTER_CHK_MASK(filter_mask, ETH_VLAN_FILTER))
    {
        if(ethvlan_cmp(eth_pkt, eth_vlan_is_filter))
        {
            if(eth_vlan_not)
                return -1;
        }else if(!eth_vlan_not)
            return -1;
    }

    if(eth_contains_ip(eth_pkt))
    {
        char skip_dest_addr = 0;

        ip = (void *)(buffer + eth_contains_ip(eth_pkt));
        
        if(FILTER_CHK_MASK(filter_mask, IP_SRC_FILTER))
        {
            if(ipcmp(ip->ip_src.IPv4_src, ip_src_is_filter))
            {
                if(ip_src_not)
                    return -1;
                // matched the source, skip dest addr
                if(ip_addr_or) skip_dest_addr = 1;
            }else if(!ip_src_not && !ip_addr_or)
                return -1;
        }
        
        if(!skip_dest_addr && FILTER_CHK_MASK(filter_mask, IP_DST_FILTER))
        {
            if(ipcmp(ip->ip_dst.IPv4_dst, ip_dst_is_filter))
            {
                if(ip_dst_not)
                    return -1;
            }else if(!ip_dst_not)
                return -1;
        }
        
        if(FILTER_CHK_MASK(filter_mask, IP_TOS_BYTE_FILTER))
        {
            if(ip->serve_type == ip_tos_byte_filter)
            {
                if(ip_tos_byte_filter_not)
                    return -1;
            }else if (!ip_tos_byte_filter_not)
                return -1;
        }

        if(FILTER_CHK_MASK(filter_mask, IP_PROTO_FILTER))
        {
            if(ip->protocol == ipproto_is_filter)
            {
                if(ipproto_not)
                    return -1;
            }else if (!ipproto_not)
                return -1;
        }

        if(FILTER_CHK_MASK(filter_mask, UDP_TCP_SPORT_FILTER))
        {
            if(udptcp_sport_cmp(ip, udp_tcp_sport_is_filter))
            {
                if(udp_tcp_sport_not)
                    return -1;
            }else if(!udp_tcp_sport_not)
                return -1;
        }
        
        if(FILTER_CHK_MASK(filter_mask, UDP_TCP_DPORT_FILTER))
        {
            if(udptcp_dport_cmp(ip, udp_tcp_dport_is_filter))
            {
                if(udp_tcp_dport_not)
                    return -1;
            }else if(!udp_tcp_dport_not)
                return -1;
        }
    }

    if(!eth_contains_ip(eth_pkt) && need_IP == 1)
        return -1;

    if(quiet)
    {
        printf("-------------------------------------------------\n");
        dump(buffer, len, NULL);

        PrintAddr("Destination EtherID=", eth_pkt->dst_mac, eETH_ADDR);
        PrintAddr(", Source EtherID=", eth_pkt->src_mac, eETH_ADDR);
        printf("\nEthertype=%s", GetEtherType(ntohs(eth_pkt->eth_type)));
        PrintExtraEtherInfo(eth_pkt);

        if(eth_contains_ip(eth_pkt))
        {
            tcpHdr *tcph = NULL;
            udpHdr *udph = NULL;
            if(ip->protocol == 0x06)
            {
                buffer = buffer + eth_contains_ip(eth_pkt);
                buffer = buffer + (ip->header_len * 4);
                tcph = (tcpHdr *)buffer;
            }
            
            if(ip->protocol == 0x11)
            {
                buffer = buffer + eth_contains_ip(eth_pkt);
                buffer = buffer + (ip->header_len * 4);
                udph = (udpHdr *)buffer;
            }

            printf("\nIPv%d: header-len=%d, type=%d, packet-size=%d, ID=%d\n",
                   ip->version, ip->header_len*4, ip->serve_type,
                   ntohs(ip->packet_len), ntohs(ip->ID));
            printf("no-frag=%c, more=%c, offset=%d, TTL=%d, protocol=%s\n",
                   (ip->dont_frag? 'N': 'Y'),
                   (ip->more_frags? 'N': 'Y'),
                   ip->frag_offset,
                   ip->time_to_live, GetProtocol(ip->protocol));
            printf("checksum=%x", ntohs(ip->hdr_chksum));

            ip->hdr_chksum = 0;
            ip->hdr_chksum = (unsigned short)checksum((unsigned short *)ip,ip->header_len*4);

            printf(" C:[%x], ", ntohs(ip->hdr_chksum));
            PrintAddr("source=", ip->ip_src.IPv4_src, eIP_ADDR);
            PrintAddr(", destination=", ip->ip_dst.IPv4_dst, eIP_ADDR);
            printf("\n");
            if(tcph)
            {
                printf("TCP Flags: ");
                if(tcph->options.flags.urg)
                    printf("URG ");
                if(tcph->options.flags.ack)
                    printf("ACK ");
                if(tcph->options.flags.psh)
                    printf("PSH ");
                if(tcph->options.flags.rst)
                    printf("RST ");
                if(tcph->options.flags.syn)
                    printf("SYN ");
                if(tcph->options.flags.fin)
                    printf("FIN ");
                printf("\n");

                printf("[TCP] transport layer cksum=%x", tcph->cksum);
                tcph->cksum = 0;
                printf(",calc'd=%x",  (unsigned short) get_tcp_checksum(ip, tcph));
                printf(",sport=%d,dport=%d", ntohs(tcph->srcPort), 
                       ntohs(tcph->dstPort));
            } 
            else if (udph)
            {
                unsigned short cksum;
                printf("[UDP] transport layer cksum=%x", udph->cksum);
                cksum = udph->cksum;
                udph->cksum = 0;
                printf(",calc'd=%x",  cksum ? (unsigned short) get_udp_checksum(ip, udph) : 0);
                printf(",sport=%d,dport=%d", ntohs(udph->srcPort), 
                       ntohs(udph->dstPort));
            }
        }
        printf("\n");
        fflush(stdout);
    }

    return 1;
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
        printf("not a socket.\n");
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

typedef struct pcap_hdr_s {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

int run = 1;

#ifdef __WIN32__
BOOL WINAPI terminate_hnd(DWORD dwCtrlType)
#else 
void terminate_hnd(int sig)
#endif
{
    run = 0;
#ifdef __WIN32__
    return 1;
#endif
}

#ifdef __WIN32__
int nanosleep(const struct timespec *requested_delay,
              struct timespec *remainder)
{
    struct timeval delay;
    delay.tv_sec = requested_delay->tv_sec;
    delay.tv_usec = requested_delay->tv_nsec / 1000;
    if(select(0, NULL, NULL, NULL, &delay) < 0)
    {
        /* handle remainder here */
    }
    return 0;
}
#endif

int snoop_nano_sleep(const struct timespec *req, struct timespec *remain)
{
    struct timespec _remainder;
    if(nanosleep(req, remain) == -1)
    {
        snoop_nano_sleep(remain, &_remainder);
    }

    return 0;
}

int timeval_compare(struct timeval *pFirst, struct timeval *pSecond)
{
    if( ( pFirst->tv_sec > pSecond->tv_sec ) ||
        ( ( pFirst->tv_sec == pSecond->tv_sec ) &&
          ( pFirst->tv_usec > pSecond->tv_usec ) ) )
        return 1;

    if( ( pFirst->tv_sec == pSecond->tv_sec ) &&
        ( pFirst->tv_usec == pSecond->tv_usec ) )
        return 0;

    return -1;
}

long int timeval_seconds_delta( struct timeval *pFirst, struct timeval *pSecond )
{
    return pFirst->tv_sec - pSecond->tv_sec;
}

long int timeval_useconds_delta( struct timeval *pFirst, struct timeval *pSecond )
{
    return pFirst->tv_usec - pSecond->tv_usec;
}

void emit_delta(struct timeval *pPacketCurrent, struct timeval *pPacketLast,
                uint32_t bursty)
{
    uint64_t burstr = 0;
    struct timeval tRemainder = {0,0};
    tRemainder.tv_sec = pPacketCurrent->tv_sec - pPacketLast->tv_sec;
    tRemainder.tv_usec = pPacketCurrent->tv_usec - pPacketLast->tv_usec;
    if(tRemainder.tv_sec < 0) tRemainder.tv_sec = 0;
    if(tRemainder.tv_usec < 0) tRemainder.tv_usec = 0;
    if(bursty != 0)
    {
        burstr = tRemainder.tv_sec * 1000000;
        burstr += tRemainder.tv_usec;
        
        if(burstr > bursty){ return; }
        
        burst_hist[burstr % 65535].pkt_count ++;
        
    }
    //printf("%u:%u\n", tRemainder.tv_sec, tRemainder.tv_usec);
}

void pcap_pkt_sleep(struct timeval *pPacketCurrent,
                    struct timeval *pPacketLast)
{
    struct timespec delta = {0}, remainder = {0};

    if(pPacketLast->tv_sec == 0)
        return;

    if( (pPacketCurrent->tv_sec < pPacketLast->tv_sec) || 
        ((pPacketCurrent->tv_sec == pPacketLast->tv_sec) &&
         (pPacketCurrent->tv_usec < pPacketLast->tv_usec))
        )
        return;

    delta.tv_sec = pPacketCurrent->tv_sec - pPacketLast->tv_sec;
    delta.tv_nsec = 1000 * (pPacketCurrent->tv_usec - pPacketLast->tv_usec);
    
    snoop_nano_sleep(&delta, &remainder);
}

int main(int argc, char *argv[])
{
    FILE *pcap_dump_file = NULL;
    pcap_hdr_t pcap_header;
    int sd=-1, bytes_read;
    int display = 1;
    char res = 0;
    char *rdata;
    char *data;
    char infomercial[15]={0};
    char pcap_input = 0, bursty = 0;
    char pcap_byteswap  = 0;
    uint print_hist     = 0;
    unsigned long int pkts_rx = 0;
    unsigned long int pkts_pass = 0;
    char *lastarg = NULL;
#ifndef __WIN32__
    int od = -1, out_phy = 0;
    char rt = 0;
    char *iface = NULL;
    char *oface = NULL;
    int promisc = 0;
#endif
    char *pcap_fname = NULL;
    struct timeval lasttime = {0};
    struct timeval curtime = {0};
    struct timeval heuristictime = {0,0};
    uchar notflag = 0, pcap_sleep = 0;
    struct sockaddr_in sa;

#ifdef __WIN32__
    int sl;
    struct hostent *h;
    u_long ON = 1;
    WSADATA wsaData;

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    if(SetConsoleCtrlHandler( (PHANDLER_ROUTINE)terminate_hnd,TRUE ) == FALSE)
    {
        printf("Unable to install handler\n");
        return -1;
    }
#else
    socklen_t sl;

    signal(SIGABRT, &terminate_hnd);
    signal(SIGTERM, &terminate_hnd);
    signal(SIGINT, &terminate_hnd);
#endif

    rdata = (char *)malloc(65535);
    if(!rdata)
    {
        fprintf(stderr, "snoop: OOM\n");
        return -1;
    }

    if(argc > 1)
    {
        while(--argc)
        {
            if(strncmp("--", argv[argc], 2))
            {
                if(strcmp("!", argv[argc]))
                    lastarg = argv[argc];
                else
                    notflag = 1;
            }
            else
            {
                if((lastarg == NULL) &&
                   strchr(argv[argc],'='))
                {
                    lastarg = strchr(argv[argc],'=');
                    ++lastarg;
                }

                if((lastarg) && lastarg[0] == '!')
                {
                    ++lastarg;
                    notflag = 1;
                }

                if(!strncmp("--help", argv[argc], 6))
                {
                    printf("snoop v0.7.0\n");
                    printf("Copyright (C) 2003-2011, Aaron Conole\n");
                    printf("=====================================\n");
                    printf("Valid arguments:\n");
                    printf("To save a .pcap file: --output\n");
                    printf("To suppress output: --quiet\n");
                    printf("To specify a negative filter use --not, or ! after the filter type.\n");
                    printf("  ex: --ip-src --not 192.168.1.1\n");
                    printf("--string,\n");
                    printf("--vlan-id, --eth-src, --eth-dst, --eth-type,\n");
                    printf("--ip-src, --ip-dst, --ip-proto, --ip-tos, --ip-sport, --ip-dport,\n");
                    printf
                        ("--u8, --u16, --u32 => format is <value>:<offset>\n");
                    printf("--m32 => format is <mask>:<offset>\n");
                    printf("--input => specify a pcap file as the input\n");
#ifdef __linux__
                    printf("--interface, --outerface, --promisc\n");
                    printf("To specify realtime mode: --rt\n");
#endif
                    return 0;
                }
                if(!strncmp("--quiet", argv[argc], 7))
                {
                    display=0;
                }
#ifdef __linux__
                else if(!strncmp("--interface", argv[argc], 11) &&
                        lastarg != NULL)
                {
                    iface = lastarg;
                }
                else if(!strncmp("--outerface", argv[argc], 11) &&
                        lastarg != NULL)
                {
                    oface = lastarg;
                }
                else if(!strncmp("--promisc", argv[argc], 11))
                {
                    promisc = 1;
                }
                else if(!strncmp("--rt", argv[argc], 4))
                {
                    rt = 1;
                }
#endif
                else if(!strncmp("--input", argv[argc], 7) && lastarg != NULL)
                {
                    pcap_input = 1;
                    pcap_fname = lastarg;
                    notflag = 0;
                }
                else if(!strncmp("--histogram", argv[argc], 11))
                {
                    int cnt;
                    print_hist = 1;

                    if(lastarg != NULL)
                        print_hist = atoi(lastarg);

                    if(!print_hist) print_hist = 1;

                    cnt = MAX_NUM_ROWS / print_hist;
                    
                    for(--cnt; cnt>=0; cnt--)
                    {
                        histogram[cnt].pkt_size = 64 + (print_hist * cnt);
                        histogram[cnt].pkt_count = 0;
                    }

                    histogram[MAX_NUM_ROWS].pkt_size  = 65535;
                    histogram[MAX_NUM_ROWS].pkt_count = 0;
                }
                else if(!strncmp("--not", argv[argc], 5) && lastarg != NULL)
                {
                    notflag = 1;
                    continue;
                }
                else if(!strncmp("--output", argv[argc], 8) && lastarg != NULL)
                {
                    printf("snoop v0.6.3 pcap starting...\n");
                    pcap_dump_file = fopen(lastarg, "w+");
                    if(pcap_dump_file == NULL)
                    {
                        printf("unable to save pcap file. aborting.\n");
                        perror("fopen");
                        return -1;
                    }
                    pcap_header.magic_number  = 0xa1b2c3d4;
                    pcap_header.version_major = 2;
                    pcap_header.version_minor = 4;
                    pcap_header.thiszone      = 0;
                    pcap_header.sigfigs       = 0;
                    pcap_header.snaplen       = 65535;
                    pcap_header.network       = 1;
                    fwrite((void *)&pcap_header, sizeof(pcap_header), 1,
                           pcap_dump_file);
                    fflush(pcap_dump_file);
                    notflag = 0;
                }
                else if(!strncmp("--string", argv[argc], 8) &&
                        lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, STRING_FILTER);
                    strncpy((char *)string_filter, lastarg, 1024);
                    string_filter[1023] = 0;
                    if(notflag) string_filter_not = 1;
                    notflag = 0;
                }
                else if(!strncmp("--vlan-id", argv[argc], 9) &&
                        lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, ETH_VLAN_FILTER);
                    eth_vlan_is_filter = strtol(lastarg,NULL,0);
                    if(notflag) eth_vlan_not = 1;
                    notflag = 0;
                } else if(!strncmp("--eth-src", argv[argc], 9) &&
                          lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, ETH_SRC_FILTER);
                    memcpy(infomercial, lastarg, 12);
                    ascii_to_bin(infomercial);
                    memcpy(eth_src_is_mac_filter, infomercial, 6);
                    if(notflag) eth_src_not = 1;
                    notflag = 0;
                } else if(!strncmp("--eth-dst", argv[argc], 9) &&
                          lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, ETH_DST_FILTER);
                    memcpy(infomercial, lastarg, 12);
                    ascii_to_bin(infomercial);
                    memcpy(eth_dst_is_mac_filter, infomercial, 6);
                    if(notflag) eth_dst_not = 1;
                    notflag = 0;
                } else if(!strncmp("--eth-type", argv[argc], 10) &&
                          lastarg != NULL)
                {
                    FILTER_SET_MASK(filter_mask, ETH_TYPE_FILTER);
                    eth_type_is_filter = strtol(lastarg, NULL, 0);
                    if(notflag) eth_type_not = 1;
                    notflag = 0;
                } else if(!strncmp("--ip-src", argv[argc], 7) &&
                          lastarg != NULL)
                {
                    need_IP = 1;
                    FILTER_SET_MASK(filter_mask, IP_SRC_FILTER);
                    ip_src_is_filter = atoip(lastarg);
                    if(notflag) ip_src_not = 1;
                    notflag = 0;
                } else if(!strncmp("--ip-dst", argv[argc], 7) &&
                          lastarg != NULL)
                {
                    need_IP = 1;
                    FILTER_SET_MASK(filter_mask, IP_DST_FILTER);
                    ip_dst_is_filter = atoip(lastarg);
                    if(notflag) ip_dst_not = 1;
                    notflag = 0;
                } else if(!strncmp("--ip-tos", argv[argc], 8) &&
                          lastarg != NULL)
                {
                    need_IP = 1;
                    FILTER_SET_MASK(filter_mask, IP_TOS_BYTE_FILTER);
                    ip_tos_byte_filter = strtol(lastarg, NULL, 0);
                    if(notflag) ip_tos_byte_filter_not = 1;
                    notflag = 0;
                } else if(!strncmp("--ip-proto", argv[argc], 10) &&
                          lastarg != NULL)
                {
                    need_IP = 1;
                    FILTER_SET_MASK(filter_mask, IP_PROTO_FILTER);
                    ipproto_is_filter = strtol(lastarg, NULL, 0);
                    if(notflag) ipproto_not = 1;
                    notflag = 0;
                } else if(!strncmp("--or-addr", argv[argc], 9))
                {
                    ip_addr_or = 1;
                } else if(!strncmp("--bursty", argv[argc], 8))
                {
                    int k = 0;
                    bursty = 1;
                    if(lastarg != NULL) bursty = atoi(lastarg);
                    if(!bursty) bursty = 1;

                    for(;k < 65535; ++k)
                    {
                        burst_hist[k].pkt_count = 0;
                    }

                } else if(!strncmp("--ip-sport", argv[argc], 10) &&
                          lastarg != NULL)
                {
                    need_IP = 1;
                    FILTER_SET_MASK(filter_mask, UDP_TCP_SPORT_FILTER);
                    udp_tcp_sport_is_filter = strtol(lastarg, NULL, 0);
                    if(notflag) udp_tcp_sport_not = 1;
                    notflag = 0;
                } else if(!strncmp("--ip-dport", argv[argc], 10) &&
                          lastarg != NULL)
                {
                    need_IP = 1;
                    FILTER_SET_MASK(filter_mask, UDP_TCP_DPORT_FILTER);
                    udp_tcp_dport_is_filter = strtol(lastarg, NULL, 0);
                    if(notflag) udp_tcp_dport_not = 1;
                    notflag = 0;
                } else if(!strncmp("--pcap-sleep", argv[argc], 12))
                {
                    pcap_sleep = 1;
                } else if(!strncmp("--u8", argv[argc], 10) &&
                          lastarg != NULL)
                {
                    char *fpos = NULL;
                    FILTER_SET_MASK(filter_mask, ARBITRARY_U8_FILTER);
                    arbitrary_u8_filter = (uchar)strtoul(lastarg, &fpos, 0);
                    if(fpos)
                        arbitrary_u8_filter_pos = strtoul(fpos+1, NULL, 0);
                    if(notflag) arbitrary_u8_not = 1;
                    notflag = 0;
                } else if(!strncmp("--u16", argv[argc], 10) &&
                          lastarg != NULL)
                {
                    char *fpos = NULL;
                    FILTER_SET_MASK(filter_mask, ARBITRARY_U16_FILTER);
                    arbitrary_u16_filter = (ushort)strtoul(lastarg, &fpos, 0);
                    if(fpos)
                        arbitrary_u16_filter_pos = strtoul(fpos+1, NULL, 0);
                    if(notflag) arbitrary_u16_not = 1;
                    notflag = 0;
                } else if(!strncmp("--u32", argv[argc], 10) &&
                          lastarg != NULL)
                {
                    char *fpos = NULL;
                    FILTER_SET_MASK(filter_mask, ARBITRARY_U32_FILTER);
                    arbitrary_u32_filter = (uint)strtoul(lastarg, &fpos, 0);
                    if(fpos)
                        arbitrary_u32_filter_pos = strtoul(fpos+1, NULL, 0);
                    if(notflag) arbitrary_u32_not = 1;
                    notflag = 0;
                } 
                else if(!strncmp("--m32", argv[argc], 10) &&
                        lastarg != NULL)
                {
                    char *fpos = NULL;
                    FILTER_SET_MASK(filter_mask, ARBITRARY_MSK_FILTER);
                    arbitrary_msk_filter = (uint)strtoul(lastarg, &fpos, 0);
                    if(fpos)
                        arbitrary_msk_filter_pos = strtoul(fpos+1, NULL, 0);
                    if(notflag) arbitrary_msk_not = 1;
                    notflag = 0;
                }
                else
                {
                    printf("UNKNOWN OPTION, %s,%s\n", argv[argc], lastarg);
                    return -1;
                }
                lastarg = NULL;
            }
        }
    }

    if(!pcap_input)
    {
        /*doesn't work with OS X*/
        sd = socket(SOCK_FAM_TYPE, SOCK_RAW, SOCK_PROTO_TYPE);
        if ( sd < 0 )
            PANIC("Snooper socket");


#ifdef __WIN32__
    printf("Seems you're using windows.\n");
    printf("A few things to let you know (especially if you're using >XPSP1):\n");
    printf("1 - All packets will be IP, and unless you're an admin, you might\n"
           "    not see anything at all. Even if you are, you might not see them\n");
    printf("2 - Due to a wacky way in which WINSOCK works, you need to enter\n"
           "    the IP address of your local interface on which you'd like to\n"
           "    sniff.\n");
    printf("3 - Even IF you're an admin, have a valid interface, and packets are flowing\n"
           "    you may not see those packets anyway - XP (sp0/sp1) is the best windows\n"
           "    OS to be using.\n");
    
    printf("\n");
    data = rdata;
    if(gethostname(data, 1024) == SOCKET_ERROR)
    {
        PANIC("gethostname");
    }

    h = gethostbyname(data);
    if(!h)
    {
        PANIC("gethostbyname");
    }

    for(argc = 0; h->h_addr_list[argc] != 0; ++argc)
    {
        printf("Interface IP [%s]\n", inet_ntoa(*(struct in_addr *)h->h_addr_list[argc]));
    }
    
    printf("IP> ");
    fflush(stdout);
    data = rdata;
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
    }
    else
    {
        int read_len;
        pcap_hdr_t in_pcap_header;
        sd = open(pcap_fname, O_RDONLY
#ifndef __WIN32__
                  | O_NOCTTY
#endif
            );

        if(sd < 1)
            PANIC("open");

#ifdef __WIN32__
        _setmode(sd, _O_BINARY);
#endif
        read_len = read(sd, &in_pcap_header, sizeof(in_pcap_header));
        if((read_len < 0) || (read_len != sizeof(in_pcap_header)))
        {
            PANIC("read");
        }

        if(in_pcap_header.magic_number == 0xa1b2c3d4)
        {
            /* we don't need to byteswap the packet info. */
        }
        else if (in_pcap_header.magic_number == 0xd4c3b2a1)
        {
            pcap_byteswap = 1 ;
            in_pcap_header.version_major = 
                endian_swap_16(in_pcap_header.version_major);
            in_pcap_header.version_minor = 
                endian_swap_16(in_pcap_header.version_minor);
            in_pcap_header.thiszone      = 
                endian_swap_32(in_pcap_header.thiszone);
            in_pcap_header.sigfigs       = 
                endian_swap_32(in_pcap_header.sigfigs);
            in_pcap_header.snaplen       = 
                endian_swap_32(in_pcap_header.snaplen);
            in_pcap_header.network       =
                endian_swap_32(in_pcap_header.network);
        }
        else
        {
            fprintf(stderr, 
                    "ERROR: Pcap file corrupt / bad magic number [%X]\n",
                    in_pcap_header.magic_number);
            return -1;
        }
        
        if(in_pcap_header.snaplen < 96)
        {
            fprintf(stderr,
                    "Error: Pcap file doesn't have large enough packets.\n");
            return -1;
        }

        if(in_pcap_header.network != 1)
        {
            fprintf(stderr, "Error: Snoop only works on ethernet caps.\n");
            return -1;
        }

        printf("pcap info:\n");
        printf("network: Ethernet\n");
        printf("tz:      %d\n", in_pcap_header.thiszone);
        printf("snaplen: %u\n", in_pcap_header.snaplen);
        printf("version: %d.%d\n", in_pcap_header.version_major, 
               in_pcap_header.version_minor);
    }
#ifndef __WIN32__
# ifdef __linux__
    if(rt)
    {
        int ss;
        struct sched_param sp;
        pid_t pid = getpid();
        sp.sched_priority = 77; /* - magic number - a high priority */
        ss = sched_setscheduler(pid, SCHED_FIFO, &sp);
        if(ss < 0)
            perror("sched_setscheduler");
    }

    if(oface)
    {
        struct sockaddr_ll s1;
        struct ifreq interface_obj;
        int result;
        od = socket(SOCK_FAM_TYPE, SOCK_RAW, SOCK_PROTO_TYPE);
        if(od < 0)
            PANIC("Snooper socket-out");

        memset(&s1, 0, sizeof(struct sockaddr_ll));
        strcpy((char *)interface_obj.ifr_name, oface);
        
        result = ioctl(sd, SIOCGIFINDEX, &interface_obj);
        if(result >= 0)
        {
            result = interface_obj.ifr_ifindex;
            s1.sll_family = SOCK_FAM_TYPE;
            s1.sll_ifindex = result;
            s1.sll_protocol = SOCK_PROTO_TYPE;
            out_phy = result;
            result = bind(od, (struct sockaddr *)&s1, sizeof(s1));
            if(result < 0)
            {
                PANIC("Snooper outerface");
            }
        }
    }

    if(iface)
    {
        struct sockaddr_ll s1;
        struct ifreq interface_obj;
        int result;
        memset(&s1, 0, sizeof(struct sockaddr_ll));
        strncpy((char *)interface_obj.ifr_name, iface, IFNAMSIZ);
        interface_obj.ifr_name[IFNAMSIZ-1] = 0;
        
        result = ioctl(sd, SIOCGIFINDEX, &interface_obj);
        if(result >= 0)
        {
            result = interface_obj.ifr_ifindex;
            s1.sll_family = SOCK_FAM_TYPE;
            s1.sll_ifindex = result;
            s1.sll_protocol = SOCK_PROTO_TYPE;
            result = bind(sd, (struct sockaddr *)&s1, sizeof(s1));
            if(result < 0)
            {
                printf("unable to bind to device.\n");
            }
            else
            {
                if(promisc && ((interface_obj.ifr_flags & IFF_PROMISC) != IFF_PROMISC))
                {
                    interface_obj.ifr_flags |= IFF_PROMISC;
                    result = ioctl(sd, SIOCSIFFLAGS, &interface_obj);
                    if(result < 0)
                        printf("unable to set promisc.\n");
                }
            }
        }
    }
# endif /* __linux__ */
#endif /* !__WIN32__ */

    do {
        struct timeval tv;
        fd_set readfd;

        tv.tv_sec = 0;
        tv.tv_usec = 5000; /* 5ms */

        FD_ZERO(&readfd);

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
        struct timeval rcvtime;

        if(!pcap_input)
        {
            sl = sizeof(struct sockaddr_in);
            FD_SET(sd, &readfd);
            bytes_read = select(sd+1, &readfd, NULL, NULL, &tv);
            
            if(bytes_read > 0)
            {
                bytes_read = recvfrom(sd, data, 65535, 0, (struct sockaddr *)&sa, &sl);
                rcvtime.tv_sec = time(NULL); // we do this because on some 
                // platforms, notably embedded, 
                // gettimeofday can "forget" to 
                // populate tv_sec.
                rcvtime.tv_usec = 0;
                
                gettimeofday(&rcvtime, NULL);

            }
            else
            {
                bytes_read = 1;
                continue;
            }
        }
        else
        {
            pcaprec_hdr_t pcap_rec;
            int read_len = read(sd, &pcap_rec, sizeof(pcap_rec));
            if((read_len < 0) || (read_len != sizeof(pcap_rec)))
            {
                perror("read");
                bytes_read = 0; run = 0;
                continue;
            }
            if(pcap_byteswap)
            {
                pcap_rec.ts_sec = endian_swap_32(pcap_rec.ts_sec);
                pcap_rec.ts_usec = endian_swap_32(pcap_rec.ts_usec);
                pcap_rec.incl_len = endian_swap_32(pcap_rec.incl_len);
                pcap_rec.orig_len = endian_swap_32(pcap_rec.orig_len);
            }
            
            if( print_hist )
            {
                rcvtime.tv_sec = pcap_rec.ts_sec;
                rcvtime.tv_usec = pcap_rec.ts_usec;
            }

            if(pcap_sleep || bursty)
            {
                memcpy(&lasttime, &curtime, sizeof(lasttime));
                curtime.tv_sec = pcap_rec.ts_sec;
                curtime.tv_usec = pcap_rec.ts_usec;
                
                if(pcap_sleep)pcap_pkt_sleep(&curtime, &lasttime);
                if(bursty)    emit_delta(&curtime, &lasttime, bursty);
            }
            bytes_read = read(sd, data, pcap_rec.incl_len);

        }

        if ( bytes_read > 0 )
        {

            if( heuristictime.tv_sec ||
                heuristictime.tv_usec )
            {
                long int seconds_delta = 
                    timeval_seconds_delta( &rcvtime, &heuristictime );
                if( seconds_delta >= 1 )
                {
                    // time to calculate;
                    long int bytespersec = ( current_second_bytes / seconds_delta );
                    if( bytespersec > peak_rate )
                        peak_rate = bytespersec;
                    if( bytespersec < min_rate )
                        min_rate = bytespersec;

                    avg_rate += bytespersec;
                    avg_samples++;

                    current_second_bytes = 0;
                    heuristictime.tv_sec = rcvtime.tv_sec;
                    heuristictime.tv_usec = rcvtime.tv_usec;
                }
            }
            else
            {
                heuristictime.tv_sec = rcvtime.tv_sec;
                heuristictime.tv_usec = rcvtime.tv_usec;
            }

            current_second_bytes += bytes_read;

            res = DumpPacket(data, bytes_read, display);
            if(res == 1)
            {
                ++pkts_pass;

                if(print_hist)
                {
                    

                    for(sl = 0; sl < MAX_NUM_ROWS; ++sl)
                    {
                        if(bytes_read <= histogram[sl].pkt_size)
                        {
                            histogram[sl].pkt_count++;
                            break;
                        }
                    }
                    // done
                }

            }
            if(pcap_dump_file && res == 1)
            {
                pcaprec_hdr_t pcap_hdr;


                pcap_hdr.ts_sec = rcvtime.tv_sec;
                pcap_hdr.ts_usec = rcvtime.tv_usec;
                pcap_hdr.incl_len = bytes_read;
                pcap_hdr.orig_len = bytes_read;
                fwrite((void *)&pcap_hdr, sizeof(pcap_hdr), 1, pcap_dump_file);
                fwrite((void *)data, 1, bytes_read, pcap_dump_file);
                fflush(pcap_dump_file);

            }
#ifdef __linux__
            if(oface && od && res == 1)
            {
                struct sockaddr_ll peerAddr;
                memset(&peerAddr, 0, sizeof(struct sockaddr_ll));

                peerAddr.sll_family   = PF_PACKET;
                peerAddr.sll_protocol = htons(ETH_P_ALL);
                peerAddr.sll_halen    = 6;
                peerAddr.sll_ifindex  = out_phy;
                peerAddr.sll_pkttype  = PACKET_OTHERHOST;
                memcpy(peerAddr.sll_addr, data, 6);
                sendto(od, data, bytes_read, 0, (struct sockaddr *)&peerAddr,
                       sizeof(peerAddr));
            }
#endif
        }
        else if(bytes_read == -1)
        {
            PANIC("Snooper read");
        }

        if(bytes_read) ++pkts_rx;
        
    } while (run && bytes_read > 0 );

    printf("terminating...\n");

    if(pcap_dump_file)
        fclose(pcap_dump_file);

    printf("Packets captured: %lu\n", pkts_rx);
    if(pkts_pass != pkts_rx)
        printf("Packets matching: %lu\n", pkts_pass);

    if(print_hist)
    {
        if( current_second_bytes )
        {
            printf(
        "Remaining data (discarded from calcs): %u bytes\n", current_second_bytes);
        }

        printf("Data Rates: min=%d Bps, peak=%d Bps, avg=%f Bps\n", min_rate, peak_rate, (avg_samples) ? (float)avg_rate / (float)avg_samples : 0);
        
        for(sl = 0; sl <= MAX_NUM_ROWS; ++sl)
        {
            if(histogram[sl].pkt_count)
                printf("H[%6d] = { %9u }\n",
                       histogram[sl].pkt_size, histogram[sl].pkt_count);
        }
    }

    if(bursty)
    {
        for(sl = 0; sl < 65535; ++sl)
        {
            if(burst_hist[sl].pkt_count)
                printf("B[%6d] = { %9u }\n",
                       sl, burst_hist[sl].pkt_count);
        }
    }
    
    return 0;
}
