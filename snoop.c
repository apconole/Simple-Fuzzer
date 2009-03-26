/* snoop.c - for use with sfuzz
 * use as a simple network monitor.
 */

#include <stdio.h>

#ifdef __WIN32__
#include "windows.h"
#define INCREMENT_CAP   0
#define SOCK_FAM_TYPE   AF_INET
#define SOCK_PROTO_TYPE IPPROTO_IP

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

int debug = 0;
int addr=0;

#ifdef __LINUX__
#include <netinet/if_ether.h>
#define INCREMENT_CAP   14
#define SOCK_FAM_TYPE   PF_PACKET
#define SOCK_PROTO_TYPE htons(ETH_P_IP)
#endif
#endif

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
    case IPPROTO_IPIP: return "IPIP";
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_EGP: return "EGP";
    case IPPROTO_PUP: return "PUP";
    case IPPROTO_UDP: return "UDP";
    case IPPROTO_IDP: return "IDP";
    case IPPROTO_RSVP: return "RSVP";
    case IPPROTO_GRE: return "GRE";
    case IPPROTO_IPV6: return "IPV6/4";
    case IPPROTO_PIM: return "PIM";
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
        dump(buffer, len);
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
#define PANIC(msg){perror(msg);exit(0);}

int main(int argc, char *argv[])
{
    int sd=-1, bytes_read;
    char data[1024];
    
    struct sockaddr_in sa;
    uint sl;

#ifdef __WIN32__
    int ON = 1;
    WSAData wsaData;

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
    if(WSAIoctl(sd, SIO_RCVALL, &ON, sizeof(ON), NULL, NULL, 
                &bytes_read, NULL, NULL) == SOCKET_ERROR)
        PANIC("Snooper error");
#endif

    do {
        sl = sizeof(struct sockaddr_in);
        bytes_read = recvfrom(sd, data, sizeof(data), 0, &sa, &sl);
        
        if ( bytes_read > 0 )
        {
            DumpPacket(data+INCREMENT_CAP, bytes_read);
        }
        
    } while ( bytes_read > 0 );

    return 0;
}
