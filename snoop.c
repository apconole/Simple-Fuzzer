/* snoop.c - for use with sfuzz
 * use as a simple network monitor.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>


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
/* -endian format.                                                    */
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

void dump(void* b, int len){
  unsigned char *buf = b;
  int i, cnt=0;
  char str[17];
  memset(str, 0, 17);
  for ( i = 0; i < len; i++ ){
    if ( cnt % 16 == 0 ){
      printf("  %s\n%04X: ", str, cnt);
      memset(str, 0, 17);
    }
    if ( buf[cnt] < ' '  ||  buf[cnt] >= 127 )
      str[cnt%16] = '.';
    else
      str[cnt%16] = buf[cnt];
    printf("%02X ", buf[cnt++]);
  }
  printf("  %*s\n\n", 16+(16-len%16)*2, str);
}

void PrintAddr(char* msg, unsigned char *addr, EAddress is_ip){
  int i;
  static struct {
    int len;
    char *fmt;
    char delim;
  } addr_fmt[] = {{ETH_SIZE, "%x", ':'}, {IP_SIZE, "%d", '.'}};
  
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

void DumpPacket(char *buffer, int len){
  struct ip_packet *ip=(void*)buffer;
  do{
    printf("-------------------------------------------------\n");
    dump(buffer, len);
    //    PrintAddr("Destination EtherID=", ip->hw_header.dst_eth, eETH_ADDR);
    //    PrintAddr(", Source EtherID=", ip->hw_header.src_eth, eETH_ADDR);
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

int main(int argc, char *argv[]){
  int sd, bytes_read;
  char data[1024];
  int addr=0;

  struct sockaddr_in sa;
  uint sl;

  if(argc > 1)
  {
    printf("Filtering on addr[%s]\n", argv[1]);
    addr = atoip(argv[1]);
  }

  /*doesn't work with OS X*/
  sd  = socket(AF_INET, SOCK_RAW, 0);//htons(ETH_P_ALL));
  if ( sd < 0 )
    PANIC("Snooper socket");
  do {
    sl = sizeof(struct sockaddr_in);
    bytes_read = recvfrom(sd, data, sizeof(data), 0, &sa, &sl);
    
    if ( bytes_read > 0 )
    {
      if((addr) && sa.sin_addr.s_addr != addr)
	{
	  printf("[%X]:[%X]\n", addr, sa.sin_addr.s_addr);
	continue;
	}
      DumpPacket(data, bytes_read);
    }

  } while ( bytes_read > 0 );
  return 0;
}
