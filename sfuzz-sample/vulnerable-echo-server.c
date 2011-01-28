/***
 * Vulnerable echo server - from Vivek Ramachandran's securitytube.net video
 * not verbatim, but close (using dump() for hex).
 */
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<error.h>
#include<strings.h>
#include<unistd.h>
#include<arpa/inet.h>


#define ERROR       -1
#define MAX_CLIENTS 2
#define MAX_DATA    1024

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
  fflush(stdout);
}

main(int argc, char **argv)
{
    struct sockaddr_in server;
    struct sockaddr_in client;
    int sock;
    int new;
    int sockaddr_len = sizeof(struct sockaddr_in);
    int data_len;
    char data[MAX_DATA];
    
    
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) == ERROR)
    {
        perror("server socket: ");
        exit(-1);
    }
    
    server.sin_family = AF_INET;
    server.sin_port = htons(atoi(argv[1]));
    server.sin_addr.s_addr = INADDR_ANY;
    bzero(&server.sin_zero, 8);
    
    if((bind(sock, (struct sockaddr *)&server, sockaddr_len)) == ERROR)
    {
        perror("bind : ");
        exit(-1);
    }
    
    if((listen(sock, MAX_CLIENTS)) == ERROR)
    {
        perror("listen");
        exit(-1);
    }
    
    while(1) // Better signal handling required
    {
        if((new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)) == ERROR)
        {
            perror("accept");
            exit(-1);
        }
        
        printf("New Client connected from port no %d and IP %s\n", ntohs(client.sin_port), inet_ntoa(client.sin_addr));

        data_len = 1;
        
        while(data_len)
        {
            data_len = recv(new, data, MAX_DATA, 0);
            
            if(data_len)
            {
                send(new, data, data_len, 0);
                printf("Sent mesg: \n");
                dump(data, data_len);
            }
            
        }

        printf("Client disconnected\n");
        
        close(new);
        fflush(stdout);
        
    }

    close(sock);

    
}

