//www.binarytides.com/packet-sniffer-code-c-linux/

//www.binarytides.com/packet-sniffer-code-in-c-using-linux-sockets-bsd-part-2/

//stackoverflow.com/questions/22206791/packet-sniffer-under-linux-in-c-c

//stackoverflow.com/questions/1637835/packet-sniffing-using-raw-sockets-in-linux-in-c


/*

A packet analyzer (also known as a network analyzer, protocol analyzer or packet sniffer—or, for particular types of networks, an Ethernet sniffer or wireless sniffer) is a computer program or piece of computer hardware that can intercept and log traffic that passes over a digital network or part of a network. As data streams flow across the network, the sniffer captures each packet and, if needed, decodes the packet's raw data, showing the values of various fields in the packet, and analyzes its content according to the appropriate RFC or other specifications. [32] Wireshark for example is the most popular packet sniffer out there and is available for all platforms. Its gui based and very easy to use.

//en.wikipedia.org/wiki/Packet_analyzer

In this chapter we are going to talk about how to code and make our own packet sniffer in C and on the linux platform. 

Note that it sniffs only incoming packets. [33]

//www.binarytides.com/packet-sniffer-code-c-linux/

*/


#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
//can get
#include<netinet/tcp.h>   //Provides declarations for tcp header
//can get
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
 
void ProcessPacket(unsigned char* , int);
void printipheader(unsigned char* , int);
void printtcppacket(unsigned char* , int);
void PrintData (unsigned char* , int);
 
int sock_raw;
FILE *logfile;
int tcp=0,others=0,total=0,i,j;

/*

struct sockaddr_in{
  short sin_family;
  unsigned short sin_port;
  IN_ADDR sin_addr;
  char sin_zero[8];
};
members in struct:
sin_family
    Address family; must be AF_INET.
sin_port
    Internet Protocol (IP) port.
sin_addr
    IP address in network byte order.
sin_zero
    Padding to make structure the same size as SOCKADDR.

*/

struct sockaddr_in source,dest;
 
/*
In the main() function we:

1. Create a raw socket, using socket() function.
2. Put it in a recvfrom loop and receive data on it, and process the recieved data.
3. close the socket after at the end.

*/

int main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct in_addr in;
     
    //create a buffer to hold large amount of data
    unsigned char *buffer = (unsigned char *)malloc(65536); 
     
    logfile=fopen("log222.txt","w");
    if(logfile==NULL) printf("Unable to create file.");
    printf("Starting...\n");
    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        ProcessPacket(buffer , data_size);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}
 
/*

In this ProcessPacket function, we:

1. get the IP header part of the packet.
2. check the protocol and see if it's tcp in this case
3. if it's tcp, then print the packet in tcp format

*/


void ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    { 
        case 6:  //TCP Protocol
            ++tcp;
            fprintf(logfile,"Data Payload\n"); 
            PrintData(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   Others : %d   Total : %d\r",tcp,others,total);
}

 
void PrintData (unsigned char* data , int Size)
{
     
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile,"."); //otherwise print a dot
            }
            fprintf(logfile,"\n");
        }
         
        if(i%16==0) fprintf(logfile,"   ");
            fprintf(logfile," %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces
             
            fprintf(logfile,"         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
                else fprintf(logfile,".");
            }
            fprintf(logfile,"\n");
        }
    }
}
