#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>

/* 接收缓冲区大小 */
#define RCV_BUF_SIZE     1024 * 5

/* 接收缓冲区 */
static int g_iRecvBufSize = RCV_BUF_SIZE; 
static char g_acRecvBuf[RCV_BUF_SIZE] = {0};

/* 物理网卡接口,需要根据具体情况修改 */
static const char *g_szIfName = "eth1";
 
/* 以太网帧封装的协议类型 */
static const int      g_iEthProId[] = { ETHERTYPE_PUP, 
                                        ETHERTYPE_SPRITE, 
                                        ETHERTYPE_IP, 
                                        ETHERTYPE_ARP,
                                        ETHERTYPE_REVARP,
                                        ETHERTYPE_AT,
                                        ETHERTYPE_AARP,
                                        ETHERTYPE_VLAN,
                                        ETHERTYPE_IPX,
                                        ETHERTYPE_IPV6,
                                        ETHERTYPE_LOOPBACK
                                      };
static const char g_szProName[][24] = { "none", "xerox pup", "sprite", "ip", "arp", 
                                        "rarp", "apple-protocol", "apple-arp", 
                                        "802.1q", "ipx", "ipv6", "loopback" 
                                      };


/* 输出MAC地址 */
static void ethdump_showMac(const int iType, const char acHWAddr[]) 
{
    int i = 0;

    if (0 == iType)
    {
        printf("SMAC=[");
    }
    else
    {
        printf("DMAC=[");
    }

    for(i = 0; i < ETHER_ADDR_LEN - 1; i++)
    {
        printf("%02x:", *((unsigned char *)&(acHWAddr[i])));
    }
    printf("%02x] ", *((unsigned char *)&(acHWAddr[i])));
}

/* 物理网卡混杂模式属性操作 */
static int ethdump_setPromisc(const char *pcIfName, int fd, int iFlags)
{
    int iRet = -1;
    struct ifreq stIfr;

    /* 获取接口属性标志位 */
    strcpy(stIfr.ifr_name, pcIfName);
    iRet = ioctl(fd, SIOCGIFFLAGS, &stIfr);
    if (0 > iRet)
    {
        perror("[Error]Get Interface Flags");    
        return -1;
    }
    
    if (0 == iFlags)
    {
        /* 取消混杂模式 */
        stIfr.ifr_flags &= ~IFF_PROMISC;
    }
    else
    {
        /* 设置为混杂模式 */
        stIfr.ifr_flags |= IFF_PROMISC;
    }

    iRet = ioctl(fd, SIOCSIFFLAGS, &stIfr);
    if (0 > iRet)
    {
        perror("[Error]Set Interface Flags");
        return -1;
    }
    
    return 0;
}

/* 获取L2帧封装的协议类型 */
static char *ethdump_getProName(const int iProNum)
{
    int iIndex = 0; 
    
    for(iIndex = 0; iIndex < sizeof(g_iEthProId) / sizeof(g_iEthProId[0]); iIndex++)
    {
        if (iProNum == g_iEthProId[iIndex])
        {
            break;
        }
    }

    return (char *)(g_szProName[iIndex + 1]);
}

/* Init L2 Socket */
static int ethdump_initSocket()
{
    int iRet = -1;
    int fd = -1;
    struct ifreq stIf;
    struct sockaddr_ll stLocal = {0};
    
    /* 创建SOCKET */
    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (0 > fd)
    {
        perror("[Error]Initinate L2 raw socket");
        return -1;
    }
    
    /* 网卡混杂模式设置 */
    ethdump_setPromisc("ETH1", fd, 1);

    /* 设置SOCKET选项 */
    iRet = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &g_iRecvBufSize,sizeof(int));
    if (0 > iRet)
    {
        perror("[Error]Set socket option");
        close(fd);
        return -1; 
    }
    
    /* 获取物理网卡接口索引 */
   /* strcpy(stIf.ifr_name, g_szIfName);
    iRet = ioctl(fd, SIOCGIFINDEX, &stIf);
    if (0 > iRet)
    {
        perror("[Error]Ioctl operation");
        close(fd);
        return -1;
    }
*/
    /* 绑定物理网卡 */
    stLocal.sll_family = PF_PACKET;
    stLocal.sll_ifindex = stIf.ifr_ifindex;
    stLocal.sll_protocol = htons(ETH_P_ALL);
    iRet = bind(fd, (struct sockaddr *)&stLocal, sizeof(stLocal)); 
    if (0 > iRet)
    {
        perror("[Error]Bind the interface");
        close(fd);
        return -1;
    }
    
    return fd;    
}

/* 解析Ethernet帧首部 */
static int ethdump_parseEthHead(const struct ether_header *pstEthHead)
{
    unsigned short usEthPktType;

    if (NULL == pstEthHead)
    {
        return -1;
    }

    /* 协议类型、源MAC、目的MAC */
    usEthPktType = ntohs(pstEthHead->ether_type);
    printf(">>>\nEth-Pkt-Type:0x%04x(%s) ", usEthPktType, ethdump_getProName(usEthPktType));
    ethdump_showMac(0, pstEthHead->ether_shost);
    ethdump_showMac(1, pstEthHead->ether_dhost);
    
    return 0;    
}

/* 解析IP数据包头 */
static int ethdump_parseIpHead(const struct ip *pstIpHead)
{
    struct protoent *pstIpProto = NULL;

    if (NULL == pstIpHead)
    {
        return -1;
    }

    /* 协议类型、源IP地址、目的IP地址 */
    pstIpProto = getprotobynumber(pstIpHead->ip_p);
    if(NULL != pstIpProto)
    {
        printf("\nIP-Pkt-Type:%d(%s) ", pstIpHead->ip_p, pstIpProto->p_name);
    }
    else
    {
        printf("\nIP-Pkt-Type:%d(%s) ", pstIpHead->ip_p, "None");
    }
    printf("SAddr=[%s] ", inet_ntoa(pstIpHead->ip_src));
    printf("DAddr=[%s]\n", inet_ntoa(pstIpHead->ip_dst));

    return 0;
}

/* 数据帧解析函数 */
static int ethdump_parseFrame(const char *pcFrameData)
{
    int iRet = -1;

    struct ether_header *pstEthHead = NULL;
    struct ip *pstIpHead = NULL;

    /* Ethnet帧头解析 */
    pstEthHead = (struct ether_header*)g_acRecvBuf;
    iRet = ethdump_parseEthHead(pstEthHead);
    if (0 > iRet)
    {
        return iRet;
    }

    /* IP数据包类型 */
    pstIpHead  = (struct ip *)(pstEthHead + 1);
    iRet = ethdump_parseIpHead(pstIpHead);

    return iRet;
}

/* 捕获网卡数据帧 */
static void ethdump_startCapture(const int fd)
{
    int iRet = -1;
    socklen_t stFromLen = 0;
    
    /* 循环监听 */
    while(1)
    {
        /* 清空接收缓冲区 */
        memset(g_acRecvBuf, 0, RCV_BUF_SIZE);

        /* 接收数据帧 */
        iRet = recvfrom(fd, g_acRecvBuf, g_iRecvBufSize, 0, NULL, &stFromLen);
        if (0 > iRet)
        {
            continue;
        }
        
        /* 解析数据帧 */
        ethdump_parseFrame(g_acRecvBuf);
    }
}   

/* Main */
int main(int argc, char *argv[])
{
    int iRet = -1;
    int fd   = -1;
    
    /* 初始化SOCKET */
    fd = ethdump_initSocket();
    if(0 > fd)
    {
        return -1;
    }
    
    /* 捕获数据包 */
    ethdump_startCapture(fd);
    
    /* 关闭SOCKET */
    close(fd);

    return 0;
}
