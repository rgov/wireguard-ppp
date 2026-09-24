#ifndef WIREGUARD_PPP_LWIPOPTS_H
#define WIREGUARD_PPP_LWIPOPTS_H

#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define MEM_LIBC_MALLOC 1
#define MEM_ALIGNMENT 8
#define MEMP_NUM_SYS_TIMEOUT 16
#define PBUF_POOL_BUFSIZE 1536

#define PPP_SUPPORT 1
#define PPP_SERVER 1
#define PPP_NOTIFY_PHASE 1
#define PPP_MRU 1400
#define PPP_MAXMRU 1400

// The host supplies TCP/IP and sockets
#define LWIP_ARP 0
#define LWIP_ICMP 0
#define LWIP_TCP 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_STATS 0
#define IP_REASSEMBLY 0
#define IP_FRAG 0

#endif
