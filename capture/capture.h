/*
 * Created by Wu Jian Ping on - 2023/04/07.
 */

#ifndef __CAPTURE_H_INCLUDED__
#define __CAPTURE_H_INCLUDED__

#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <stdlib.h>

#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN      14
#endif

#ifndef IPV4_HDRLEN 
#define IPV4_HDRLEN       20
#endif

#ifndef IPV6_HDRLEN 
#define IPV6_HDRLEN       40
#endif

#ifndef ARP_HRDLEN
#define ARP_HRDLEN        28
#endif

#define PACKET_ICMP        1
#define PACKET_TCP         6
#define PACKET_UDP        17
#define PACKET_ICMPV6     58
/*
                           IPv4 packet datagram

       0                   1                   2                   3   
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |Version|  IHL  |Type of Service|          Total Length         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |         Identification        |Flags|      Fragment Offset    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Time to Live |    Protocol   |         Header Checksum       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Source Address                          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    Destination Address                        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    Options                    |    Padding    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

typedef struct {
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int8_t        ip_header_lenth:4;        /* header length */
    u_int8_t        ip_version:4;             /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int8_t        ip_version:4;             /* version */
    u_int8_t        ip_header_lenth:4;        /* header length */
#endif

    u_int8_t        ip_tos;                   /* type of service */
    u_int16_t       ip_len;                   /* total length */
    u_int16_t       ip_id;                    /* identification */
    u_int16_t       ip_off;	                  /* fragment offset field */
    u_int8_t        ip_ttl;	                  /* time to live */
    u_int8_t        ip_p;                     /* protocol */
    u_int16_t       ip_sum;                   /* checksum */
    struct in_addr  ip_src, ip_dst;           /* source and dest address */
} ipv4_header_t;


/*
                            IPv6 packet datagram

       0                   1                   2                   3   
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |Version|  Traffic Class |              Flow Label              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |         Playload Length        |  Next Header  |   Hop Limit  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                       Source Address                          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                    Destination Address                        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

typedef struct {
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int8_t        traffic_class_1:4;         /* traffic_class_1 */
    u_int8_t        version:4;                 /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int8_t        version:4;                 /* version */
    u_int8_t        traffic_class_1:4;         /* traffic_class_1 */
#endif


#if BYTE_ORDER == LITTLE_ENDIAN
    u_int8_t        flow_label_1:4;            /* flow_label_1 */
    u_int8_t        traffic_class_2:4;         /* traffic_class_2 */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int8_t         traffic_class_2:4;        /* traffic_class_2 */
    u_int8_t         flow_label_1:4;           /* flow_label_1 */
#endif

    u_int16_t       flow_label_2;              /* flow_label_2 */
    u_int16_t       payload_len;               /* payload length */
    u_int8_t        next_header;               /* next header */
    u_int8_t        hop_limit;	               /* hop limit */
    in6_addr_t      ip_src, ip_dst;            /* source and dest address */
} ipv6_header_t;

typedef struct {
    u_int16_t       port_src;
    u_int16_t       port_dst;
    u_int32_t       data_seq;
    u_int32_t       ack_seq;
} tcp_header_t;

typedef struct pcap_pkthdr pcap_pkthdr_t;
typedef struct ether_header ether_header_t;
typedef struct bpf_program bpf_program_t;

/*
                            ARP packet datagram

       0                   1                   2                   3   
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |          Hardware Type         |        Protocol Type         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |Hardware Lendth |Protocol Length|            Op Type           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          Sender MAC                           |
      |                                |          Sender IP           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          Target MAC                           |
      |                                |          Target IP           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

typedef struct {
    u_int16_t       hardware_type;                /* type of hardware*/
    u_int16_t       protocol_type;                /* type of protocol */
    u_int8_t        hardware_size;                /* hardware address length */
    u_int8_t        protocol_size;                /* protocol length */
    u_int16_t       op_type;                      /* request: 1, reply: 2, re-request: 3, re-reply: 4 */
    u_char          sender_mac[ETHER_ADDR_LEN];   /* sender mac */
    u_char          sender_ip[4];                 /* sender ip */
    u_char          target_mac[ETHER_ADDR_LEN];   /* target mac */
    u_char          target_ip[4];                    /* target ip */
} arp_header_t;

void handle_packet(u_char *args, const pcap_pkthdr_t *header, const u_char *packet);

#endif
