/*
 * Created by Wu Jian Ping on - 2023/04/06.
 */

#include "capture.h"

static void handle_ipv4_packet(u_char *args, const pcap_pkthdr_t *header, const u_char *packet);
static void handle_ipv6_packet(u_char *args, const pcap_pkthdr_t *header, const u_char *packet);
static void handle_arp_packet(u_char *args, const pcap_pkthdr_t *header, const u_char *packet);
static char *get_protocol_name(u_int8_t next_header);

void handle_packet(u_char *args, const pcap_pkthdr_t *header, const u_char *packet) {
    ether_header_t  *eth_header;
    u_int16_t        ether_type;

    if(header->len < ETHER_HDR_LEN) {
        return;
    }
  
    eth_header = (ether_header_t *) packet;
    ether_type = ntohs(eth_header->ether_type);

    switch(ether_type) {
        case ETHERTYPE_IP:
            handle_ipv4_packet(args, header, packet);
            break;

        case ETHERTYPE_IPV6:
            handle_ipv6_packet(args, header, packet);
            break;

        case ETHERTYPE_ARP:
            handle_arp_packet(args, header, packet);
            break;

        case ETHERTYPE_REVARP:
            handle_arp_packet(args, header, packet);
            break;
    }
}

static void handle_ipv4_packet(u_char *args, const pcap_pkthdr_t *header, const u_char *packet) {
    ether_header_t  *eth_header;
    ipv4_header_t   *ip_header;
    u_int16_t        total_len, offset;

    if(header->len < (ETHER_HDR_LEN + IPV4_HDRLEN)) {
        return;
    }

    fprintf(stdout, "\n");

    eth_header = (ether_header_t *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    ip_header = (ipv4_header_t *)(packet + ETHER_HDRLEN);

    if(ip_header->ip_version != 4) {
        return;
    }

    if(ip_header->ip_header_lenth < 5) {
        return;
    }

    fprintf(stdout, "-----------------------------------------------------------------------------------------------------------------------------------------\n");

    /* ip package length + ether header length */
    total_len = ntohs(ip_header->ip_len) + ETHER_HDRLEN; 

    fprintf(stdout, "(IPv4 - %s) %4d bytes ", get_protocol_name(ip_header->ip_p), total_len);
    fprintf(stdout, "tos: 0x%02x ", ip_header->ip_tos);
    fprintf(stdout, "id: %5d ", ntohs(ip_header->ip_id));

    fprintf(stdout, "RF: %d DF: %d MF: %d ",
                    (ntohs(ip_header->ip_off) & IP_RF) >> 15,
                    (ntohs(ip_header->ip_off) & IP_DF) >> 14,
                    (ntohs(ip_header->ip_off) & IP_MF) >> 13);

    offset = ntohs(ip_header->ip_off) & IP_OFFMASK;
    fprintf(stdout, "offset: %d ", offset);

    fprintf(stdout, "ttl: %d ", ip_header->ip_ttl);
    fprintf(stdout, "sum: 0x%04x ", ntohs(ip_header->ip_sum));
    // fprintf(stdout,"mac: %s" , ether_ntoa((const struct ether_addr *)&eth_header->ether_shost));

    fprintf(stdout, 
            "mac: %02x:%02x:%02x:%02x:%02x:%02x", 
            eth_header->ether_shost[0],
            eth_header->ether_shost[1],
            eth_header->ether_shost[2],
            eth_header->ether_shost[3],
            eth_header->ether_shost[4],
            eth_header->ether_shost[5]);

    fprintf(stdout, "  ip: %15s", inet_ntoa(ip_header->ip_src));
    
    fprintf(stdout, " -> ");

    // fprintf(stdout,"mac: %s" , ether_ntoa((const struct ether_addr *)&eth_header->ether_dhost));

    fprintf(stdout, 
            "mac: %02x:%02x:%02x:%02x:%02x:%02x", 
            eth_header->ether_dhost[0],
            eth_header->ether_dhost[1],
            eth_header->ether_dhost[2],
            eth_header->ether_dhost[3],
            eth_header->ether_dhost[4],
            eth_header->ether_dhost[5]
          );

    fprintf(stdout, "  ip: %15s", inet_ntoa(ip_header->ip_dst));
}


static void handle_ipv6_packet(u_char *args, const pcap_pkthdr_t *header, const u_char *packet) {
    ether_header_t  *eth_header;
    ipv6_header_t   *ip_header;
    u_int16_t        total_len;
    char             src_ip_buf[INET6_ADDRSTRLEN] = {'\0'};
    char             dst_ip_buf[INET6_ADDRSTRLEN] = {'\0'};

    if(header->len < (ETHER_HDR_LEN + IPV6_HDRLEN)) {
        return;
    }

    fprintf(stdout, "\n");

    eth_header = (ether_header_t *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IPV6) {
        return;
    }

    ip_header = (ipv6_header_t *)((u_char *)(packet + ETHER_HDRLEN));

    if(ip_header->version != 6) {
        return;
    }

    fprintf(stdout, "-----------------------------------------------------------------------------------------------------------------------------------------\n");

    /* payload length + ether header length +  ipv6 header lendth */
    total_len = ntohs(ip_header->payload_len) + ETHER_HDRLEN + IPV6_HDRLEN;
    fprintf(stdout, "(IPv6 - %s) %4d bytes  ", get_protocol_name(ip_header->next_header), total_len);

    fprintf(stdout, 
            "mac: %02x:%02x:%02x:%02x:%02x:%02x", 
            eth_header->ether_shost[0],
            eth_header->ether_shost[1],
            eth_header->ether_shost[2],
            eth_header->ether_shost[3],
            eth_header->ether_shost[4],
            eth_header->ether_shost[5]);

    inet_ntop(AF_INET6, &ip_header->ip_src, src_ip_buf, INET6_ADDRSTRLEN);
    fprintf(stdout, "  ip6: %-40s", src_ip_buf);

    
    fprintf(stdout, " -> ");

    fprintf(stdout, 
            "mac: %02x:%02x:%02x:%02x:%02x:%02x", 
            eth_header->ether_dhost[0],
            eth_header->ether_dhost[1],
            eth_header->ether_dhost[2],
            eth_header->ether_dhost[3],
            eth_header->ether_dhost[4],
            eth_header->ether_dhost[5]
          );

    inet_ntop(AF_INET6, &ip_header->ip_dst, dst_ip_buf, INET6_ADDRSTRLEN);
    fprintf(stdout, "  ip6: %-40s", dst_ip_buf);
}

static void handle_arp_packet(u_char *args, const pcap_pkthdr_t *header, const u_char *packet) {
    ether_header_t  *eth_header;
    arp_header_t    *arp_header;

    if(header->len < (ETHER_HDR_LEN + ARP_HRDLEN)) {
        return;
    }

    fprintf(stdout, "\n");

    eth_header = (ether_header_t *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_ARP) {
        return;
    }

    arp_header = (arp_header_t *)(packet + ETHER_HDR_LEN);

    fprintf(stdout, "-----------------------------------------------------------------------------------------------------------------------------------------\n");

    fprintf(stdout, "(IP - ARP) ");

    fprintf(stdout, "hardware_type: %d ", ntohs(arp_header->hardware_type));
    fprintf(stdout, "protocol_type: 0x%04x ", ntohs(arp_header->protocol_type));

    fprintf(stdout, "hardware_size: %d ", arp_header->hardware_size);
    fprintf(stdout, "protocol_size: %d ", arp_header->protocol_size);

    fprintf(stdout, "opcode: %d ", ntohs(arp_header->op_type));

    fprintf(stdout, 
            "mac: %02x:%02x:%02x:%02x:%02x:%02x ", 
            arp_header->sender_mac[0],
            arp_header->sender_mac[1],
            arp_header->sender_mac[2],
            arp_header->sender_mac[3],
            arp_header->sender_mac[4],
            arp_header->sender_mac[5]);

    fprintf(stdout, "ip: %d.%d.%d.%d", arp_header->sender_ip[0], arp_header->sender_ip[1], arp_header->sender_ip[2], arp_header->sender_ip[3]);

    fprintf(stdout, " -> ");

    fprintf(stdout, 
            "mac: %02x:%02x:%02x:%02x:%02x:%02x", 
            arp_header->target_mac[0],
            arp_header->target_mac[1],
            arp_header->target_mac[2],
            arp_header->target_mac[3],
            arp_header->target_mac[4],
            arp_header->target_mac[5]
          );

    fprintf(stdout, " ip: %d.%d.%d.%d", arp_header->target_ip[0], arp_header->target_ip[1], arp_header->target_ip[2], arp_header->target_ip[3]);
}

int main(int argc, char **argv) {
    char           *device;
    pcap_t         *pcap;
    bpf_program_t   fp;
    bpf_u_int32     netp = 0;
    char            error[PCAP_ERRBUF_SIZE];

    if(argc < 2){ 
        fprintf(stdout,"Usage: %s ether, ex: %s eth0\n", argv[0], argv[0]);
        return 0;
    }

    device = argv[1];

    pcap = pcap_create(device, error);

    if(pcap == NULL) {
        fprintf(stdout, "err: %s\n", error);
        return 1;
    }

    pcap_set_snaplen(pcap, 2048); /* ETHER_HDRLEN + IPV6_HDRLEN */
    pcap_set_immediate_mode(pcap, 1);

    if(pcap_activate(pcap) != 0) {
        fprintf(stdout, "active failed");
        return 1;
    }

    if(pcap_setnonblock(pcap, 1, error) == PCAP_ERROR) {
        fprintf(stdout, "pcap_setnonblock failed: %s\n", error);
    }

    // if(pcap_compile(pcap, &fp, "host 101.37.113.58", 0, netp) == -1) { 
    //     fprintf(stdout, "Error calling pcap_compile\n"); 
    //     exit(1); 
    // }

    if(pcap_compile(pcap, &fp, "arp", 0, netp) == -1) { 
        fprintf(stdout, "Error calling pcap_compile\n"); 
        exit(1); 
    }

    // if(pcap_compile(pcap, &fp, "dst port 443 and host 101.37.113.58", 1, netp) == -1) { 
    //     fprintf(stdout, "Error calling pcap_compile\n"); 
    //     exit(1); 
    // }

    // if(pcap_compile(pcap, &fp, "ip6", 1, netp) == -1) { 
    //     fprintf(stdout, "Error calling pcap_compile\n"); 
    //     exit(1); 
    // }

    if(pcap_setfilter(pcap, &fp) == -1) { 
        fprintf(stdout, "Error setting filter\n"); 
        exit(1); 
    }

    pcap_loop(pcap, 0, handle_packet, NULL);

    return 0;
}

static char *get_protocol_name(u_int8_t next_header) {
    switch(next_header) {
        case PACKET_TCP:
            return "TCP";
        case PACKET_UDP:
            return "UDP";
        case PACKET_ICMP:
            return "ICMP";
        case PACKET_ICMPV6:
            return "ICMPV6";
        default:
            return NULL;
    }
}
