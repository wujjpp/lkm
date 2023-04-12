#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char           *device;
    pcap_t         *pcap;
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

    u_char c[78] = {
0x40, 0x31, 0x3c, 0x0d, 0x2f, 0xd7, 0xa4, 0xcf, 0x99, 0x58, 0x45, 0x4d, 0x08, 0x00, 0x45, 0x00,
0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x84, 0x1c, 0xc0, 0xa8, 0x1f, 0x94, 0x65, 0x25,
0x71, 0x3a, 0xd6, 0x1f, 0x01, 0xbb, 0xad, 0xd6, 0x32, 0x1c, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02,
0xff, 0xff, 0xc1, 0x90, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01,
0x08, 0x0a, 0x7c, 0x93, 0x8a, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00
};

    fprintf(stdout, "%d\n", pcap_inject(pcap, c, 78));
}