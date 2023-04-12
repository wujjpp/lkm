/*
 * Created by Wu Jian Ping on - 2023/04/07.
 */

#include <stdlib.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

typedef struct {
} empty_t;

typedef struct {
    u_int8_t        version;
    u_int8_t        traffic_class;
    u_int32_t       flow_label;   
    
} ipv6_header_t;

typedef struct {
    unsigned char   a:2;
    unsigned char   b:2;
    unsigned char   c:2;
    unsigned char   d:2;
} bit_char_field_t;


typedef struct {
    unsigned        a:2;
    unsigned        b:2;
    unsigned        c:2;
    unsigned        d:2;
} bit_unsigned_field_t;

typedef struct {
    unsigned char   a:4;
    u_int16_t       b:8;
    u_int16_t       c;
} bit_area_t;


int main() {
    ipv6_header_t ipv6_header;
    bit_char_field_t bit_char = {
        .a = 0b00,
        .b = 0b01,
        .c = 0b10,
        .d = 0b11
    };

    bit_area_t bit_area;

    printf("                sizeof(char): %lu\n", sizeof(char));
    printf("       sizeof(unsigned char): %lu\n", sizeof(unsigned char));
    printf("            sizeof(u_int8_t): %lu\n", sizeof(u_int8_t));
    printf("           sizeof(u_int16_t): %lu\n", sizeof(u_int16_t));
    printf("           sizeof(u_int32_t): %lu\n", sizeof(u_int32_t));
    printf("            sizeof(unsigned): %lu\n", sizeof(unsigned));
    printf("       sizeof(unsigned long): %lu\n", sizeof(unsigned long));
    printf("             sizeof(empty_t): %lu\n", sizeof(empty_t));
    printf("         sizeof(bit_field_t): %lu\n", sizeof(bit_char_field_t));
    printf("sizeof(bit_unsigned_field_t): %lu\n", sizeof(bit_unsigned_field_t));
    printf("          sizeof(bit_area_t): %lu\n", sizeof(bit_area_t));

    printf("\n");

    printf("                     version: %p addr + 0\n", (void *)&ipv6_header.version);
    printf("               traffic_class: %p addr + 1\n", (void *)&ipv6_header.traffic_class);
    printf("                  flow_label: %p addr + 4 前面不足4 bytes，按4 bytes算\n", (void *)&ipv6_header.flow_label);
    printf("       sizeof(ipv6_header_t): %lu\n", sizeof(ipv6_header_t));
    printf("         sizeof(ipv6_header): %lu\n", sizeof(ipv6_header));

    printf("\n");

    printf("                  bit_char.a: %d\n", bit_char.a);
    printf("                  bit_char.b: %d\n", bit_char.b);
    printf("                  bit_char.c: %d\n", bit_char.c);
    printf("                  bit_char.d: %d\n", bit_char.d);

    printf("\n");

    u_int32_t   n  = 0x78563412;
    char       *np = (void *)&n;

    memcpy(&bit_area, &n, sizeof(n));
    printf("                 u_int16_t n: 0x%x\n", n);
    printf("                  bit_area.a: 0x%x\n", bit_area.a);
    printf("                  bit_area.b: 0x%x\n", bit_area.b);
    printf("                          &n: %p\n", (void *)&n);
    printf("                         np0: %x\n", *np);
    printf("                         np1: %x\n", *(np + 1));
    printf("                         np2: %x\n", *(np + 2));
    printf("                         np3: %x\n", *(np + 3));
    printf("                    np0 addr: %p\n", (void *)np);
    printf("                    np1 addr: %p\n", (void *)++np);
    printf("                    np1 addr: %p\n", (void *)++np);
    printf("                    np1 addr: %p\n", (void *)++np);

    printf("\n");

    char *heap   = malloc(2);
    char *heap_p = heap;

    printf("                  heap0 addr: %p\n", (void *)heap_p);
    printf("                  heap1 addr: %p\n", (void *)++heap_p);
    free(heap);

    printf("\n移位操作:\n");

    // u_int64_t s = 0b0001001000110100010101100111100010011010101111001101111011110000;
    u_int64_t s = 0x123456789abcdef0;
    printf("s: %llx, s >> 4: %llx, s >> 8: %llx, s >> 32: %llx, s << 4 >> 8: %llx\n", s, s >> 4, s >> 8, s >> 32, s << 4 >> 8);
    printf("s: %llx, s << 3: %llx\n", s, s << 3);

    // u_int16_t s1 = 0b0100000000000000;
    u_int16_t s1 = 0x4000;
    u_int16_t s2 = s1 << 3;
    printf("s1: 0x%04x(%d), s1 << 1: 0x%04x(%d), s1 << 2: 0x%04x(%d), s1 << 3: 0x%04x(%d), s1 << 4: 0x%04x(%d), (s1 & 0x1fff) << 3: 0x%04x(%d), s2: 0x%04x(%d)\n", 
            s1, s1,
            s1 << 1, s1 << 1, 
            s1 << 2, s1 << 2,
            s1 << 3, s1 << 3,
            s1 << 4, s1 << 4,
            (s1 & 0x1fff) << 3, (s1 & 0x1fff) << 3,
            s2, s2
          );
    printf("sizeof(s1): %lu, sizeof(s1 << 3): %lu\n", sizeof(s1), sizeof(s1 << 1));

    u_int8_t s3 = 0x80;
    u_int8_t s4 = s3 << 1;
    printf("sizeof(s3): %lu, sizeof(s3 << 1): %lu, s4: %0x\n", sizeof(s3), sizeof(s3 << 1), s4);

}
