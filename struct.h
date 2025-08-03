#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
// Ethernet + ARP 헤더 구조체
#pragma pack(push, 1)
typedef struct {
    uint8_t dmac[MAC_ADDR_LEN];
    uint8_t smac[MAC_ADDR_LEN];
    uint16_t type;
} eth_hdr_t;

typedef struct {
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
    uint8_t smac[MAC_ADDR_LEN];
    uint8_t sip[IP_ADDR_LEN];
    uint8_t tmac[MAC_ADDR_LEN];
    uint8_t tip[IP_ADDR_LEN];
} arp_hdr_t;
#pragma pack(pop)
