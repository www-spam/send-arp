#pragma once

#include <cstdint>
#include <string>

#define MAC_LEN 6
#define IP_LEN 4

#pragma pack(push, 1)
struct eth_hdr_t {
    uint8_t dmac[MAC_LEN];
    uint8_t smac[MAC_LEN];
    uint16_t type;
};

struct arp_hdr_t {
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
    uint8_t smac[MAC_LEN];
    uint8_t sip[IP_LEN];
    uint8_t tmac[MAC_LEN];
    uint8_t tip[IP_LEN];
};
#pragma pack(pop)

void usage();
bool get_mac(const std::string& iface, uint8_t* mac);
