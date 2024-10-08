#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <winsock2.h>
#include <stdlib.h>
#include <conio.h>
#include <stdint.h>
#include <tchar.h>
#include <time.h>
#include "pcap.h"


#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )

#define TCP_OPTION 12
#define TCP_HEADER_JMP 20
#define SIZE_ETHERNET 14
#define ARP_REPLY_SIZE 46
#define ARP_REQUEST_SIZE 28
//각각 응용계층 프로토콜이 사용하는 포트 정의
#define HTTP 80   
#define SMTP 25
#define POP3 110
#define IMAP 143
#define DNS 53
#define SSH 22
#define FTP_DATA 20
#define FTP_CONTROLL 21
#define TELNET 23
#define TCP 6
#define UDP 17
//각각의 flag의 값 정의
#define SYN 0x02
#define PUSH 0x08
#define ACK 0x10
#define SYN_ACK 0x12
#define PUSH_ACK 0x18
#define FIN_ACK 0x11
#define DHCP_SERVER 67
#define DHCP_CLIENT 68

//프로토콜별 헤더를 구조체로 정의해 캡처된 패킷에서 구조체 포인터로 각각의 헤더 정보를 얻어옴.
struct ether_addr
{
    unsigned char ether_addr_octet[6];
};

struct ether_header
{
    struct  ether_addr ether_dhost;
    struct  ether_addr ether_shost;
    unsigned short ether_type;
};

struct ip_header
{
    unsigned char ip_header_len : 4;
    unsigned char ip_version : 4;
    unsigned char ip_tos;
    unsigned short ip_total_length;
    unsigned short ip_id;
    unsigned char ip_frag_offset : 5;
    unsigned char ip_more_fragment : 1;
    unsigned char ip_dont_fragment : 1;
    unsigned char ip_reserved_zero : 1;
    unsigned char ip_frag_offset1;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short ip_checksum;
    struct in_addr ip_srcaddr;
    struct in_addr ip_destaddr;
};

struct tcp_header
{
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int sequence;
    unsigned int acknowledge;

    unsigned char reserved_part1 : 3;
    unsigned char ns : 1;
    unsigned char data_offset : 4;
    unsigned char cwr : 1;
    unsigned char ecn : 1;
    unsigned char urg : 1;
    unsigned char ack : 1;
    unsigned char psh : 1;
    unsigned char rst : 1;
    unsigned char syn : 1;
    unsigned char fin : 1;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};
struct udp_header
{
    unsigned short sourcePort;
    unsigned short destPort;
    unsigned short udpLength;
    unsigned short udpChecksum;
};
struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};
struct dns_header {
    unsigned short id;
    unsigned short flag;
    unsigned short qCount;
    unsigned short ansCount;
    unsigned short authCount;
    unsigned short addCount;
};
struct dhcp_packet { //
    uint8_t op; /* 0: Message opcode/type */
    uint8_t htype; /* 1: Hardware addr type (net/if_types.h) */
    uint8_t hlen; /* 2: Hardware addr length */
    uint8_t hops; /* 3: Number of relay agent hops from client */
    uint32_t xid; /* 4: Transaction ID */
    uint16_t secs; /* 8: Seconds since client started looking */
    uint16_t flags; /* 10: Flag bits */
    struct in_addr ciaddr; /* 12: Client IP address (if already in use) */
    struct in_addr yiaddr; /* 16: Client IP address */
    struct in_addr siaddr; /* 18: IP address of next server to talk to */
    struct in_addr giaddr; /* 20: DHCP relay agent IP address */
    const unsigned char chaddr[16]; /* 24: Client hardware address */
    char sname[64]; /* 40: Server name */
    char file[128]; /* 104: Boot filename */
    /* 212: Optional parameters
    (actual length dependent on MTU). */
};


struct CheckSummer
{
    u_short part1;
    u_short part2;
    u_short part3;
    u_short part4;
    u_short part5;
    u_short checksum;
    u_short part6;
    u_short part7;
    u_short part8;
    u_short part9;
};

struct packet {
    int no;
    struct pcap_pkthdr* p_header;
    struct ether_header* p_ether;
    struct ip_header* p_ip;
    struct tcp_header* p_tcp;
    struct udp_header* p_udp;
    struct arp_header* p_arp;
    struct dns_header* p_dns;
    struct dhcp_packet* p_dhcp;
    char* app;
};


struct node {
    int type;
    struct packet info;
    struct node* next;
    struct node* prev;
};

void print_ether_header(ether_header* data)
{
    struct  ether_header* eh;               // 이더넷 헤더 구조체
    unsigned short ether_type;
    eh = data;
    ether_type = ntohs(eh->ether_type);       // 숫자는 네트워크 바이트 순서에서 호스트 바이트 순서로 바꿔야함

    if (ether_type == 0x0800)
    {
        printf("<<<IPv4>>>\n");
    }
    else if (ether_type == 0x0806)
    {
        printf("\n\n\n<<<ARP>>>\n");
    }
    // 이더넷 헤더 출력
    printf("============Ethernet Header==================================================================================================================\n");
    printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for dest
        eh->ether_dhost.ether_addr_octet[0],
        eh->ether_dhost.ether_addr_octet[1],
        eh->ether_dhost.ether_addr_octet[2],
        eh->ether_dhost.ether_addr_octet[3],
        eh->ether_dhost.ether_addr_octet[4],
        eh->ether_dhost.ether_addr_octet[5]);
    printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for src
        eh->ether_shost.ether_addr_octet[0],
        eh->ether_shost.ether_addr_octet[1],
        eh->ether_shost.ether_addr_octet[2],
        eh->ether_shost.ether_addr_octet[3],
        eh->ether_shost.ether_addr_octet[4],
        eh->ether_shost.ether_addr_octet[5]);
    printf("=============================================================================================================================================\n");
}
void print_ip(ip_header* ip)
{

    printf("============IP Header========================================================================================================================\n");
    printf(" |-IP Version : %d\n", (unsigned int)ip->ip_version);
    printf(" |-IP Header Length : %d DWORDS or %d Bytes\n", (unsigned int)ip->ip_header_len, ((unsigned int)(ip->ip_header_len) * 4));
    printf(" |-Type Of Service : %d\n", (unsigned int)ip->ip_tos);
    printf(" |-IP Total Length : %d Bytes(Size of Packet)\n", ntohs(ip->ip_total_length));
    printf(" |-Identification : %d\n", ntohs(ip->ip_id));
    printf(" |-TTL : %d\n", (unsigned int)ip->ip_ttl);
    printf(" |-Protocol : %d\n", (unsigned int)ip->ip_protocol);
    printf(" |-Checksum : %d\n", ntohs(ip->ip_checksum));
    printf(" |-Source IP : %s\n", inet_ntoa(ip->ip_srcaddr));
    printf(" |-Destination IP : %s\n", inet_ntoa(ip->ip_destaddr));
    printf("=============================================================================================================================================\n");
}

void print_tcp(tcp_header* tcp) {
    printf("============TCP Header=======================================================================================================================\n");
    printf(" |-Source Port : %u\n", ntohs(tcp->source_port));
    printf(" |-Destination Port : %u\n", ntohs(tcp->dest_port));
    printf(" |-Sequence Number : %u\n", ntohl(tcp->sequence));
    printf(" |-Acknowledge Number : %u\n", ntohl(tcp->acknowledge));
    printf(" |-Header Length : %d DWORDS or %d BYTES\n", (unsigned int)tcp->data_offset, (unsigned int)tcp->data_offset * 4);
    printf(" |-Flags :\n");
    printf("   |-URG: %d\n", (unsigned int)tcp->urg);
    printf("   |-ACK: %d\n", (unsigned int)tcp->ack);
    printf("   |-PSH: %d\n", (unsigned int)tcp->psh);
    printf("   |-RST: %d\n", (unsigned int)tcp->rst);
    printf("   |-SYN: %d\n", (unsigned int)tcp->syn);
    printf("   |-FIN: %d\n", (unsigned int)tcp->fin);
    printf(" |-Window Size : %d\n", ntohs(tcp->window));
    printf(" |-Checksum : %d\n", ntohs(tcp->checksum));
    printf(" |-Urgent Pointer : %d\n", tcp->urgent_pointer);
    printf("=============================================================================================================================================\n");
}

void print_udp(udp_header* udp) {
    printf("============UDP Header=======================================================================================================================\n");
    printf(" |-Source Port : %d\n", ntohs(udp->sourcePort));
    printf(" |-Destination Port : %d\n", ntohs(udp->destPort));
    printf(" |-UDP Length : %d\n", ntohs(udp->udpLength));
    printf(" |-UDP Checksum : %d\n", ntohs(udp->udpChecksum));
    printf("=============================================================================================================================================\n");
}

void print_packet(packet p, int type) {
    if (type >= 11 && type <= 19) { // TCP-based protocols
        print_ether_header(p.p_ether);
        print_ip(p.p_ip);
        print_tcp(p.p_tcp);

        // Handle specific TCP-based protocols
        switch (type) {
        case 11: // HTTP
            printf("============HTTP Data=================================================================================================================\n");
            if (p.app) printf("%s\n", p.app);
            printf("======================================================================================================================================\n");
            break;
        case 12: // FTP
            printf("============FTP Data===================================================================================================================\n");
            if (p.app) printf("%s\n", p.app);
            printf("=======================================================================================================================================\n");
            break;
        case 13: // TELNET
            printf("============TELNET Data================================================================================================================\n");
            if (p.app) printf("%s\n", p.app);
            printf("========================================================================================================================================\n");
            break;
        case 14: // SSH
            printf("============SSH Data====================================================================================================================\n");
            if (p.app) printf("%s\n", p.app);
            printf("========================================================================================================================================\n");
            break;
        case 15: // SMTP
            printf("============SMTP Data===================================================================================================================\n");
            if (p.app) printf("%s\n", p.app);
            printf("========================================================================================================================================\n");
            break;
        case 16: // POP3
            printf("============POP3 Data===================================================================================================================\n");
            if (p.app) printf("%s\n", p.app);
            printf("========================================================================================================================================\n");
            break;
        case 17: // IMAP
            printf("============IMAP Data===================================================================================================================\n");
            if (p.app) printf("%s\n", p.app);
            printf("========================================================================================================================================\n");
            break;
        case 18: // P2P
            printf("============P2P Data====================================================================================================================\n");
            if (p.app) printf("%s\n", p.app);
            printf("========================================================================================================================================\n");
            break;
        case 19: // Additional TCP-based protocol (if any)
            printf("============TCP Data=====================================================================================================================\n");
            if (p.app) printf("%s\n", p.app);
            printf("=========================================================================================================================================\n");
            break;
        default:
            printf("Unknown TCP protocol type.\n");
            break;
        }
    }
    else if (type >= 21 && type <= 23) { // UDP-based protocols
        print_ether_header(p.p_ether);
        print_ip(p.p_ip);
        print_udp(p.p_udp);

        // Handle specific UDP-based protocols
        switch (type) {
        case 21: // DNS
            printf("============DNS Data=====================================================================================================================\n");
            if (p.app) printf("%s\n", p.app);
            printf("=========================================================================================================================================\n");
            break;
        case 22: // DHCP
            printf("============DHCP Data====================================================================================================================\n");
            if (p.app) printf("%s\n", p.app); // DHCP options would require further parsing
            printf("=========================================================================================================================================\n");
            break;
        case 23: // Additional UDP-based protocol (if any)
            printf("============UDP Data=====================================================================================================================\n");
            if (p.app) printf("%s\n", p.app);
            printf("=========================================================================================================================================\n");
            break;
        default:
            printf("Unknown UDP protocol type.\n");
            break;
        }
    }
    else {
        printf("Unsupported protocol type: %d\n", type);
    }
}



class linked_list {
private:
    struct node* head;
    struct node* tail;
public:
    linked_list() {
        head = new node;
        tail = head;
    }

    void insert(node* obj, struct tm* ltime) {
        if (head == tail) {
            tail = obj;
            obj->prev = head;
            head->next = obj;
        }
        else {
            tail->next = obj;
            obj->prev = tail;
            tail = obj;
        }
        char timestr[16];
        strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
        printf("=============================================================================================================================================\n");
        printf("NO.     Time        source          destination              protocol          length           \n");
        printf("%d      %s    %s    %s            %d             %d\n", obj->info.no, timestr, inet_ntoa(obj->info.p_ip->ip_srcaddr), inet_ntoa(obj->info.p_ip->ip_destaddr), (unsigned int)obj->info.p_ip->ip_protocol, (unsigned int)obj->info.p_ip->ip_total_length);
        printf("=============================================================================================================================================\n");

    }
    void remove_all() { //모든 노드 삭제
        while (head != tail) {
            struct node* tmp = tail;
            tail = tail->prev;
            delete tmp;
        }
    }
    void print_all(int type) { //모든 노드 출력
        struct node* iter = head;
        while (head != tail) {
            if (iter->type == type) {
                print_packet(iter->info, iter->type);
            }
            iter = iter->next;
        }
    }
    node* find(int no) { //no를 이용해서 찾고자 하는 패킷 노드 탐색
        struct node* iter = head;
        while (head != tail) {
            if (iter->info.no == no) {
                print_packet(iter->info, iter->type);
                return iter;
            }
            iter = iter->next;
        }
    }
};

void stop_capture(linked_list& link) { //패킷 캡쳐 중단 시 호출 함수수
    char ichar;
    printf("=============================================================================================================================================\n");
    printf("if you want to go back to menu, press 'q', if you want to see detail of packet, press 's' and enter number of packet\n");
    printf("=============================================================================================================================================\n");
    while (1) {
        scanf("%c", &ichar);
        if (ichar == 'q' || ichar == 'Q') { // 찾고자 하는 패킷의 넘버가 q와 동일하면, 의도치 않게 종료돼서 char형으로 변경
            link.remove_all();
            return;
        }
        else if (ichar == 's' || ichar == 'S') {
            int number; //ichar로 number를 입력받는 것은 불가능하기 때문에 int형으로 따로 받아야 함
            printf("number of packet : ");
            scanf("%d", &number);
            link.find(number);
        }
    }
}

void print_menu(const char* packet_filter, int* inum1, int* inum2) { //메뉴 출력 함수
    //전송 계층 옵션 선택
    printf("=============================================================================================================================================\n");
    printf("choose the packet you want to catch.\n");
    printf("=============================================================================================================================================\n");
    printf("1:TCP(HTTP, FTP, TELNET, SSH, SMTP, POP3, IMAP, P2P)\n");
    printf("2:UDP(DNS, DHCP)\n");
    printf("=============================================================================================================================================\n");
    printf("Enter the number (1-2) : ");
    scanf_s("%d", inum1);
    //들어온 입력값에 따라 packet_filter값을 정의 && 응용 계층 정보 inum2에 저장
    if (*inum1 == 1) {
        packet_filter = "tcp";
        printf("=============================================================================================================================================\n");
        printf("choose the one packet you want to catch.\n");
        printf("=============================================================================================================================================\n");
        printf("1:HTTP\n");
        printf("2:FTP\n");
        printf("3:TELNET\n");
        printf("4:SSH\n");
        printf("5:SMTP\n");
        printf("6:POP3\n");
        printf("7:IMAP\n");
        printf("8:P2P\n");
        printf("9:ALL(TCP)\n");
        printf("=============================================================================================================================================\n");
        printf("Enter the number : ");
        scanf_s("%d", inum2);
    }
    else if (*inum1 == 2) {
        packet_filter = "udp";
        printf("=============================================================================================================================================\n");
        printf("choose the one packet you want to catch.\n");
        printf("=============================================================================================================================================\n");
        printf("1:DNS\n");
        printf("2:DHCP\n");
        printf("3:ALL(UDP)\n");
        printf("=============================================================================================================================================\n");
        printf("Enter the number : ");
        scanf_s("%d", inum2);
    }
    else if (*inum1 == 3) {
        packet_filter = "arp";
        *inum2 = 0;
    }
    else if (*inum1 == 4) //모든 프로토콜 캡쳐
        *inum2 = 0;
}

int main() {
    linked_list link = linked_list(); //링크 생성
    pcap_if_t* alldevs = NULL; // 네트워크 어댑터의 디바이스 정보 저장할 포인터
    char errbuf[PCAP_ERRBUF_SIZE]; //에러값 저장

    // 네트워크 어댑터 찾기
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("dev find failed\n");
        return -1;
    }
    if (alldevs == NULL) {
        printf("no devs found\n");
        return -1;
    }
    // 네트워크 어댑터 리스트 출력
    printf("Select a network adapter to capture packets.\n");
    pcap_if_t* d; int i;
    for (d = alldevs, i = 0; d != NULL; d = d->next) {
        printf("%d-th dev: %s ", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    int inum, inum1, inum2;
    const char* packet_filter = "";

    printf("enter the interface number : ");
    scanf("%d", &inum);
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++); // jump to the i-th dev
    while (1) {

        print_menu(packet_filter, &inum1, &inum2);
        // open
        pcap_t* fp;
        if ((fp = pcap_open_live(d->name,      // name of the device
            65536,                   // capture size
            1,  // promiscuous mode
            20,                    // read timeout
            errbuf
        )) == NULL) {
            printf("pcap open failed\n");
            pcap_freealldevs(alldevs);
            return -1;
        }

        printf("pcap open successful\n");

        struct bpf_program  fcode;
        if (pcap_compile(fp,  // pcap handle
            &fcode,  // compiled rule
            packet_filter,  // filter rule
            1,            // optimize
            NULL) < 0) {
            printf("pcap compile failed\n");
            pcap_freealldevs(alldevs);
            return -1;
        }
        if (pcap_setfilter(fp, &fcode) < 0) {
            printf("pcap compile failed\n");
            pcap_freealldevs(alldevs);
            return -1;
        }

        struct pcap_pkthdr* header;

        const unsigned char* pkt_data;
        const unsigned char* ether_data;
        int res;
        int cnt = 1;
        while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
            if (res == 0) continue;
            if (_kbhit()) {
                int ichar = _getch();
                if (ichar == 'p' || ichar == 'P') {
                    break;
                }
            }
            struct tm ltime;

            time_t local_tv_sec;
            local_tv_sec = header->ts.tv_sec;
            localtime_s(&ltime, &local_tv_sec);

            struct node* new_node = new node;

            new_node->info.p_header = new pcap_pkthdr;
            *new_node->info.p_header = *header;
            ether_data = pkt_data;
            if (pkt_data[13] == 0x00) {
                new_node->info.p_ether = new ether_header;
                *(new_node->info.p_ether) = *(struct ether_header*)pkt_data;
                pkt_data = pkt_data + SIZE_ETHERNET;
                new_node->info.p_ip = new ip_header;
                *(new_node->info.p_ip) = *(struct ip_header*)pkt_data;
                int ipLen = (new_node->info.p_ip->ip_header_len * 4); //워드(4바이트) 크기로 header_len을 표현하므로 바이트 단위로 변환하기 위해 *4
                pkt_data = pkt_data + ipLen;
                int tcplen;
                int udplen;
                switch (new_node->info.p_ip->ip_protocol) {
                case TCP: {
                    new_node->info.p_tcp = new tcp_header;
                    *(new_node->info.p_tcp) = *(struct tcp_header*)pkt_data;
                    tcplen = (new_node->info.p_tcp->data_offset * 4); // The header length is given in 32-bit words
                    pkt_data = pkt_data + tcplen;

                    // Check the destination port for further protocol identification
                    int dest_port = ntohs(new_node->info.p_tcp->dest_port);
                    if (dest_port == HTTP) {
                        new_node->type = 11;
                        new_node->info.app = (char*)pkt_data;
                    }
                    else if (dest_port == FTP_DATA || dest_port == FTP_CONTROLL) {
                        new_node->type = 12;
                        new_node->info.app = (char*)pkt_data;
                    }
                    else if (dest_port == TELNET) {
                        new_node->type = 13;
                        new_node->info.app = (char*)pkt_data;
                    }
                    else if (dest_port == SSH) {
                        new_node->type = 14;
                        new_node->info.app = (char*)pkt_data;
                    }
                    else if (dest_port == SMTP) {
                        new_node->type = 15;
                        new_node->info.app = (char*)pkt_data;
                    }
                    else if (dest_port == POP3) {
                        new_node->type = 16;
                        new_node->info.app = (char*)pkt_data;
                    }
                    else if (dest_port == IMAP) {
                        new_node->type = 17;
                        new_node->info.app = (char*)pkt_data;
                    }
                    else {
                        new_node->type = 18;
                        new_node->info.app = (char*)pkt_data;
                    }
                    break;
                }
                case UDP: {
                    new_node->info.p_udp = new udp_header;
                    *(new_node->info.p_udp) = *(struct udp_header*)pkt_data;
                    udplen = ntohs(new_node->info.p_udp->udpLength);

                    // Check the destination port for further protocol identification
                    int dest_port = ntohs(new_node->info.p_udp->destPort);
                    if (dest_port == DNS) {
                        new_node->type = 21;
                        new_node->info.app = (char*)pkt_data;
                    }
                    else if (dest_port == DHCP_SERVER || dest_port == DHCP_CLIENT) {
                        new_node->type = 22;
                        new_node->info.p_dhcp = (struct dhcp_packet*)pkt_data;
                    }
                    else {
                        new_node->type = 23;
                        new_node->info.app = (char*)pkt_data;
                    }
                    break;
                }
                case 0x0806: { // ARP protocol
                    new_node->info.p_arp = new arp_header;
                    *(new_node->info.p_arp) = *(struct arp_header*)pkt_data;
                    new_node->type = 31;
                    break;
                }
                default:
                    new_node->type = 41; // Unknown type
                    break;
                }
                if (inum1 * 10 + inum2 == new_node->type) {
                    new_node->info.no = cnt++;
                    link.insert(new_node, &ltime);
                }
            }
        }
        stop_capture(link);
        pcap_close(fp);
    }
    pcap_freealldevs(alldevs); // stop_capture 이후 while문을 다시 시작하면, 디바이스 정보가 필요하기에 모든 프로그램 종료 후 dev목록 free하기
    return 0;
}
