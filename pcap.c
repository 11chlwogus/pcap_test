#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include "pcap.h"

//ethernet header 구조체
struct libnet_ethernet_hdr {
    u_char ether_dhost[6];  
    u_char ether_shost[6];  
    u_short ether_type;       
};

//ip header 구조체
struct libnet_ipv4_hdr {
    u_char ihl:4, version:4;        
            //여기서 ihl을 먼저 써준 이유는 리틀 인디언이기 때문에 ihl을 먼저 읽기 때문이다.
            //:4는 정확히 4비트만 읽으라는 뜻이다.
    u_char  tos;              
    u_short total_len;        
    u_short identification;   
    u_short flags;            
    u_char ttl;              
    u_char protocol;         
    u_short checksum;         
    struct in_addr src;       
    struct in_addr dst;    
    //여기서 struct in_addr은 ip주소를 저장하기 위한 전용 바구니이다.   
};

//tcp header 구조체
struct libnet_tcp_hdr {
    u_short sport;            
    u_short dport;            
    u_int seq;              
    u_int ack;              
    u_short off:4, res:3,flags:9;      
    // 여기서 실수로 char를 썼다가 8비트를 초과했기에 오류가 발생했었다.    
    u_short win;              
    u_short sum;              
    u_short urp;              
};

void usage(){
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct{
    char* dev_;
}Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]){
    if(argc != 2){
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]){
    if (!parse(&param, argc, argv)){
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL){
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // Ethernet 헤더 따로 빼놓기
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        
        // ip4파일인지 확인
        if (ntohs(eth_hdr->ether_type) != 0x0800) {
            continue;
        }
        
        // IP 헤더 따로 빼놓기
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        //packet 즉, 시작 주소에서 ethernet header의 크기만큼을 뛰어넘은 부분부터 복사해준다.

        // TCP 즉, protocol이 6인지 확인하고 아니면 continue 하기
        if (ip_hdr->protocol != 6) {
            continue;
        }
        
        int ip_header_len = ip_hdr->ihl * 4;
        //우선 ip header의 길이를 구해준다. ihl에 곱하기 4를 해주면 나온다.
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + ip_header_len);
        //이후 tcp header를 추출해준다. ethernet 과 ip header 부분을 뛰어넘은 다음 부터 추출해주면 된다.

        // TCP 데이터 오프셋 계산
        int tcp_header_len = tcp_hdr->off * 4;
        //tcp header의 길이를 구해서 data가 어디서부터 시작하는지 알아준다.
        int total_header_len = sizeof(struct libnet_ethernet_hdr) + ip_header_len + tcp_header_len;
        //이후 전체 헤더의 길이를 찾아준다.
        int data_len = header->len - total_header_len;
        //패킷 전체의 길이에서 헤더의 길이를 빼주면 데이터의 길이가 나온다.
        
        // src mac과 dst mac 출력
        printf("ETHERNET HEADER -> SRC: %02x:%02x:%02x:%02x:%02x:%02x, DST: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
               eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5],
               eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
               eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
        
        // src ip와 dst ip를 출력해준다.
        printf("IP HEADER -> SRC: %d.%d.%d.%d, DST: %d.%d.%d.%d\n\n", ((unsigned char *)&ip_hdr->src)[0], ((unsigned char *)&ip_hdr->src)[1], ((unsigned char *)&ip_hdr->src)[2], ((unsigned char *)&ip_hdr->src)[3], ((unsigned char *)&ip_hdr->dst)[0],((unsigned char *)&ip_hdr->dst)[1],((unsigned char *)&ip_hdr->dst)[2],((unsigned char *)&ip_hdr->dst)[3]);

        // src port와 dst port를 출력해준다. 참고로 이때 리틀 엔디안으로 저장됐기에 ntohs를 해준다.
        u_char *s = (u_char *)&ip_hdr->src;
        printf("TCP HEADER -> SRC PORT: %d, DST PORT: %d\n\n", ntohs(tcp_hdr->sport), ntohs(tcp_hdr->dport));
        
        // data의 크기를 출력해준다.
        printf("DATA SIZE: %d\n\n", data_len);
        
        // TCP 헤더 이후 데이터 20바이트 출력
        const u_char* tcp_data = packet + total_header_len;
        // 시작 지점부터 header만큼의 영역을 뛰어넘은 곳의 주소를 tcp_data는 저장한다.
        int print_len = (data_len < 20) ? data_len : 20;
        
        printf("TCP DATA (first %d bytes): ", print_len);
        for (int i = 0; i < print_len; i++) {
            printf("%02x ", tcp_data[i]);
        }
        printf("\n\n");
        printf("_________________________");
        printf("\n");
        
    }
    
    pcap_close(pcap);

    

    return 0;
}
