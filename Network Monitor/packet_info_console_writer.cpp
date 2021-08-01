#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/tcp.h> 
#include <netinet/ether.h>
#include "packet_info_console_writer.h"

using namespace std;

string convertHexToBinary(char hex){
    switch(hex){
        case '0':
            return "0000";
            break;
        case '1':
            return "0001";
            break;
        case '2':
            return "0010";
            break;
        case '3':
            return "0011";
            break;
        case '4':
            return "0100";
            break;
        case '5':
            return "0101";
            break;
        case '6':
            return "0110";
            break;
        case '7':
            return "0111";
            break;
        case '8':
            return "1000";
            break;
        case '9':
            return "1001";
            break;
        case 'a':
            return "1010";
            break;
        case 'b':
            return "1011";
            break;
        case 'c':
            return "1100";
            break;
        case 'd':
            return "1101";
            break;
        case 'e':
            return "1110";
            break;
        case 'f':
            return "1111";
            break;
        default:
            return "";
    }
}

PacketInfoConsoleWriter::PacketInfoConsoleWriter(){
}

void PacketInfoConsoleWriter::WritePacketInfo(struct PacketInfo& recieved_packet_info){
    struct tcphdr* tcphdr = (struct tcphdr *)(recieved_packet_info.packet_pointer+14+20);

    /* retireve the position of the ip header */
    struct IpHeader* ip_header = (struct IpHeader *) (recieved_packet_info.packet_pointer + 14); 

    /* retireve the position of the udp header */
    u_int ip_len = (ip_header->ver_ihl & 0xf) * 4;
    struct UdpHeader* udp_header = (struct UdpHeader *) ((u_char*)ip_header + ip_len);

    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    recieved_packet_info.ethernet_header_pointer = (ether_header* ) recieved_packet_info.packet_pointer;

    /* convert the timestamp to readable format */
    local_tv_sec = recieved_packet_info.packet_header_pointer.ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* print timestamp and length of the packet */
    printf("%s.%.6d, ", timestr, recieved_packet_info.packet_header_pointer.ts.tv_usec);

    char smac[12];
    sprintf(smac, "%02x%02x%02x%02x%02x%02x", 
    (unsigned)recieved_packet_info.ethernet_header_pointer->ether_shost[0],
    (unsigned)recieved_packet_info.ethernet_header_pointer->ether_shost[1],
    (unsigned)recieved_packet_info.ethernet_header_pointer->ether_shost[2],
    (unsigned)recieved_packet_info.ethernet_header_pointer->ether_shost[3],
    (unsigned)recieved_packet_info.ethernet_header_pointer->ether_shost[4],
    (unsigned)recieved_packet_info.ethernet_header_pointer->ether_shost[5]);
    
    for(int i = 0; i < 12; i++){
        if(i == 6){
            printf(":");
        }
        printf("%s", convertHexToBinary(smac[i]).c_str());
    }
    printf(", ");

    char dmac[12];
    sprintf(dmac, "%02x%02x%02x%02x%02x%02x", 
    (unsigned)recieved_packet_info.ethernet_header_pointer->ether_dhost[0],
    (unsigned)recieved_packet_info.ethernet_header_pointer->ether_dhost[1],
    (unsigned)recieved_packet_info.ethernet_header_pointer->ether_dhost[2],
    (unsigned)recieved_packet_info.ethernet_header_pointer->ether_dhost[3],
    (unsigned)recieved_packet_info.ethernet_header_pointer->ether_dhost[4],
    (unsigned)recieved_packet_info.ethernet_header_pointer->ether_dhost[5]);

    for(int i = 0; i < 12; i++){
        if(i == 6){
            printf(":");
        }
        printf("%s", convertHexToBinary(dmac[i]).c_str());
    }
    printf(", ");

    char ips[16];

    sprintf(ips, "%02x%02x%02x%02x%02x%02x%02x%02x", 
        ip_header->saddr.byte1,
        ip_header->saddr.byte2,
        ip_header->saddr.byte3,
        ip_header->saddr.byte4,
        ip_header->daddr.byte1,
        ip_header->daddr.byte2,
        ip_header->daddr.byte3,
        ip_header->daddr.byte4
    );

    printf("%s%s.%s%s.%s%s.%s%s, %s%s.%s%s.%s%s.%s%s, ",
        convertHexToBinary(ips[0]).c_str(),
        convertHexToBinary(ips[1]).c_str(),
        convertHexToBinary(ips[2]).c_str(),
        convertHexToBinary(ips[3]).c_str(),
        convertHexToBinary(ips[4]).c_str(),
        convertHexToBinary(ips[5]).c_str(),
        convertHexToBinary(ips[6]).c_str(),
        convertHexToBinary(ips[7]).c_str(),
        convertHexToBinary(ips[8]).c_str(),
        convertHexToBinary(ips[9]).c_str(),
        convertHexToBinary(ips[10]).c_str(),
        convertHexToBinary(ips[11]).c_str(),
        convertHexToBinary(ips[12]).c_str(),
        convertHexToBinary(ips[13]).c_str(),
        convertHexToBinary(ips[14]).c_str(),
        convertHexToBinary(ips[15]).c_str()
        );
    
    printf("%u, %u, ", tcphdr->th_sport, tcphdr->th_dport);
    
    printf("%s%s%s%s%s%s, ", 
        tcphdr->th_flags & TH_FIN ? "1" : "0", 
        tcphdr->th_flags & TH_SYN ? "1" : "0", 
        tcphdr->th_flags & TH_RST ? "1" : "0", 
        tcphdr->th_flags & TH_PUSH ? "1" : "0", 
        tcphdr->th_flags & TH_ACK ? "1" : "0", 
        tcphdr->th_flags & TH_URG ? "1" : "0");

    printf("%u, ", ntohl(tcphdr->th_seq) );
    printf("%u, ", ntohl(tcphdr->th_ack) );
    printf("%u, ", ntohl(tcphdr->th_win) );

    printf("%d\n", recieved_packet_info.packet_header_pointer.len);
}