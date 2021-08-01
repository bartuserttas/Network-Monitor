#ifndef PACKETINFO_H
#define PACKETINFO_H

struct PacketInfo {
    const u_char* packet_pointer;
    struct pcap_pkthdr packet_header_pointer;
    struct ether_header* ethernet_header_pointer;
};

#endif