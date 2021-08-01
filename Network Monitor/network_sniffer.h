#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <pcap.h> 
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <ctime>

#include "network_sniffer_interface.h"
#include "packet_info_writer.h"

using namespace std;

#ifndef NETWORKSNIFFER_H
#define NETWORKSNIFFER_H

class NetworkSniffer : public INetworkSniffer {
    private:
        char *dev; 
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* descr;
        const u_char *packet;
        struct pcap_pkthdr hdr;  
        struct ether_header *eptr;  
        int result_of_capture_attempt;
        u_char *ptr; 

        IPacketInfoWriter* _packetInfoWriter;

    public:
        NetworkSniffer(char* filter, IPacketInfoWriter* packetInfoWriter);
        void Connect();        
        void CapturePacket();
        struct PacketInfo ReturnPacketInfo();
        void ProcessPacketData();
};

#endif