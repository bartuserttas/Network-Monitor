#include "network_sniffer.h"

using namespace std;

NetworkSniffer::NetworkSniffer(char* filter, IPacketInfoWriter* packetInfoWriter){

    this->_packetInfoWriter = packetInfoWriter;
    this->dev = filter;
    if(this->dev == NULL)
    {
        printf("%s\n", this->errbuf);
        exit(1);
    }
}

void NetworkSniffer::Connect(){
    this->descr = pcap_open_live(this->dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, -1, this->errbuf);

    if(this->descr == NULL)
    {
        printf("pcap_open_live(): %s\n", this->errbuf);
        exit(1);
    }
}

void NetworkSniffer::CapturePacket(){
    do {
        this->packet = pcap_next(this->descr, &this->hdr);
    } while (this->packet == NULL);

    if(this->packet == NULL)
    {
        printf("Didn't grab packet\n");
        exit(1);
    }
}

struct PacketInfo NetworkSniffer::ReturnPacketInfo(){
    struct PacketInfo packet_information;
    packet_information.ethernet_header_pointer = this->eptr;
    packet_information.packet_header_pointer = this->hdr;
    packet_information.packet_pointer = this->packet;

    return packet_information;
}

void NetworkSniffer::ProcessPacketData(){
    struct PacketInfo packet_information = ReturnPacketInfo();
    _packetInfoWriter->WritePacketInfo(packet_information);
}