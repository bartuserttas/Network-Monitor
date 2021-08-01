#include <iostream>
#include <string>
#include "packet_info.h"
#include "ip_header.h"
#include "udp_header.h"

using namespace std;

#ifndef IPACKETINFOWRITER_H
#define IPACKETINFOWRITER_H

class IPacketInfoWriter {
    public:
        virtual void WritePacketInfo(struct PacketInfo& recieved_packet_info) = 0;
};

#endif