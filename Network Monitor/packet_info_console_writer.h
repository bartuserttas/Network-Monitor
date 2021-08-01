#include "packet_info_writer.h"
#include <netinet/tcp.h> 

using namespace std;

#ifndef PACKETINFOCONSOLEWRITER_H
#define PACKETINFOCONSOLEWRITER_H

class PacketInfoConsoleWriter : public IPacketInfoWriter {
    public:
        PacketInfoConsoleWriter();
        void WritePacketInfo(struct PacketInfo& recieved_packet_info);
};

#endif