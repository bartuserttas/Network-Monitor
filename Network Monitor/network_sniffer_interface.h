#include <string>
#include "packet_info.h"

using namespace std;

class INetworkSniffer {
    public:
        virtual void Connect() = 0;
        virtual void CapturePacket() = 0;
        virtual struct PacketInfo ReturnPacketInfo() = 0;
        virtual void ProcessPacketData() = 0;
};