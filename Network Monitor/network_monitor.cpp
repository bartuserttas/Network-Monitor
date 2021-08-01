#include "network_monitor.h"

using namespace std;

NetworkMonitor::NetworkMonitor(char* filter){
    this->_networkSniffer = new NetworkSniffer(filter, new PacketInfoConsoleWriter());
}

void NetworkMonitor::ProcessPacketData(){
    _networkSniffer->Connect();
    _networkSniffer->CapturePacket();
    _networkSniffer->ProcessPacketData();
}