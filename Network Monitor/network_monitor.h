#include "network_sniffer.h"
#include "packet_info_writer.h"
#include "packet_info_console_writer.h"

using namespace std;

#ifndef NETWORKMONITOR_H
#define NETWORKMONITOR_H

class NetworkMonitor {
    private:
        NetworkSniffer* _networkSniffer;
    public:
        NetworkMonitor(char* filter);
        void ProcessPacketData();
};

#endif