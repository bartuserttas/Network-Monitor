#include <pcap.h>

#ifndef UDPHEADER_H
#define UDPHEADER_H

struct UdpHeader{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
};

#endif