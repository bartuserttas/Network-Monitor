#include <pcap.h>

#ifndef IPADDRESS_H
#define IPADDRESS_H

struct IpAddress{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

#endif