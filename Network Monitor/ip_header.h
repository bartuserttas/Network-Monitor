#include <pcap.h>
#include "ip_address.h"

#ifndef IPHEADER_H
#define IPHEADER_H

struct IpHeader{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    struct IpAddress saddr;      // Source address
    struct IpAddress daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
};

#endif