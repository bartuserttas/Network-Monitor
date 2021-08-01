#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include "network_monitor.h"

using namespace std;

int main(){
    char* filter = "enp0s3";
    NetworkMonitor sniffer(filter);
    while(true){
        sniffer.ProcessPacketData();
    }
}