#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

struct ether_header{
    u_int8_t dest[6];
    u_int8_t src[6];
    u_int8_t type[2];
    // 0806 == ARP
};

struct ip_header{
    u_int8_t sender[4];
    u_int8_t target[4];
};

ether_header getEther(const u_char *packet){
    ether_header ether;
    for(int i = 0; i < 6; i++) ether.dest[i] = packet[i];
    for(int i = 0; i < 6; i++) ether.src[i] = packet[i+6];
    ether.type[0] = packet[12];
    ether.type[1] = packet[13];

    return ether;
}

ip_header getIp(const u_char *packet){
    ip_header ip;
    for(int i = 0; i < 4; i++) {
        ip.sender[i] = packet[i+28];
        ip.target[i] = packet[i+38];
    }
    return ip;
}

void changeType2Int(char* ip, u_int8_t* intIP){
    int j = 0;
    intIP[0] = 0;
    for(int i = 0; i < 15; i++){
        if(ip[i] == '\0') break;
        if(ip[i] == '.') {
            j++;
            intIP[j] = 0;
            continue;
        }

       intIP[j] *= 10;
       intIP[j] += ip[i] - '0';
    }
}

char changeHex(int num){
    if(num < 10) return num + '0';
    else return num - 10 + 'a';
}

void changeHex2String(u_int8_t* intMAC, char* strMAC){
    for(int i = 3; i <= 15; i+=3) strMAC[i-1] = ':';
    for(int i = 0; i < 6; i++){
        strMAC[i*3] = changeHex(intMAC[i] / 16);
        strMAC[i*3+1] = changeHex(intMAC[i] % 16);
    }
}

void getMAC(char* interface, char* myMAC){
  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, interface);
  if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
      for(int i = 3; i <= 15; i+=3) myMAC[i-1] = ':';
      for(int i = 0; i < 6; i++){
          myMAC[i*3] = changeHex((unsigned char)s.ifr_addr.sa_data[i] / 16);
          myMAC[i*3+1] = changeHex((unsigned char)s.ifr_addr.sa_data[i] % 16);
      }
  }
}
