/*
 * sniffer.c
 *
 * By David C Harrison (david.harrison@ecs.vuw.ac.nz) July 2015
 *
 * Use as-is, modification, and/or inclusion in derivative works is permitted only if 
 * the original author is credited. 
 *
 * To compile: gcc -o sniffer sniffer.c -l pcap 
 *
 * To run: tcpdump -s0 -w - | ./sniffer -
 *     Or: ./sniffer <some file captured from tcpdump or wireshark>
 */

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "headers.h"
#include "sniffer.h"


void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  printf ("\nPacket #: %d\n",packet_number++);
  sort_ethernet_frame (packet);
}


void
sort_ethernet_frame (const char *packet) {

  const struct ethernet_frame *ethernet_header = (struct ethernet_frame *) (packet);
  int ip_proto;

  if (ethernet_header->proto_type == 8){
    printf ("Ether Type: IPv4\n");
    unpack_ipv4_packet (packet + ethernet_Frame_Length);
  }
  
  if (ethernet_header->proto_type == 56710){
    printf ("Ether Type: IPv6\n");
    unpack_ipv6_packet (packet + ethernet_Frame_Length);
  }

  else
    printf ("Unknown Protocol\n");
  
}

void
unpack_ipv4_packet (const char *data){

  const struct ipv4_packet *get_ipv4_packet = (struct ipv4_packet *) (data);
  printf ("Source Address: %s\n",get_ipv4_addr (get_ipv4_packet->src_addr));
  printf ("Destination Address: %s\n",get_ipv4_addr (get_ipv4_packet->dest_addr));
  
  switch (get_ipv4_packet->protocol){
      
      case 1:
          printf ("Protocol: ICMP\n");
          
          break;
      
      case 6:
          printf ("Protocol: TCP\n");
          
          break;
          
      case 17:
          printf ("Protocol: UDP\n");
          
          break;
      
  }
  
}

void
unpack_ipv6_packet (const char *data){
    
    const struct ipv6_packet *get_ipv6_packet = (struct ipv6_packet *) (data);
    printf ("Source Address: %s\n",get_ipv6_addr (get_ipv6_packet->src_addr));
    
}

//Converts ipv6 byte address to ip address
const char *
get_ipv6_addr (const struct in6_addr byte_address) {
    
    char address[INET6_ADDRSTRLEN]; //inet_addrstrlen is a predefined length of 46
    
    inet_ntop(AF_INET6, &byte_address, address, INET6_ADDRSTRLEN);

    addr_toupper(address);
    return address[INET6_ADDRSTRLEN];
    
}
//Converts ipv4 byte address to ip address
const char *
get_ipv4_addr (int byte_address) {
    
    struct in_addr ip_addr;
    ip_addr.s_addr = byte_address;
    
    return inet_ntoa(ip_addr);
}

//Converts address to uppercase
const char *
addr_toupper (const char *address) {
    
    int i = 0;
    while (address[i]){
        putchar (toupper(address[i]));
        i++;
    }
    return address;
}

int
main(int argc, char **argv)
{
  
    if (argc < 2) {
        fprintf(stderr, "Must have an argument, either a file name or '-'\n");
        return -1;
    }

    pcap_t *handle = pcap_open_offline(argv[1], NULL);
    pcap_loop(handle, 1024*1024, got_packet, NULL);
    pcap_close(handle);
    
    // Error reporting                                                                                                                                                 
    char errbuf[PCAP_ERRBUF_SIZE];

    if (handle == NULL) {
      printf ("Couldn't open pcap file %s: %s\n", argv[1], errbuf);
    }

    return 0;
    
}
