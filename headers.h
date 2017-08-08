#ifndef PACKET_SNIFFER_C_HEADERS_H
#define PACKET_SNIFFER_C_HEADERS_H

#endif //PACKET_SNIFFER_C_HEADERS_H

#define ethernet_Address_Length     6
#define ethernet_Frame_Length       14

//Ethernet header
struct ethernet_frame {
  u_char src_mac_addr[ethernet_Address_Length];
  u_char dest_mac_addr[ethernet_Address_Length];
  u_short proto_type;
  u_char data;
};

//IPv4 header
struct ipv4_packet {
  u_char  version : 4;
  u_char  version_header_length : 4;
  u_char  type_of_service : 8;
  u_short length;
  u_short id;
  u_short frag_offset;
  u_char  ttl;
  u_char  protocol;
  u_short checksum;
  u_int   src_addr;
  u_int   dest_addr;
};

//IPv6 header
struct ipv6_packet {
  u_char  version;
  u_int   traffic_class;
  u_int   flow_label;
  u_int   payload_length;
  u_char  next_header;
  u_char  hop_limit;
  struct  in6_addr src_addr;
  struct  in6_addr dest_addr;
};

//icmp header
struct icmp_packet {
  u_char  type;
  u_char  code;
  u_char  checksum;
};

//tcp header
struct tcp_segment {
  u_short src_port;
  u_short dest_port;
  u_long  sequence;
  u_long  acknowledgement;
  u_char  reserved; 
  u_char  offset;
  u_char  flags;
    
#define fin 0x01
#define syn 0x02
#define rst 0x04
#define psh 0x08
#define ack 0x10
#define urg 0x20
    
  u_short window;
  u_short checksum;
  u_short urgent_pointer;
};

//udp header
struct udp_segment {
  u_short src_port;
  u_short dest_port;
  u_short length;
  u_short checksum;
};
