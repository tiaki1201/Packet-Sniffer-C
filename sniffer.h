#ifndef PACKET_SNIFFER_C_SNIFFER_H
#define PACKET_SNIFFER_C_SNIFFER_H

#endif //PACKET_SNIFFER_C_SNIFFER_H


int packet_number = 1;

/*
 *Recieves entire packer with header and payload
 
 */
void got_packet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/*
 * Find ethernet proto type
 */
void sort_ethernet_frame (const char *packet);

/*
 * Prints out raw Data
 */
void print_raw_data (const char *data);

/*
 * Format mac address
 */
void mac2str (const char *bytes);

/*
 * Unpack IPv4 packet
 */
void unpack_ipv4_packet (const char *data);

/*
 * Unpack IPv6 packet
 */
void unpack_ipv6_packet (const char *data);

/*
 * Unpack IPv6 packet
 */
void ipv6_packet (const char *data);

/*
 * Unpack icmp segment
 */
void icmp_packet (const char *data);

/*
 * Unpack tcp segment
 */
void tcp_segment (const char *data);

/*
 * Unpack udp segment 
 */
void udp_segment (const char *data);

/*
 * Finds and returns icmp type  
 */
void find_icmp_type (int type);

/*
 * Converts byte address to ip address  
 */
const char * get_ipv4_addr (int type);

/*
 * Converts byte address to ip address  
 */
const char * get_ipv6_addr (const struct in6_addr byte_address);

/*
 * Converts address to uppercase
 */
const char * addr_toupper (const char *address);
