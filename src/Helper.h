#include "RouterTypes.h"
#include "protocol.h"
#include "spdlog/spdlog.h"
#include "utils.h"
// #include <_types/_uint8_t.h>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <vector>

// bool ip_checksum_valid(sr_ip_hdr_t *ip) {
//   int checksum = cksum(ip, sizeof(sr_ip_hdr_t));
// }

// class ETHR_Packet {

//   //   sr_ethertype;
// }

// class PacketHeader {
// public:
//   virtual ~PacketHeader() = default;
//   virtual void convert_to_host_order() = 0;
//   virtual void convert_to_network_order() = 0;
// };

class ArpPacketHeader {
public:
  ArpPacketHeader() {}
  ArpPacketHeader(Packet &raw_eth_packet) {
    _arp_packet =
        (sr_arp_hdr_t *)(raw_eth_packet.data() + sizeof(sr_ethernet_hdr_t));
  }

  void convert_to_host_order() {
    _arp_packet->ar_hrd = ntohs(_arp_packet->ar_hrd);
    _arp_packet->ar_pro = ntohs(_arp_packet->ar_pro);
    _arp_packet->ar_op = ntohs(_arp_packet->ar_op);
    _arp_packet->ar_sip = ntohl(_arp_packet->ar_sip);
    _arp_packet->ar_tip = ntohl(_arp_packet->ar_tip);
  }

  void convert_to_network_order() {
    _arp_packet->ar_hrd = htons(_arp_packet->ar_hrd);
    _arp_packet->ar_pro = htons(_arp_packet->ar_pro);
    _arp_packet->ar_op = htons(_arp_packet->ar_op);
    _arp_packet->ar_sip = htonl(_arp_packet->ar_sip);
    _arp_packet->ar_tip = htonl(_arp_packet->ar_tip);
  }

  ip_addr get_target_ip(){
    return ntohl(_arp_packet->ar_tip);
  }

  unsigned short get_type(){
    return ntohs(_arp_packet->ar_op);
  }

  void print_header(){
    std::cout << std::endl;
    print_hdr_arp((uint8_t *)&_arp_packet);
  }

  mac_addr get_sender_mac(){
    return make_mac_addr(_arp_packet->ar_sha);
  }

  mac_addr get_target_mac(){
    return make_mac_addr(_arp_packet->ar_tha);
  }


  // Converst the ARP packet to a reply packet
  // Assertion: We have a valid Request packet
  void convert_to_reply(uint32_t new_sender_ip, mac_addr new_sender_mac_addr){

    header().ar_op = htons(sr_arp_opcode::arp_op_reply);

    // Update Target to be our Sender
    header().ar_tip = header().ar_sip; 
    memcpy(header().ar_tha, header().ar_sha, ETHER_ADDR_LEN);

    // Update Sender 
    header().ar_sip = new_sender_ip;
    memcpy(header().ar_sha, new_sender_mac_addr.data(), ETHER_ADDR_LEN);

  }


  sr_arp_hdr_t &header() { return *_arp_packet; }

private:
  sr_arp_hdr_t *_arp_packet = nullptr;
};

class IP_Packet_Header {
public:
  IP_Packet_Header() {}

  IP_Packet_Header(sr_ip_hdr_t *const data) : _ip_packet(data) {}

  void convert_to_host_order() {
    _ip_packet->ip_len = ntohs(_ip_packet->ip_len); // Total length of IP packet
    _ip_packet->ip_id =
        ntohs(_ip_packet->ip_id); // Identification field for fragmentation
    _ip_packet->ip_off = ntohs(_ip_packet->ip_off); // Fragment offset field
    _ip_packet->ip_sum = ntohs(_ip_packet->ip_sum); // IP header checksum
    _ip_packet->ip_src = ntohl(_ip_packet->ip_src); // Source IP address
    _ip_packet->ip_dst = ntohl(_ip_packet->ip_dst); // Destination IP address
  }

  void convert_to_network_order() {
    _ip_packet->ip_len = htons(_ip_packet->ip_len); // Total length of IP packet
    _ip_packet->ip_id =
        htons(_ip_packet->ip_id); // Identification field for fragmentation
    _ip_packet->ip_off = htons(_ip_packet->ip_off); // Fragment offset field
    _ip_packet->ip_sum = htons(_ip_packet->ip_sum); // IP header checksum
    _ip_packet->ip_src = htonl(_ip_packet->ip_src); // Source IP address
    _ip_packet->ip_dst = htonl(_ip_packet->ip_dst); // Destination IP address
  }

  // void print_header() {
  //   // sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  //   spdlog::info("IP header:");
  //   spdlog::info("\tversion: {}", static_cast<int>(_ip_packet->ip_v));
  //   spdlog::info("\theader length: {}", static_cast<int>(_ip_packet->ip_hl));
  //   spdlog::info("\ttype of service: {}", _ip_packet->ip_tos);
  //   spdlog::info("\tlength: {}", (_ip_packet->ip_len));
  //   spdlog::info("\tid: {}", (_ip_packet->ip_id));

  //   if (ntohs(_ip_packet->ip_off) & IP_DF)
  //     spdlog::info("\tfragment flag: DF");
  //   else if ((_ip_packet->ip_off) & IP_MF)
  //     spdlog::info("\tfragment flag: MF");
  //   else if ((_ip_packet->ip_off) & IP_RF)
  //     spdlog::info("\tfragment flag: R");

  //   spdlog::info("\tfragment offset: {}", (_ip_packet->ip_off) & IP_OFFMASK);
  //   spdlog::info("\tTTL: {}", _ip_packet->ip_ttl);
  //   spdlog::info("\tprotocol: {}", _ip_packet->ip_p);
  //   spdlog::info("\tchecksum: {}",
  //   static_cast<uint32_t>(_ip_packet->ip_sum)); spdlog::info("\tsource: ");
  //   print_addr_ip_int((_ip_packet->ip_src));
  //   spdlog::info("\tdestination: ");
  //   print_addr_ip_int((_ip_packet->ip_dst));
  // }

  const sr_ip_hdr_t &packet() const { return *_ip_packet; }

private:
  sr_ip_hdr_t *_ip_packet = nullptr;
};

class EthPacketHeader {
public:
  EthPacketHeader(std::vector<uint8_t> &raw_network_data)
      : packet_ref(raw_network_data) {

    if (raw_network_data.size() < sizeof(sr_ethernet_hdr_t)) {
      std::cerr << "Error: <data> does not contain enough bytes for an "
                   "ethernet packet\n";
      exit(1);
    }

    _eth_header = (sr_ethernet_hdr_t *)raw_network_data.data();
    data_type = ntohs(_eth_header->ether_type);
  }

  uint16_t get_type() const { return data_type; }

  void print_header() {
    print_hdr_eth((uint8_t *)_eth_header);
    print_addr_eth((uint8_t *)_eth_header);
    std::cout << "Full packet size: " << packet_ref.size() << std::endl;
  }

  void update_header_data(mac_addr src, mac_addr dst, uint16_t type) {
    memcpy(_eth_header->ether_shost, src.data(), ETHER_ADDR_LEN);
    memcpy(_eth_header->ether_dhost, dst.data(), ETHER_ADDR_LEN);
    _eth_header->ether_type = htons(type);
  }

  const sr_ethernet_hdr_t *header() const { return _eth_header; }

private:
  Packet &packet_ref;
  sr_ethernet_hdr_t *_eth_header;
  uint16_t data_type = 0;
};