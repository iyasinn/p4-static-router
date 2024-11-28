#include "protocol.h"
#include "spdlog/spdlog.h"
#include "utils.h"
// #include <_types/_uint8_t.h>
#include <cstdint>
#include <iostream>
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

class ARP_Packet_Header {
public:
  ARP_Packet_Header() {}
  ARP_Packet_Header(sr_arp_hdr_t *const raw_network_data)
      : _arp_packet(raw_network_data) {}

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

  // void print_header() {
  //   spdlog::info("ARP header");
  //   spdlog::info("\thardware type: {}", _arp_packet->ar_hrd);
  //   spdlog::info("\tprotocol type: {}", _arp_packet->ar_pro);
  //   spdlog::info("\thardware address length: {}", _arp_packet->ar_hln);
  //   spdlog::info("\tprotocol address length: {}", _arp_packet->ar_pln);
  //   spdlog::info("\topcode: {}", _arp_packet->ar_op);
  //   spdlog::info("\tsender hardware address: ");
  //   print_addr_eth(_arp_packet->ar_sha);
  //   spdlog::info("\tsender ip address: ");
  //   print_addr_ip_int(_arp_packet->ar_sip);
  //   spdlog::info("\ttarget hardware address: ");
  //   print_addr_eth(_arp_packet->ar_tha);
  //   spdlog::info("\ttarget ip address: ");
  //   print_addr_ip_int(_arp_packet->ar_tip);
  // }

  const sr_arp_hdr_t &packet() { return *_arp_packet; }

  sr_arp_hdr_t *_arp_packet = nullptr;

private:
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
  //   spdlog::info("\tchecksum: {}", static_cast<uint32_t>(_ip_packet->ip_sum));
  //   spdlog::info("\tsource: ");
  //   print_addr_ip_int((_ip_packet->ip_src));
  //   spdlog::info("\tdestination: ");
  //   print_addr_ip_int((_ip_packet->ip_dst));
  // }

  const sr_ip_hdr_t &packet() const { return *_ip_packet; }

private:
  sr_ip_hdr_t *_ip_packet = nullptr;
};

class ETH_Packet {
public:
  ETH_Packet(const std::vector<uint8_t> &raw_network_data)
      : _eth_packet(raw_network_data) {
    if (raw_network_data.size() < sizeof(sr_ethernet_hdr_t)) {
      std::cerr << "Error: <data> does not contain enough bytes for an "
                   "ethernet packet\n";
      exit(1);
    }
    _eth_header = (sr_ethernet_hdr_t *)_eth_packet.data();

    data_type = ntohs(_eth_header->ether_type);

    if (data_type == sr_ethertype::ethertype_arp) {
      sr_arp_hdr_t *arp_header =
          (sr_arp_hdr_t *)(_eth_packet.data() + sizeof(sr_ethernet_hdr_t));
      arp = ARP_Packet_Header(arp_header);
    } else if (data_type == sr_ethertype::ethertype_ip) {
      sr_ip_hdr_t *ip_header =
          (sr_ip_hdr_t *)(_eth_packet.data() + sizeof(sr_ethernet_hdr_t));
      ip = IP_Packet_Header(ip_header);
    }
  }

  void convert_to_host_order() {
    if (data_type == sr_ethertype::ethertype_arp) {
      arp.convert_to_host_order();
    } else if (data_type == sr_ethertype::ethertype_ip) {
      ip.convert_to_host_order();
    }
    _eth_header->ether_type = ntohs(_eth_header->ether_type);
  }

  void convert_to_network_order() {
    if (data_type == sr_ethertype::ethertype_arp) {
      arp.convert_to_network_order();
    } else if (data_type == sr_ethertype::ethertype_ip) {
      ip.convert_to_network_order();
    }
    _eth_header->ether_type = htons(_eth_header->ether_type);
  }

  uint16_t get_type() const { return data_type; }

  void print_header() {
    spdlog::info("ETHERNET header:");
    spdlog::info("\tdestination: ");
    print_addr_eth(_eth_header->ether_dhost);
    spdlog::info("\tsource: ");
    print_addr_eth(_eth_header->ether_shost);
    spdlog::info("\ttype: {}", data_type);
  }

  const std::vector<uint8_t> &raw_packet() const { return _eth_packet; }
  const sr_ethernet_hdr_t *header() const { return _eth_header; }
  IP_Packet_Header ip;
  ARP_Packet_Header arp;

private:
  std::vector<uint8_t> _eth_packet;
  sr_ethernet_hdr_t *_eth_header;
  uint16_t data_type = 0;
};