#include "RouterTypes.h"
#include "protocol.h"
#include "spdlog/spdlog.h"
#include "utils.h"
// #include <_types/_uint8_t.h>
#include <_types/_uint16_t.h>
#include <_types/_uint8_t.h>
#include <array>
#include <cstdint>
#include <iostream>
#include <iterator>

class ArpPacketHeader {
public:
  ArpPacketHeader() {}
  ArpPacketHeader(Packet &raw_eth_packet) {
    _arp_packet =
        (sr_arp_hdr_t *)(raw_eth_packet.data() + sizeof(sr_ethernet_hdr_t));
  }

  ArpPacketHeader(sr_arp_hdr_t *arp_header_in) : _arp_packet(arp_header_in) {}

  // void convert_to_host_order() {
  //   _arp_packet->ar_hrd = ntohs(_arp_packet->ar_hrd);
  //   _arp_packet->ar_pro = ntohs(_arp_packet->ar_pro);
  //   _arp_packet->ar_op = ntohs(_arp_packet->ar_op);
  //   _arp_packet->ar_sip = ntohl(_arp_packet->ar_sip);
  //   _arp_packet->ar_tip = ntohl(_arp_packet->ar_tip);
  // }

  // void convert_to_network_order() {
  //   _arp_packet->ar_hrd = htons(_arp_packet->ar_hrd);
  //   _arp_packet->ar_pro = htons(_arp_packet->ar_pro);
  //   _arp_packet->ar_op = htons(_arp_packet->ar_op);
  //   _arp_packet->ar_sip = htonl(_arp_packet->ar_sip);
  //   _arp_packet->ar_tip = htonl(_arp_packet->ar_tip);
  // }

  unsigned short get_type() { return ntohs(_arp_packet->ar_op); }

  // Returns target ip in network order
  ip_addr get_target_ip() { return _arp_packet->ar_tip; }
  mac_addr get_target_mac() { return make_mac_addr(_arp_packet->ar_tha); }

  // Returns sender ip in network order
  ip_addr get_sender_ip() { return _arp_packet->ar_sip; }
  mac_addr get_sender_mac() { return make_mac_addr(_arp_packet->ar_sha); }

  void update_src_mac(const mac_addr &mac) {
    memcpy(_arp_packet->ar_sha, mac.data(), ETHER_ADDR_LEN);
  }

  void update_dst_mac(const mac_addr &mac) {
    memcpy(_arp_packet->ar_tha, mac.data(), ETHER_ADDR_LEN);
  }

  void print_header() {
    std::cout << std::endl;
    print_hdr_arp((uint8_t *)&_arp_packet);
  }

  // Converst the ARP packet to a reply packet
  // Assertion: We have a valid Request packet
  void convert_to_reply(uint32_t new_sender_ip, mac_addr new_sender_mac_addr) {

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

class EthPacketHeader {
public:
  EthPacketHeader(const std::vector<uint8_t> &raw_network_data) {

    if (raw_network_data.size() < sizeof(sr_ethernet_hdr_t)) {
      std::cerr << "Error: <data> does not contain enough bytes for an "
                   "ethernet packet\n";
      exit(1);
    }

    _eth_header = (sr_ethernet_hdr_t *)raw_network_data.data();
    data_type = ntohs(_eth_header->ether_type);
  }

  EthPacketHeader(sr_ethernet_hdr_t *eth_in) : _eth_header(eth_in) {}

  uint16_t get_type() const { return data_type; }

  void update_type(sr_ethertype host_order_type) {
    _eth_header->ether_type = htons(host_order_type);
  }

  void update_src_mac(const mac_addr &src) {
    memcpy(_eth_header->ether_shost, src.data(), ETHER_ADDR_LEN);
  }

  void update_dst_mac(const mac_addr &dst) {
    memcpy(_eth_header->ether_dhost, dst.data(), ETHER_ADDR_LEN);
  }

  void print_header() {
    print_hdr_eth((uint8_t *)_eth_header);
    print_addr_eth((uint8_t *)_eth_header);
  }

  // type is in host order
  void update_header_data(mac_addr src, mac_addr dst, uint16_t type) {
    memcpy(_eth_header->ether_shost, src.data(), ETHER_ADDR_LEN);
    memcpy(_eth_header->ether_dhost, dst.data(), ETHER_ADDR_LEN);
    _eth_header->ether_type = htons(type);
  }

  const sr_ethernet_hdr_t *header() const { return _eth_header; }

private:
  sr_ethernet_hdr_t *_eth_header;
  uint16_t data_type = 0;
};

class ICMPPacket {
public:
  enum class Type { T0, T3, T11 };

  enum class Code { Zero, NetUnreachable, HostUnreachable, PortUnreachable };

  ICMPPacket(Type type, Code code, std::vector<uint8_t> data_in = {}) {

    if (type == Type::T3 && data_in.size() > ICMP_DATA_SIZE) {
      std::cout << "Cannot create\n";
      exit(1);
    }

    _type = type;
    _code = code;

    if (_type == Type::T3) {
      t3_packet.icmp_type = (uint8_t)type;
      t3_packet.icmp_code = (uint8_t)code;

      t3_packet.next_mtu = htons(1500);
      t3_packet.unused = htons(0);

      memset(t3_packet.data, 0, ICMP_DATA_SIZE);
      memcpy(t3_packet.data, data_in.data(), ICMP_DATA_SIZE);
    } else {
      t_packet.icmp_type = (uint8_t)type;
      t_packet.icmp_code = (uint8_t)code;
    }

    calculate_checksum();
  }

  void calculate_checksum() {
    if (_type == Type::T3) {
      t3_packet.icmp_sum = 0;
      t3_packet.icmp_sum =
          cksum(&t3_packet, sizeof(sr_icmp_t3_hdr_t)); // ! dk if this right
    } else {
      t_packet.icmp_sum = 0;
      t_packet.icmp_sum =
          cksum(&t_packet, sizeof(sr_icmp_hdr_t)); // ! same here
    }
  }

  Packet get_packet() const {

    Packet packet;

    if (_type == Type::T3) {
      packet.resize(sizeof(sr_icmp_t3_hdr_t));
      std::memcpy(packet.data(), &t3_packet, sizeof(sr_icmp_t3_hdr_t));
    } else {
      packet.resize(sizeof(sr_icmp_hdr_t));
      std::memcpy(packet.data(), &t_packet, sizeof(sr_icmp_hdr_t));
    }

    return packet;
  }

  void convert_to_network_order() {
    // ! dont need to convert type/code fields bc theyre only one byte long
    if (_type == Type::T3) {
      t3_packet.icmp_sum = htons(t3_packet.icmp_sum);
      t3_packet.unused = htons(t3_packet.unused);
      t3_packet.next_mtu = htons(t3_packet.next_mtu);
    } else {
      t_packet.icmp_sum = htons(t_packet.icmp_sum);
    }
  }

  void convert_to_host_order() {
    if (_type == Type::T3) {
      t3_packet.icmp_sum = ntohs(t3_packet.icmp_sum);
      t3_packet.unused = ntohs(t3_packet.unused);
      t3_packet.next_mtu = ntohs(t3_packet.next_mtu);
    } else {
      t_packet.icmp_sum = ntohs(t_packet.icmp_sum);
    }
  }

private:
  Type _type;
  Code _code;
  union {
    sr_icmp_hdr_t t_packet;
    sr_icmp_t3_hdr_t t3_packet;
  };
};

// * Helepr Generator Functions

inline mac_addr get_broadcast_mac_addr() {
  static const uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF,
                                                         0xFF, 0xFF, 0xFF};
  return make_mac_addr((void *)broadcast_addr);
}

inline Packet create_ethernet_packet(mac_addr src_mac, mac_addr dst_mac,
                                     sr_ethertype type, Packet data) {

  sr_ethernet_hdr_t eth_header;

  EthPacketHeader eth(&eth_header);
  eth.update_src_mac(src_mac);
  eth.update_dst_mac(dst_mac);
  eth.update_type(type);

  Packet packet(sizeof(sr_ethernet_hdr_t) + data.size());
  memcpy(packet.data(), &eth_header, sizeof(sr_ethernet_hdr_t));
  memcpy(packet.data() + sizeof(sr_ethernet_hdr_t), data.data(), data.size());

  return packet;
}

/*


  Type 0 - Response to an Echo request ping to the oruter interfacece
  Type 3 Code 1 - 7 unreachable arp requests
  Type 3 Code 0 - NOn eexisten torute no matching entry in routing table
  Type 3 Code 0 - No matching entry in routing table when forwarding ip packet
  Type 11 code 0  - IP packet discard because the TTL field is 0

  Type 8 0 - Echo request?

*/
inline Packet create_ip_packet(ip_addr src_ip, ip_addr dst_ip, uint8_t protocol,
                               Packet data, uint8_t ttl = 64) {
  sr_ip_hdr_t ip_header;

  ip_header.ip_tos = 0;
  ip_header.ip_len = htons(data.size() + sizeof(sr_ip_hdr_t));
  ip_header.ip_id = htons(0);
  ip_header.ip_off = htons(IP_DF); // Don't fragment
  ip_header.ip_ttl = ttl;
  ip_header.ip_p = protocol;
  ip_header.ip_src = src_ip;
  ip_header.ip_dst = dst_ip;
  ip_header.ip_sum = 0; // Checksum calculated by router

  Packet packet(sizeof(sr_ip_hdr_t) + data.size());
  memcpy(packet.data(), &ip_header, sizeof(sr_ip_hdr_t));
  memcpy(packet.data() + sizeof(sr_ip_hdr_t), data.data(), data.size());

  return packet;
}

inline Packet create_icmp_packet(Type icmp_type, Code code) {}

inline Packet create_icmp_t3_packet(Code code) {}

// Creates an arp request
inline Packet create_arp_packet(mac_addr src_mac, ip_addr src_ip,
                                mac_addr dst_mac, ip_addr dst_ip,
                                sr_arp_opcode type) {

  sr_arp_hdr_t arp_header;

  arp_header.ar_hrd = htons(sr_arp_hrd_fmt::arp_hrd_ethernet);
  arp_header.ar_pro = htons(sr_ethertype::ethertype_arp);
  arp_header.ar_hln = ETHER_ADDR_LEN;
  // arp_header.ar_pln = sr_ip_hdr().ip_hl;
  arp_header.ar_pln = 4;

  arp_header.ar_op = htons(type);

  ArpPacketHeader arp(&arp_header);
  arp.update_src_mac(src_mac);
  arp_header.ar_sip = src_ip;

  arp.update_dst_mac(dst_mac);
  arp_header.ar_tip = dst_ip;

  Packet arp_packet(sizeof(sr_ethernet_hdr_t));

  memcpy(arp_packet.data(), &arp_header, sizeof(sr_ethernet_hdr_t));

  return arp_packet;
}