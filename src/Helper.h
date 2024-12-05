#ifndef HELPER_H_INCLUDED
#define HELPER_H_INCLUDED

#include "RouterTypes.h"
#include "protocol.h"
#include "spdlog/spdlog.h"
#include "utils.h"
// #include <_types/_uint8_t.h>
// #include <_types/_uint16_t.h>
// #include <_types/_uint8_t.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <iterator>

class ArpHeaderModifier {
public:
  ArpHeaderModifier() {}
  ArpHeaderModifier(Packet &raw_eth_packet) {
    _arp_packet =
        (sr_arp_hdr_t *)(raw_eth_packet.data() + sizeof(sr_ethernet_hdr_t));
  }

  ArpHeaderModifier(sr_arp_hdr_t *arp_header_in) : _arp_packet(arp_header_in) {}

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

class EthHeaderModifier {
public:
  EthHeaderModifier(const std::vector<uint8_t> &raw_network_data) {

    if (raw_network_data.size() < sizeof(sr_ethernet_hdr_t)) {
      std::cerr << "Error: <data> does not contain enough bytes for an "
                   "ethernet packet\n";
      exit(1);
    }

    _eth_header = (sr_ethernet_hdr_t *)raw_network_data.data();
    data_type = ntohs(_eth_header->ether_type);
  }

  EthHeaderModifier(sr_ethernet_hdr_t *eth_in) : _eth_header(eth_in) {}

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

  mac_addr get_src_mac() const {
    return make_mac_addr(_eth_header->ether_shost);
  }

  mac_addr get_dst_mac() const {
    return make_mac_addr(_eth_header->ether_dhost);
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

enum class Type { T0 = 0, T3 = 3, T8 = 8, T11 = 11 };

enum class Code { C0 = 0, C1 = 1, C2 = 2, C3 = 3 };


// Only operates on a sr_icmp_hdr
class ICMP_T_PacketModifier {
public:
  ICMP_T_PacketModifier(const Packet &raw_ethernet_data) {
    icmp_packet = (sr_icmp_hdr_t *)(raw_ethernet_data.data() + IP_PACKET_SIZE);
  }

  ICMP_T_PacketModifier(sr_icmp_hdr_t *icmp_packet_in)
      : icmp_packet(icmp_packet_in) {}

  bool is_valid_checksum() {
    int original_checksum = icmp_packet->icmp_sum;
    calculate_checksum();
    int calculated_checksum = icmp_packet->icmp_sum;
    icmp_packet->icmp_sum = original_checksum;
    return calculated_checksum == original_checksum;
  }

  uint8_t get_type() const { return icmp_packet->icmp_type; }

  uint8_t get_code() const { return icmp_packet->icmp_code; }

  // void update_type(uint8_t type) {
  //   icmp_packet->icmp_type = type;
  //   calculate_checksum();
  // }

  // void update_code(uint8_t code) {
  //   icmp_packet->icmp_code = code;
  //   calculate_checksum();
  // }

  void update_checksum() { calculate_checksum(); }

  Packet get_packet_copy() {
    Packet packet(sizeof(sr_icmp_hdr_t));
    memcpy(packet.data(), icmp_packet, sizeof(sr_icmp_hdr_t));
    return packet;
  }

  sr_icmp_hdr_t *header() { return icmp_packet; }

private:
  void calculate_checksum() {
    icmp_packet->icmp_sum = htons(0);
    icmp_packet->icmp_sum = cksum(icmp_packet, sizeof(sr_icmp_hdr_t));
  }

  sr_icmp_hdr_t *icmp_packet = nullptr;
};

class IPHeaderModifier {
public:
  IPHeaderModifier() {}

  IPHeaderModifier(const Packet &raw_ethernet_data) {
    ip_header =
        (sr_ip_hdr_t *)(raw_ethernet_data.data() + sizeof(sr_ethernet_hdr_t));
  }

  IPHeaderModifier(sr_ip_hdr_t *const ip_header_in) : ip_header(ip_header_in) {}

  void print_header() const { print_hdr_ip((uint8_t *)ip_header); }

  bool is_valid_checksum() {
    int original_checksum = ip_header->ip_sum;
    calculate_checksum();
    int calculated_checksum = ip_header->ip_sum;

    // restore our original checksum
    ip_header->ip_sum = original_checksum;
    return calculated_checksum == original_checksum;
  }

  uint8_t get_ttl() const { return ip_header->ip_ttl; }

  void decrement_ttl() {
    ip_header->ip_ttl -= 1;
    calculate_checksum();
  }

  // network order src ip
  const uint32_t get_ip_src() const { return ip_header->ip_src; }

  // network order dst ip
  const uint32_t get_ip_dst() const { return ip_header->ip_dst; }

  uint8_t get_protocol() const { return ip_header->ip_p; }

  Packet get_packet_copy() {
    Packet packet(sizeof(sr_ip_hdr_t));
    memcpy(packet.data(), ip_header, sizeof(sr_ip_hdr_t));
    return packet;
  }

private:
  void calculate_checksum() {
    ip_header->ip_sum = htons(0);

    // * If we were using options, then the length would be ip_hl * 4
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
  }

  sr_ip_hdr_t *ip_header = nullptr;
};

// * ------------------ Helper Generator Functions ------------------ * //

inline mac_addr get_broadcast_mac_addr() {
  static const uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF,
                                                         0xFF, 0xFF, 0xFF};
  return make_mac_addr((void *)broadcast_addr);
}

inline mac_addr get_blank_mac_addr() {
  static const uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0x00, 0x00, 0x00,
                                                         0x00, 0x00, 0x00};
  return make_mac_addr((void *)broadcast_addr);
}

inline Packet create_ethernet_packet(mac_addr src_mac, mac_addr dst_mac,
                                     sr_ethertype type, Packet data) {

  sr_ethernet_hdr_t eth_header;

  EthHeaderModifier eth(&eth_header);
  eth.update_src_mac(src_mac);
  eth.update_dst_mac(dst_mac);
  eth.update_type(type);

  Packet packet(sizeof(sr_ethernet_hdr_t) + data.size());
  memcpy(packet.data(), &eth_header, sizeof(sr_ethernet_hdr_t));
  memcpy(packet.data() + sizeof(sr_ethernet_hdr_t), data.data(), data.size());

  return packet;
}

// Creates an arp request
inline Packet create_arp_packet(mac_addr src_mac, ip_addr src_ip,
                                mac_addr dst_mac, ip_addr dst_ip,
                                sr_arp_opcode type) {

  sr_arp_hdr_t arp_header;

  arp_header.ar_hrd = htons(sr_arp_hrd_fmt::arp_hrd_ethernet);
  arp_header.ar_pro = htons(sr_ethertype::ethertype_ip);
  arp_header.ar_hln = ETHER_ADDR_LEN;
  // arp_header.ar_pln = sr_ip_hdr().ip_hl;
  arp_header.ar_pln = 4;

  arp_header.ar_op = htons(type);

  ArpHeaderModifier arp(&arp_header);
  arp.update_src_mac(src_mac);
  arp_header.ar_sip = src_ip;

  arp.update_dst_mac(dst_mac);
  arp_header.ar_tip = dst_ip;

  Packet arp_packet(sizeof(sr_arp_hdr_t));

  memcpy(arp_packet.data(), &arp_header, sizeof(sr_arp_hdr_t));

  return arp_packet;
}

inline Packet create_ip_packet(ip_addr src_ip, ip_addr dst_ip, uint8_t protocol,
                               const Packet &payload) {
  // Step 1: Construct the IP header
  sr_ip_hdr_t ip_header;
  memset(&ip_header, 0, sizeof(sr_ip_hdr_t)); // Clear the memory

  ip_header.ip_v = 4;                        // IPv4
  ip_header.ip_hl = sizeof(sr_ip_hdr_t) / 4; // Header length in 32-bit words
  ip_header.ip_tos = 0;                      // Type of Service (default 0)
  ip_header.ip_len =
      htons(sizeof(sr_ip_hdr_t) + payload.size()); // Total length
  ip_header.ip_id = htons(0);  // Identification field (set to 0 for simplicity)
  ip_header.ip_off = htons(0); // No fragmentation
  ip_header.ip_ttl = INIT_TTL; // Time-to-live
  ip_header.ip_p = protocol;   // Protocol (e.g., ICMP, TCP, UDP)
  ip_header.ip_src = src_ip;   // Source IP address
  ip_header.ip_dst = dst_ip;   // Destination IP address
  ip_header.ip_sum = 0;        // Initialize checksum to 0 before calculation

  // Step 2: Calculate the IP header checksum
  ip_header.ip_sum = cksum(&ip_header, sizeof(sr_ip_hdr_t));

  // Step 3: Create the packet combining IP header and payload
  Packet packet(sizeof(sr_ip_hdr_t) + payload.size());
  memcpy(packet.data(), &ip_header, sizeof(sr_ip_hdr_t)); // Add IP header
  memcpy(packet.data() + sizeof(sr_ip_hdr_t), payload.data(),
         payload.size()); // Add payload

  return packet;
}

inline Packet create_t0_icmp(Type type, Code code, Packet data) {

  Packet packet(sizeof(sr_icmp_hdr_t) + data.size(), 0);
  sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t *)packet.data();

  icmp->icmp_code = (uint8_t)code;
  icmp->icmp_type = (uint8_t)type;
  icmp->icmp_sum = htons(0);

  memcpy(packet.data() + sizeof(sr_icmp_hdr_t), data.data(), data.size());

  icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_hdr_t) + data.size());

  return packet;
}

inline Packet create_t3_icmp(Type type, Code code, Packet data) {

  if (data.size() != ICMP_DATA_SIZE) {
    spdlog::error(
        "ERROR: Tried to create icmp3 packet with wrong amount data of size:",
        data.size(), "\nexpected size: ", ICMP_DATA_SIZE);
    exit(1);
  }

  Packet packet(sizeof(sr_icmp_t3_hdr_t), 0);
  sr_icmp_t3_hdr_t *icmp = (sr_icmp_t3_hdr_t *)packet.data();

  icmp->icmp_code = (uint8_t)code;
  icmp->icmp_type = (uint8_t)type;
  icmp->unused = htons(0);

  // TODO: CHeck this 1500 values
  icmp->next_mtu = htons(1500);
  icmp->icmp_sum = htons(0);

  memset(icmp->data, 0, ICMP_DATA_SIZE);
  memcpy(icmp->data, data.data(), data.size());

  icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));

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

//    inline Packet create_ip_packet(ip_addr src_ip, ip_addr dst_ip, uint8_t
//    protocol,
//                                Packet data, uint8_t ttl = 64) {
//   sr_ip_hdr_t ip_header;
//   ip_header.ip_tos = 0;
//   ip_header.ip_len = htons(data.size() + sizeof(sr_ip_hdr_t));
//   ip_header.ip_id = htons(0);
//   ip_header.ip_off = htons(IP_DF); // Don't fragment
//   ip_header.ip_ttl = ttl;
//   ip_header.ip_p = protocol;
//   ip_header.ip_src = src_ip;
//   ip_header.ip_dst = dst_ip;
//   ip_header.ip_sum = 0; // Checksum calculated by router

//   Packet packet(sizeof(sr_ip_hdr_t) + data.size());
//   memcpy(packet.data(), &ip_header, sizeof(sr_ip_hdr_t));
//   memcpy(packet.data() + sizeof(sr_ip_hdr_t), data.data(), data.size());

//   return packet;
//   }

#endif // ARPCACHE_H

// class ICMPPacket {
// public:
//   ICMPPacket(Type type, Code code, std::vector<uint8_t> data_in) {

//     if (type == Type::T3 && data_in.size() > ICMP_DATA_SIZE) {
//       std::cout << "Cannot create\n";
//       exit(1);
//     }

//     _type = type;
//     _code = code;

//     if (_type == Type::T3) {
//       t3_packet.icmp_type = (uint8_t)type;
//       t3_packet.icmp_code = (uint8_t)code;

//       t3_packet.next_mtu = htons(1500);
//       t3_packet.unused = htons(0);

//       memset(t3_packet.data, 0, ICMP_DATA_SIZE);
//       memcpy(t3_packet.data, data_in.data(), ICMP_DATA_SIZE);
//     } else {
//       t_packet.icmp_type = (uint8_t)type;
//       t_packet.icmp_code = (uint8_t)code;
//     }

//     calculate_checksum();
//   }

//   // Assumes packet has enough space for whatever it has
//   ICMPPacket(Packet eth_packet) {
//     sr_icmp_hdr_t *general =
//         (sr_icmp_hdr_t *)(eth_packet.data() + IP_PACKET_SIZE);

//     _type = (Type)general->icmp_type;
//     _code = (Code)general->icmp_code;

//     if (general->icmp_type == 3) {
//       t3_packet = *((sr_icmp_t3_hdr_t *)(eth_packet.data() + IP_PACKET_SIZE));
//     } else {
//       t_packet = *((sr_icmp_hdr_t *)(eth_packet.data() + IP_PACKET_SIZE));
//     }
//   }

//   void calculate_checksum() {
//     if (_type == Type::T3) {
//       t3_packet.icmp_sum = htons(0);
//       t3_packet.icmp_sum = htons(
//           cksum(&t3_packet, sizeof(sr_icmp_t3_hdr_t))); // ! dk if this right
//     } else {
//       t_packet.icmp_sum = htons(0);
//       t_packet.icmp_sum =
//           cksum(&t_packet, sizeof(sr_icmp_hdr_t)); // ! same here
//     }
//   }

//   bool validate_checksum() {
//     int original_checksum = 0;
//     int calculated_checksum = 0;

//     if (_type == Type::T3) {
//       original_checksum = t3_packet.icmp_sum;
//       calculate_checksum();
//       calculated_checksum = t3_packet.icmp_sum;
//       t3_packet.icmp_sum = original_checksum;
//       return original_checksum == calculated_checksum;
//     } else {
//       original_checksum = t_packet.icmp_sum;
//       calculate_checksum();
//       calculated_checksum = t_packet.icmp_sum;
//       t_packet.icmp_sum = original_checksum;
//       return original_checksum == calculated_checksum;
//     }
//   }

//   Type get_type() { return _type; }

//   Packet get_packet() const {

//     Packet packet;

//     if (_type == Type::T3) {
//       packet.resize(sizeof(sr_icmp_t3_hdr_t));
//       std::memcpy(packet.data(), &t3_packet, sizeof(sr_icmp_t3_hdr_t));
//     } else {
//       packet.resize(sizeof(sr_icmp_hdr_t));
//       std::memcpy(packet.data(), &t_packet, sizeof(sr_icmp_hdr_t));
//     }

//     return packet;
//   }

// private:
//   Type _type;
//   Code _code;
//   union {
//     sr_icmp_hdr_t t_packet;
//     sr_icmp_t3_hdr_t t3_packet;
//   };
// };
