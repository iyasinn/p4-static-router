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
    _ip_packet->ip_len =
        ntohs(_ip_packet->ip_len);  // Total length of IP packet
    _ip_packet->ip_id =
        ntohs(_ip_packet->ip_id);  // Identification field for fragmentation
    _ip_packet->ip_off = ntohs(_ip_packet->ip_off);  // Fragment offset field
    _ip_packet->ip_sum = ntohs(_ip_packet->ip_sum);  // IP header checksum
    _ip_packet->ip_src = ntohl(_ip_packet->ip_src);  // Source IP address
    _ip_packet->ip_dst = ntohl(_ip_packet->ip_dst);  // Destination IP address
  }

  void convert_to_network_order() {
    _ip_packet->ip_len =
        htons(_ip_packet->ip_len);  // Total length of IP packet
    _ip_packet->ip_id =
        htons(_ip_packet->ip_id);  // Identification field for fragmentation
    _ip_packet->ip_off = htons(_ip_packet->ip_off);  // Fragment offset field
    _ip_packet->ip_sum = htons(_ip_packet->ip_sum);  // IP header checksum
    _ip_packet->ip_src = htonl(_ip_packet->ip_src);  // Source IP address
    _ip_packet->ip_dst = htonl(_ip_packet->ip_dst);  // Destination IP address
  }

  void calc_checksum() {
    _ip_packet->ip_sum = 0;
    _ip_packet->ip_sum = cksum(_ip_packet, sizeof(sr_ip_hdr_t));  // ! same here
  }

  void prepare_for_send() {
    convert_to_network_order();
    calc_checksum();
  }
  // validates packet's checksum
  // throws corresponding ICMPException if packet is corrupted
  void validate_checksum() {
    _ip_packet->ip_sum = 0;  // 0 the checksum before validating - rfc 1071
    uint16_t calcd_checksum =
        cksum(_ip_packet, _ip_packet->ip_hl * 4);  // header len in bytes

    if (calcd_checksum != _ip_packet->ip_sum) {
      throw ICMPException(Type::T3, Code::NetUnreachable);
    }
  }

  const sr_ip_hdr_t &packet() const { return *_ip_packet; }

  uint8_t get_ttl() const { return _ip_packet->ip_ttl; }

  // decrements TTL, throws corresponding ICMPException if TTL == 0
  void decr_ttl() {
    _ip_packet->ip_ttl--;
    if (_ip_packet->ip_ttl == 0) {
      throw ICMPException(Type::T11, Code::Zero);
    }
  }

  uint16_t get_checksum() const { return _ip_packet->ip_sum; }

  const uint32_t get_ip_src() const { return _ip_packet->ip_src; }

  const uint32_t get_ip_dst() const { return _ip_packet->ip_dst; }

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

  void set_eth_header(const sr_ethernet_hdr_t &header) {
    if (_eth_packet.size() < sizeof(sr_ethernet_hdr_t)) {
      _eth_packet.resize(sizeof(sr_ethernet_hdr_t));
    }
    std::memcpy(_eth_packet.data(), &header, sizeof(sr_ethernet_hdr_t));
    _eth_header = reinterpret_cast<sr_ethernet_hdr_t *>(_eth_packet.data());
  }

  Packet to_packet() {
    Packet packet;

    // TODO: impl me
  }

  IP_Packet_Header ip;
  ARP_Packet_Header arp;

 private:
  std::vector<uint8_t> _eth_packet;
  sr_ethernet_hdr_t *_eth_header;
  uint16_t data_type = 0;
};

enum class Type { T0, T3, T11 };

enum class Code { Zero, NetUnreachable, HostUnreachable, PortUnreachable };

class ICMP_Packet {
 public:
  ICMP_Packet(const ICMPException &e) : _type(e.getType()), _code(e.getCode()) {
    switch (_type) {
      case Type::T3:
        _t3_packet = new sr_icmp_t3_hdr_t();
        break;
      case Type::T0:
      case Type::T11:
        _packet = new sr_icmp_hdr_t();
        break;
    }
  }

  ~ICMP_Packet() {
    if (_type == Type::T3) {  // prefer if-else bc of less opts
      delete _t3_packet;
    } else {
      delete _packet;
    }
  }

  void calc_checksum() {
    if (_type == Type::T3) {
      _t3_packet->icmp_sum = 0;
      _t3_packet->icmp_sum =
          cksum(_t3_packet, sizeof(sr_icmp_t3_hdr_t));  // ! dk if this right
    } else {
      _packet->icmp_sum = 0;
      _packet->icmp_sum = cksum(_packet, sizeof(sr_icmp_hdr_t));  // ! same here
    }
  }

  void prepare_for_send() {
    convert_to_network_order();
    calc_checksum();
  }

  // ! put prepare_for_send() inside to_packet()? prob fine,
  // ! dt decoupling a huge issue here, but ill leave as is
  Packet to_packet() const {
    Packet packet;
    packet.clear();

    // serialize
    if (_type == Type::T3) {
      packet.resize(sizeof(sr_icmp_t3_hdr_t));
      std::memcpy(packet.data(), _t3_packet, sizeof(sr_icmp_t3_hdr_t));
    } else {
      packet.resize(sizeof(sr_icmp_hdr_t));
      std::memcpy(packet.data(), _packet, sizeof(sr_icmp_hdr_t));
    }

    return packet;
  }

  void convert_to_network_order() {
    // ! dont need to convert type/code fields bc theyre only one byte long
    if (_type == Type::T3) {
      _t3_packet->icmp_sum = htons(_t3_packet->icmp_sum);
      _t3_packet->unused = htons(_t3_packet->unused);
      _t3_packet->next_mtu = htons(_t3_packet->next_mtu);
    } else {
      _packet->icmp_sum = htons(_packet->icmp_sum);
    }
  }

  void convert_to_host_order() {
    if (_type == Type::T3) {
      _t3_packet->icmp_sum = ntohs(_t3_packet->icmp_sum);
      _t3_packet->unused = ntohs(_t3_packet->unused);
      _t3_packet->next_mtu = ntohs(_t3_packet->next_mtu);
    } else {
      _packet->icmp_sum = ntohs(_packet->icmp_sum);
    }
  }

 private:
  Type _type;
  Code _code;
  union {
    sr_icmp_hdr_t *_packet;
    sr_icmp_t3_hdr_t *_t3_packet;
  };
};

class ICMPException : public std::exception {
 public:
  ICMPException(Type type, Code code) : _type(type), _code(code) {}

  const char *what() const noexcept override { return "ICMP error occurred"; }

  Type getType() const { return _type; }
  Code getCode() const { return _code; }

 private:
  Type _type;
  Code _code;
};