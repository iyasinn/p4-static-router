
// // checksum and lets see if the ip packet is valid
// // also i want something for simply converting a buffer to

#include "protocol.h"
#include "util.h"
#include "utils.h"
#include <_types/_uint8_t.h>

// bool ip_checksum_valid(sr_ip_hdr_t *ip) {
//   int checksum = cksum(ip, sizeof(sr_ip_hdr_t));
// }

class ETHR_Packet {

  //   sr_ethertype;
} l

    class ARP_Packet_Header {
public:
  ARP_Packet(const sr_arp_hdr_t *const data) : _arp_packet(*data) {}

  void convert_to_host_order() {
    _arp_packet.ar_hrd = ntohs(_arp_packet.ar_hrd);
    _arp_packet.ar_pro = ntohs(_arp_packet.ar_pro);
    _arp_packet.ar_op = ntohs(_arp_packet.ar_op);
    _arp_packet.ar_sip = ntohl(_arp_packet.ar_sip);
    _arp_packet.ar_tip = ntohl(_arp_packet.ar_tip);
  }

  void convert_to_network_order() {
    _arp_packet.ar_hrd = htons(_arp_packet.ar_hrd);
    _arp_packet.ar_pro = htons(_arp_packet.ar_pro);
    _arp_packet.ar_op = htons(_arp_packet.ar_op);
    _arp_packet.ar_sip = htonl(_arp_packet.ar_sip);
    _arp_packet.ar_tip = htonl(_arp_packet.ar_tip);
  }

  const sr_arp_hdr_t &packet() { return _arp_packet; }

private:
  sr_arp_hdr_t _arp_packet;
};