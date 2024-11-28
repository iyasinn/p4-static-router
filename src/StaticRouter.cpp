#include "StaticRouter.h"

#include <_types/_uint16_t.h>
#include <_types/_uint8_t.h>
#include <cstring>
#include <spdlog/spdlog.h>

#include "protocol.h"
#include "utils.h"

#include <iostream>

// Our libraries
#include "Helper.h"
#include <string>

StaticRouter::StaticRouter(std::unique_ptr<IArpCache> arpCache,
                           std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable), packetSender(packetSender),
      arpCache(std::move(arpCache)) {}

void StaticRouter::handlePacket(std::vector<uint8_t> packet,
                                std::string iface) {
  std::unique_lock lock(mutex);

  if (packet.size() < sizeof(sr_ethernet_hdr_t)) {
    spdlog::error("Packet is too small to contain an Ethernet header.");
    return;
  }

  std::cout << "Received packet on interface: " << iface << std::endl;
  std::cout << "Packet size: " << packet.size() << std::endl;

  ETH_Packet eth(packet);
  eth.print_header();

  // auto dst_addr = make_mac_addr(ethr->ether_dhost);

  if (eth.get_type() == sr_ethertype::ethertype_arp) {
    eth.convert_to_host_order();
    ARP_Packet_Header &arp = eth.arp;
    print_hdr_arp((uint8_t *)arp._arp_packet);
    std::cout << "\n";
    arp.print_header();
  }

  // if (packet_type == sr_ethertype::ethertype_ip) {

  //   sr_ip_hdr_t *ipr =
  //       (sr_ip_hdr_t *)(packet.data() + sizeof(sr_ethernet_hdr_t));

  //   print_hdr_ip((uint8_t *)(ipr));

  //   std::cout << "HAVE NOT IMPLEMENTED THIS YET\n";

  // } else if (packet_type == sr_ethertype::ethertype_arp) {

  //   sr_arp_hdr_t *arp =
  //       (sr_arp_hdr_t *)(packet.data() + sizeof(sr_ethernet_hdr_t));

  //   ARP_Packet_Header arp_header(arp);

  //   print_hdr_arp((uint8_t *)&(arp_header.packet()));

  //   arp_header.convert_to_host_order();

  //   print_hdr_arp((uint8_t *)&(arp_header.packet()));

  //   // Extract the ARP operation type
  //   uint16_t arp_type = ntohs(arp->ar_op);

  //   // Log or process the ARP type as needed
  //   spdlog::info("ARP operation type: {}", arp_type);

  //   ETH_Packet eth(packet);
  // }

  return;
}
// auto mac_addr = make_mac_addr(ethr->ether_dhost);
//   for (int i = 0; i < mac_addr.size(); i++) {
//     std::cout << std::hex << (int)mac_addr[i] << ":";
//   }

/*
  So we have just received a packet on an interface
  We need to figure out what to do with it.

  - Lets focus on Packet Validiation first
      - Check if the packet is valid using the checksum
      - If the TTL is 0, we just drop it


  - Decrement TTL by 1 somewhere


  - ARP stuff to deterimine where ot send it if we need to send it
  - Decrement TTL
  - Determine if we need to forward the packet or if it is destined for this
machine

  - ARP stuff to deterimine where ot send it if we need to send it


Questions:
- DO we decrement TTL If we are the destination?


*/
