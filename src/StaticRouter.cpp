#include "StaticRouter.h"

#include <_types/_uint16_t.h>
#include <cstring>
#include <spdlog/spdlog.h>

#include "protocol.h"
#include "utils.h"

#include <iostream>

// Our libraries
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

  // Create a packet object
  sr_ethernet_hdr_t *ethr = (sr_ethernet_hdr_t *)(packet.data());
  // sr_ip_hdr_t *ipr = (sr_ip_hdr_t *)(packet.data() +
  // sizeof(sr_ethernet_hdr_t));

  print_hdr_eth(packet.data());

  auto dst_addr = make_mac_addr(ethr->ether_dhost);
  auto src_addr = make_mac_addr(ethr->ether_shost);
  uint16_t type = ntohs(ethr->ether_type);

  if (type == sr_ethertype::ethertype_ip) {

  } else if (type == sr_ethertype::ethertype_arp) {
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
}
