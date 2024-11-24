#include "StaticRouter.h"

#include <cstring>
#include <spdlog/spdlog.h>

#include "protocol.h"
#include "utils.h"

#include <iostream>

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

  // TODO: Your code below

  std::cout << "Received packet on interface: " << iface << std::endl;
  std::cout << "Packet size: " << packet.size() << std::endl;

  print_hdr_eth(packet.data());
  print_hdr_ip(packet.data() + sizeof(sr_ethernet_hdr_t));
  std::cout << "\n";
  sr_ethernet_hdr_t *ethr_hdr = (sr_ethernet_hdr_t *)packet.data();
  std::cout << "ether dst: " << ethr_hdr->ether_dhost << std::endl;
  std::cout << "ether src: " << ethr_hdr->ether_shost << std::endl;
  std::cout << "ether type: " << ethr_hdr->ether_type << std::endl;

  std::cout << "\n";

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
