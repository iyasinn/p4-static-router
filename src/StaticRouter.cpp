#include "StaticRouter.h"

#include <cstdint>
// #include <_types/_uint16_t.h>
// #include <_types/_uint8_t.h>
#include <spdlog/spdlog.h>

#include <cstring>
#include <iostream>

#include "protocol.h"
#include "utils.h"

// Our libraries
#include <string>

#include "Helper.h"

StaticRouter::StaticRouter(std::unique_ptr<IArpCache> arpCache,
                           std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable),
      packetSender(packetSender),
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
    // arp.print_header();
  } else if (eth.get_type() == sr_ethertype::ethertype_ip) {
    eth.convert_to_host_order();  // ! implicitly call this in ETH_Packet ctor?
                                  // ! @iyasin
    IP_Packet_Header &ip = eth.ip;
    print_hdr_ip((uint8_t *)&ip.packet());

    /*
      TODO:
        overall, need to validate when to convert to network byte order
        and make finish some small things like creating the final ethernet
        packet after getting response from ARP cache, etc

        also need to make sure the ICMP stuff is working properly
        ! cant test bc ping repeatedly sends ARP requests, will never send IP
        ! until ARP request is resolved
     */
    try {
      ip.validate_checksum();
      ip.decr_ttl();
      auto routing_entry = routingTable->getRoutingEntry(ip.get_ip_dst());
      if (!routing_entry) {
        throw ICMPException(Type::T3,
                            Code::NetUnreachable);  // ! i think its this code?
      }
      auto arp_entry = arpCache->getEntry(routing_entry->dest);
      if (!arp_entry) {
        // Otherwise, send an ARP request for the next-hop IP (if one hasn't
        // been sent within the last second), and add the packet to the queue of
        // packets waiting on this ARP request.
      }

      ip.prepare_for_send();
      // init ethernet header, pass below
      // eth.set_eth_header() // ! this function is defined, but havent tested
      // TODO: stick ip packet back in eth frame body
      // ! ETH_Packet::to_packet() not impld
      packetSender->sendPacket(eth.to_packet(), routing_entry->iface);

    } catch (const ICMPException &e) {
      ICMP_Packet icmp = ICMP_Packet(e);
      icmp.prepare_for_send();
      // send back on iface which we received packet from
      packetSender->sendPacket(icmp.to_packet(), iface);
    }
  }
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
