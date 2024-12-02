#include "StaticRouter.h"

#include <cstdint>
// #include <_types/_uint16_t.h>
// #include <_types/_uint8_t.h>
#include <cstring>
#include <spdlog/spdlog.h>

#include "IRoutingTable.h"
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
  EthPacketHeader eth(packet);

  spdlog::info("Received packet on interface: {}", iface);
  spdlog::info("Packet size: {}", packet.size());
  eth.print_header();
  spdlog::info("Handling Packet");

  // * Handle packet lgoic

  if (eth.get_type() == sr_ethertype::ethertype_arp) {
    handle_arp(packet, iface);
  } else if (eth.get_type() == sr_ethertype::ethertype_ip) {
  }
}

void StaticRouter::handle_ip(Packet packet, const std::string &iface) {

  /*

    We have a few type of ip requests to our interface

  */
}

void StaticRouter::handle_arp(Packet packet, const std::string &iface) {
  ArpPacketHeader arp(packet);

  switch (arp.get_type()) {
  case sr_arp_opcode::arp_op_request:
    handle_arp_request(packet, iface);
    break;
  case sr_arp_opcode::arp_op_reply:
    handle_arp_reply(packet, iface);
    break;
  default:
    spdlog::warn("Unknown ARP operation type.");
    break;
  }
}

void StaticRouter::handle_arp_request(Packet packet, const std::string &iface) {

  int size_for_arp = packet.size() - sizeof(sr_ethernet_hdr_t);
  
  if (size_for_arp < sizeof(sr_arp_hdr_t)) {
    spdlog::error("ARP packet is too small to contain an ARP header.");
    return;
  }


  EthPacketHeader eth(packet);
  ArpPacketHeader arp(packet);

  // Need to see if we have enough space for an arp packet

  auto interface = routingTable->getRoutingInterface(iface);

  if (interface.ip != arp.header().ar_tip) {
    spdlog::error("ARP packet not destined for us");
    return;
  }

  // arp.convert_to_reply(interface.ip, interface.mac);
  auto apr_packet =
      create_arp_packet(interface.mac, interface.ip, arp.get_sender_mac(),
                        arp.header().ar_sip, sr_arp_opcode::arp_op_reply);
  // eth.update_header_data(interface.mac, arp.get_target_mac(),
  //  sr_ethertype::ethertype_arp);
  auto eth_packet =
      create_ethernet_packet(interface.mac, arp.get_sender_mac(),
                             sr_ethertype::ethertype_arp, apr_packet);

  ArpPacketHeader random(eth_packet);
  EthPacketHeader rnadometh(eth_packet);

  spdlog::info("Sending ARP packet\n\n");
  eth.print_header();
  rnadometh.print_header();
  packetSender->sendPacket(eth_packet, iface);
}

void StaticRouter::handle_arp_reply(Packet packet, const std::string &iface) {


  /*
    So we are receiving a reply. Is this reply for us? We should 

  */

  EthPacketHeader eth(packet);
  ArpPacketHeader arp(packet);
  arpCache->addEntry(arp.get_sender_ip(), arp.get_sender_mac());
}
