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

  spdlog::info("\n\nHandle packet invoked");

  if (packet.size() < sizeof(sr_ethernet_hdr_t)) {
    spdlog::error("Packet is too small to contain an Ethernet header.");
    return;
  }
  EthHeaderModifier eth(packet);

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

// * ------------------ Handle ARP Packets ------------------ * //

void StaticRouter::handle_arp(Packet packet, const std::string &iface) {
  ArpHeaderModifier arp(packet);

  spdlog::info("Handling Arp packet");
  spdlog::info("Printing ARP Packet");
  arp.print_header();

  int size_for_arp = packet.size() - sizeof(sr_ethernet_hdr_t);

  if (size_for_arp < sizeof(sr_arp_hdr_t)) {
    spdlog::error("ARP packet is too small to contain an ARP header.");
    return;
  }

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

  spdlog::info("Handling ARP Request");

  EthHeaderModifier eth(packet);
  ArpHeaderModifier arp(packet);

  auto interface = routingTable->getRoutingInterface(iface);

  if (interface.ip != arp.header().ar_tip) {
    spdlog::error("ARP packet request not destined for any of our interfaces");
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

  ArpHeaderModifier random(eth_packet);
  EthHeaderModifier rnadometh(eth_packet);

  spdlog::info("Sending ARP reply packet\n");
  eth.print_header();
  rnadometh.print_header();
  packetSender->sendPacket(eth_packet, iface);
}

void StaticRouter::handle_arp_reply(Packet packet, const std::string &iface) {

  spdlog::info("Handling ARP Reply");

  EthHeaderModifier eth(packet);
  ArpHeaderModifier arp(packet);

  auto interface = routingTable->getRoutingInterface(iface);

  if (interface.ip != arp.header().ar_tip) {
    spdlog::error("ARP packet reply not destined for any of our interfaces");
    return;
  }

  spdlog::info("Attemping to add ARP reply data to cache");

  arpCache->addEntry(arp.get_sender_ip(), arp.get_sender_mac());
}

// * ------------------ Handle IP Packets ------------------ * //

void StaticRouter::handle_ip(Packet eth_packet, const std::string &iface) {

  /*
    We have a few type of ip requests to our interface
  */

  spdlog::info("Handling IP Packet");

  IPHeaderModifier ip(eth_packet);

  if (!ip.is_valid_checksum()) {
    spdlog::error("Invalid checksum");
    return;
  } else if (ip.get_ttl() <= 0) {
    spdlog::error("TTL is 0, so we ignore and drop it");
    return;
  }

  ip.decrement_ttl();

  auto entry = routingTable->getRoutingEntry(ip.get_ip_dst());
  // Nothing is reachable

  if (entry == std::nullopt) {
    /*
      Does not match for any entry
    */
  }

  auto interface = routingTable->getRoutingInterface(iface);

  if (interface.ip == ip.get_ip_dst()) {
    // Echo request 
    if (ip.get_protocol() == sr_ip_protocol::ip_protocol_icmp){

      ICMPPacket curr_packet(eth_packet);

      // Now we know we have an ICMP request

      // lets make sure its an echo request 

      ICMPPacket icmp(ICMPPacket::Type::T0, ICMPPacket::Code::C0);
  
      // Make sure we include original data

      //TODO: need to create an ip packet (echo reply) to send back to the sending host 

    } else if (ip.get_protocol() == sr_ip_protocol::ip_protocol_tcp || ip.get_protocol() == sr_ip_protocol::ip_protocol_udp) {
      spdlog::error("We dont support TCP or UDP");
      //TODO: send ICMP port unreachable to sending host
    }
    else{
      spdlog::error("Unknown IP protocol");
    }
    return;
  }

  //TODO: For other ICMP messages (i.e. Type 3 and Type 11) that you send, make sure the data 
  //field is populated correctly with the incoming packet that it is responding to.

  // Now we need to forward but if ttl is 0 we cant forward
  if (ip.get_ttl() == 0) {
    spdlog::error("TTL became 0 after decrementing, so we send icmp");
    return;
  }

  EthHeaderModifier eth(eth_packet);
  eth.update_src_mac(interface.mac);
  arpCache->queuePacket(entry->gateway, eth_packet, entry->iface);

  // * Other method: Not sure if this is better
  // auto arp_entry = arpCache->getEntry(entry->gateway);

  // // Send it out of the right interface
  // if (arp_entry == std::nullopt) {
  //   arpCache->queuePacket(entry->gateway, packet, entry->iface);
  // } else {
  //   eth.update_dst_mac(arp_entry.value());
  //   packetSender->sendPacket(packet, entry->iface);
  // }
}