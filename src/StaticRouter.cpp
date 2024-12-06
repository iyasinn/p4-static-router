#include "StaticRouter.h"

#include <cstddef>
#include <cstdint>
// #include <_types/_uint16_t.h>
// #include <_types/_uint8_t.h>
#include <cstring>
#include <spdlog/spdlog.h>

#include "IRoutingTable.h"
#include "RouterTypes.h"
#include "protocol.h"
#include "utils.h"

#include <iostream>

// Our libraries
#include "Helper.h"
#include <string>
#include <vector>

StaticRouter::StaticRouter(std::unique_ptr<IArpCache> arpCache,
                           std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable), packetSender(packetSender),
      arpCache(std::move(arpCache)) {}

void StaticRouter::handlePacket(std::vector<uint8_t> packet,
                                std::string iface)
{
  std::unique_lock lock(mutex);

  try
  {
    spdlog::info("\n\nHandle packet invoked");

    if (packet.size() < sizeof(sr_ethernet_hdr_t))
    {
      spdlog::error("Packet is too small to contain an Ethernet header.");
      return;
    }
    EthHeaderModifier eth(packet);

    spdlog::info("Received packet on interface: {}", iface);
    spdlog::info("Packet size: {}", packet.size());
    eth.print_header();
    spdlog::info("Handling Packet");

    // * Handle packet lgoic

    if (eth.get_type() == sr_ethertype::ethertype_arp)
    {
      handle_arp(packet, iface);
    }
    else if (eth.get_type() == sr_ethertype::ethertype_ip)
    {
      handle_ip(packet, iface);
    }
  }
  catch (const std::exception &e)
  {
    spdlog::info("Encountered an error");
    spdlog::info("Error in handlePacket: {}", e.what());
    spdlog::error("Error in handlePacket: {}", e.what());
  }
  spdlog::info("Handle Packet Done\n");
  spdlog::info("------------------------------------\n");
}

// * ------------------ Handle ARP Packets ------------------ * //

void StaticRouter::handle_arp(Packet packet, const std::string &iface)
{
  ArpHeaderModifier arp(packet);

  spdlog::info("Handling Arp packet");
  spdlog::info("Printing ARP Packet");
  arp.print_header();

  int size_for_arp = packet.size() - sizeof(sr_ethernet_hdr_t);

  if (size_for_arp < sizeof(sr_arp_hdr_t))
  {
    spdlog::error("ARP packet is too small to contain an ARP header.");
    return;
  }

  switch (arp.get_type())
  {
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

void StaticRouter::handle_arp_request(Packet raw_eth_packet,
                                      const std::string &iface)
{

  spdlog::info("Handling ARP Request");

  EthHeaderModifier eth(raw_eth_packet);
  ArpHeaderModifier arp(raw_eth_packet);

  auto interface = routingTable->getRoutingInterface(iface);

  if (interface.ip != arp.header().ar_tip)
  {
    spdlog::error("ARP packet request not destined for any of our interfaces");
    return;
  }

  // arp.convert_to_reply(interface.ip, interface.mac);
  auto apr_packet =
      create_arp_packet(interface.mac, interface.ip, arp.get_sender_mac(),
                        arp.header().ar_sip, sr_arp_opcode::arp_op_reply);
  // eth.update_header_data(interface.mac, arp.get_target_mac(),
  //  sr_ethertype::ethertype_arp)
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

void StaticRouter::handle_arp_reply(Packet raw_eth_packet,
                                    const std::string &iface)
{

  spdlog::info("Handling ARP Reply");

  EthHeaderModifier eth(raw_eth_packet);
  ArpHeaderModifier arp(raw_eth_packet);

  auto interface = routingTable->getRoutingInterface(iface);

  if (interface.ip != arp.header().ar_tip)
  {
    spdlog::error("ARP packet reply not destined for any of our interfaces");
    return;
  }

  spdlog::info("Attemping to add ARP reply data to cache");

  arpCache->addEntry(arp.get_sender_ip(), arp.get_sender_mac());
}

// * ------------------ Handle IP Packets ------------------ * //

// entry interface is where this came from. Because we are sending back, we send
// back on entry iface
// Target interface is the interface the packet request was for
void StaticRouter::handle_ip_for_us(Packet packet,
                                    const std::string &entry_iface,
                                    RoutingInterface target_interface)
{

  EthHeaderModifier eth(packet);
  IPHeaderModifier ip(packet);

  // We will return through the entry iface
  auto get_exit_interface = routingTable->getRoutingInterface(entry_iface);

  if (ip.get_protocol() == sr_ip_protocol::ip_protocol_icmp)
  {

    spdlog::info("Handling ICMP packet for us");
    print_hdr_icmp(packet.data() + IP_PACKET_SIZE);

    if (packet.size() < ICMP_PACKET_SIZE)
    {
      spdlog::info("Not enough space for a valid ICMP request packet");
      return;
    }

    sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t *)(packet.data() + IP_PACKET_SIZE);
    uint16_t old_checksum = icmp->icmp_sum;
    icmp->icmp_sum = htons(0);
    uint16_t new_checksum = cksum(icmp, packet.size() - IP_PACKET_SIZE);

    if (old_checksum != new_checksum)
    {
      spdlog::info("ICMP Packet has a bad checksum");
      return;
    }

    ICMP_T_PacketModifier incoming_icmp(packet);

    if (incoming_icmp.get_type() != (uint8_t)Type::T8)
    {
      spdlog::info("Not a icmp echo request. We can drop");
      return;
    }
    // ! Better to copy entire packet and modify the fields
    Packet data_copy =
        std::vector<uint8_t>(packet.begin() + IP_PACKET_SIZE + 4, packet.end());

    Packet icmp_packet = create_t0_icmp(Type::T0, Code::C0, data_copy);
    Packet ip_packet =
        create_ip_packet(target_interface.ip, ip.get_ip_src(),
                         sr_ip_protocol::ip_protocol_icmp, icmp_packet);
    Packet eth_packet =
        create_ethernet_packet(get_exit_interface.mac, eth.get_src_mac(),
                               sr_ethertype::ethertype_ip, ip_packet);

    print_hdr_icmp(icmp_packet.data());
    print_hdr_ip(ip_packet.data());
    print_hdr_eth(eth_packet.data());

    spdlog::info("Sending ICMP echo reply");
    packetSender->sendPacket(eth_packet, entry_iface);
  }
  // * ICMP UDP TCP
  else if (ip.get_protocol() == sr_ip_protocol::ip_protocol_udp ||
           ip.get_protocol() == sr_ip_protocol::ip_protocol_tcp)
  {
    spdlog::info("Handling TCP UDP Packet for us");

    Packet original_ip_packet = ip.get_packet_copy();
    // Add the 8 bytes of TCP UDP
    for (int i = IP_PACKET_SIZE; i < IP_PACKET_SIZE + 8; i++)
    {
      original_ip_packet.push_back(packet[i]);
    }

    Packet icmp_packet = create_t3_icmp(Type::T3, Code::C3, original_ip_packet);
    Packet ip_packet =
        create_ip_packet(target_interface.ip, ip.get_ip_src(),
                         sr_ip_protocol::ip_protocol_icmp, icmp_packet);
    Packet eth_packet =
        create_ethernet_packet(get_exit_interface.mac, eth.get_src_mac(),
                               sr_ethertype::ethertype_ip, ip_packet);
    spdlog::info("Sending ICMP port unreachable because TCP UDP");
    print_hdr_eth(eth_packet.data());
    print_hdr_ip(ip_packet.data());
    print_hdr_icmp(icmp_packet.data());
    packetSender->sendPacket(eth_packet, entry_iface);
  }
}

void StaticRouter::handle_ip(Packet eth_packet, const std::string &iface)
{

  spdlog::info("Handling IP Packet");

  IPHeaderModifier ip(eth_packet);

  ip.print_header();

  if (!ip.is_valid_checksum())
  {
    spdlog::error("Invalid checksum");
    return;
  }

  else if (ip.get_ttl() <= 0)
  {
    spdlog::error("TTL is 0, so we ignore and drop it");
    return;
  }

  // * IP packet is for us
  for (auto interface : routingTable->getRoutingInterfaces())
  {
    if (interface.second.ip == ip.get_ip_dst())
    {
      spdlog::info("Handling IP packet for us");
      handle_ip_for_us(eth_packet, iface, interface.second);
      return;
    }
  }

  // * IP packet needs to be routed
  auto entry = routingTable->getRoutingEntry(ip.get_ip_dst());

  // * Nowhere to route this IP packet - Desintaiotn Net unreadhable
  if (entry == std::nullopt)
  {

    auto entry_interface = routingTable->getRoutingInterface(iface);
    EthHeaderModifier eth(eth_packet);

    Packet original_ip_packet = ip.get_packet_copy();
    // Add the 8 bytes of TCP UDP
    for (int i = IP_PACKET_SIZE; i < IP_PACKET_SIZE + 8; i++)
    {
      if (i >= eth_packet.size())
      {
        spdlog::info("We are exceeiding packet size, but we'll just do it... and pad with 0");
        original_ip_packet.push_back(0);
        continue;
      }
      original_ip_packet.push_back(eth_packet[i]);
    }
    // destination unreachable
    // were're sending this back from where it came from
    Packet new_icmp_packet =
        create_t3_icmp(Type::T3, Code::C0, original_ip_packet);
    Packet new_ip_packet =
        create_ip_packet(entry_interface.ip, ip.get_ip_src(),
                         sr_ip_protocol::ip_protocol_icmp, new_icmp_packet);
    Packet new_eth_packet =
        create_ethernet_packet(entry_interface.mac, eth.get_src_mac(),
                               sr_ethertype::ethertype_ip, new_ip_packet);

    spdlog::error(
        "No entry found for destination IP so destination net unreachable");
    packetSender->sendPacket(new_eth_packet, iface);
    return;
  }

  // * This is the interface for our entry
  // auto interface = routingTable->getRoutingInterface(iface);
  auto exit_interface = routingTable->getRoutingInterface(entry->iface);

  // * Handle types of ip requests for us
  // if (interface.ip == ip.get_ip_dst()) {
  //   spdlog::info("Handling IP packet for us");
  //   handle_ip_for_us(eth_packet, iface, interface);

  //   return;
  // }

  // Only decrement ttl before sending
  // ip.decrement_ttl();

  if (ip.get_ttl() == 1)
  {
    // if (true){
    auto return_interface = routingTable->getRoutingInterface(iface);
    EthHeaderModifier eth(eth_packet);

    Packet original_ip_packet = ip.get_packet_copy();
    // Add the 8 bytes of TCP UDP
    for (int i = IP_PACKET_SIZE; i < IP_PACKET_SIZE + 8; i++)
    {
      if (i == eth_packet.size())
      {
        break;
      }
      original_ip_packet.push_back(eth_packet[i]);
    }
    // time exceeded
    Packet new_icmp_packet =
        create_t3_icmp(Type::T11, Code::C0, original_ip_packet);
    Packet new_ip_packet =
        create_ip_packet(return_interface.ip, ip.get_ip_src(),
                         sr_ip_protocol::ip_protocol_icmp, new_icmp_packet);
    Packet new_eth_packet =
        create_ethernet_packet(return_interface.mac, eth.get_src_mac(),
                               sr_ethertype::ethertype_ip, new_ip_packet);

    spdlog::info("Timed out");
    packetSender->sendPacket(new_eth_packet, iface);
    return;
  }

  spdlog::info("Forward packet");

  // need to update the eth src and eth mac
  // we need to decrement as well

  auto entry_mac = arpCache->getEntry(entry->gateway);
  if (entry_mac != std::nullopt)
  {
    EthHeaderModifier eth(eth_packet);
    eth.update_src_mac(exit_interface.mac);
    eth.update_dst_mac(entry_mac.value());
    ip.decrement_ttl();
    spdlog::info("Sending packet to gateway IMMEDIATELY");
    eth.print_header();
    ip.print_header();
    packetSender->sendPacket(eth_packet, entry->iface);
    return;
  }
  else
  {
    arpCache->queuePacket(entry->gateway, eth_packet, entry->iface);
  }

  spdlog::info("Finished forwaridng a packet");

  return;
}
