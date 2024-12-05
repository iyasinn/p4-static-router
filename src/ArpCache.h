#ifndef ARPCACHE_H
#define ARPCACHE_H

// #include <_types/_uint32_t.h>
// #include <_types/_uint8_t.h>
#include <array>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <unordered_map>
#include <vector>

#include "IArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"
#include "RouterTypes.h"
#include "protocol.h"

// Helper files
#include "Helper.h"
#include "spdlog/spdlog.h"
#include <cstdint>

class ArpCache : public IArpCache
{
public:
  ArpCache(std::chrono::milliseconds timeout,
           std::shared_ptr<IPacketSender> packetSender,
           std::shared_ptr<IRoutingTable> routingTable);

  ~ArpCache() override;

  void tick();

  void addEntry(uint32_t ip, const mac_addr &mac) override;

  std::optional<mac_addr> getEntry(uint32_t ip) override;

  void queuePacket(uint32_t ip, const Packet &packet,
                   const std::string &iface) override;

private:
  void loop();

  std::chrono::milliseconds timeout;

  std::mutex mutex;
  std::unique_ptr<std::thread> thread;
  std::atomic<bool> shutdown = false;

  std::shared_ptr<IPacketSender> packetSender;
  std::shared_ptr<IRoutingTable> routingTable;

  std::unordered_map<ip_addr, ArpEntry> entries;
  std::unordered_map<ip_addr, ArpRequest> requests;

  std::optional<std::string> get_iface(uint32_t ip)
  {
    auto entry = routingTable->getRoutingEntry(ip);
    if (entry == std::nullopt)
    {
      return std::nullopt;
    }
    return entry->iface;
  }

  // Sends an arp request for ip. If not exist, create it. Then send.
  // Assumes that there is no arp failure in the system
  // Returns false if we fail to send an arp
  bool send_arp_request(uint32_t ip, std::string iface_name)
  {

    auto &request = requests[ip];

    auto iface = routingTable->getRoutingInterface(iface_name);

    Packet arp_packet =
        create_arp_packet(iface.mac, iface.ip, get_blank_mac_addr(), request.ip,
                          sr_arp_opcode::arp_op_request);

    Packet ethernet_packet =
        create_ethernet_packet(iface.mac, get_broadcast_mac_addr(),
                               sr_ethertype::ethertype_arp, arp_packet);

    packetSender->sendPacket(ethernet_packet, iface_name);
    request.timesSent += 1;
    request.lastSent = std::chrono::steady_clock::now();
    return true;
  }

  void send_all_packets(uint32_t ip)
  {

    auto &packets = requests[ip].awaitingPackets;

    auto gateway_mac_addr = entries[ip].mac;
    auto gateway_ip = ip;

    auto entry = routingTable->getRoutingEntry(gateway_ip);
    auto interface = routingTable->getRoutingInterface(entry->iface);

    while (!packets.empty())
    {

      auto packet_metadata = packets.front();
      EthHeaderModifier eth(packet_metadata.packet);
      IPHeaderModifier ip_hdr(packet_metadata.packet);

      ip_hdr.decrement_ttl();

      eth.update_src_mac(interface.mac);
      eth.update_dst_mac(gateway_mac_addr);

      spdlog::info("TICK FUNCTION: SENDING PACKET");
      eth.print_header();
      ip_hdr.print_header();
      packetSender->sendPacket(packet_metadata.packet, packet_metadata.iface);
      packets.pop_front();
      spdlog::info("\n\n");
    }
  }

  void dump()
  {
    spdlog::info("Dumping arp cache entries");
    for (auto &entry : entries)
    {
      spdlog::info("IP: {}", entry.first);
      spdlog::info("MAC: ");
      print_addr_eth(entry.second.mac.data());
      spdlog::info("");
    }
    spdlog::info("Dumping arp cache requests");
    for (auto &request : requests)
    {
      spdlog::info("IP: {}", request.first);
      spdlog::info("Times sent: {}", request.second.timesSent);
      spdlog::info("Last sent: {}",
                   request.second.lastSent.time_since_epoch().count());
      spdlog::info("Awaiting packets: ");
      for (auto &packet : request.second.awaitingPackets)
      {
        spdlog::info("Packet iface: {}", packet.iface);
      }
    }
  }

  // checks if arp has failed our conditions and send icmp
  // bool check_if_arp_failed(uint32_t ip)
  // {

  //   auto &request = requests[ip];

  //   auto one_second = std::chrono::seconds(1);
  //   auto curr_time = std::chrono::steady_clock::now();

  //   return request.timesSent >= 7 &&
  //          (curr_time - request.lastSent) > one_second;
  // }

  bool check_one_second_elapsed(uint32_t ip)
  {
    auto &request = requests[ip];
    auto one_second = std::chrono::seconds(1);
    auto curr_time = std::chrono::steady_clock::now();
    return (curr_time - request.lastSent) > one_second;
  }

  bool check_seven_arp_sent(uint32_t ip)
  {
    auto &request = requests[ip];
    return request.timesSent >= 7;
  }

  void send_all_icmp(uint32_t ip)
  {

    auto &packets = requests[ip].awaitingPackets;

    while (!packets.empty())
    {

      auto packet_metadata = packets.front();
      EthHeaderModifier eth(packet_metadata.packet);
      IPHeaderModifier ip(packet_metadata.packet);

      auto target_ip = ip.get_ip_src();
      auto target_mac = eth.get_src_mac();

      auto getEntry = routingTable->getRoutingEntry(target_ip);
      auto iface = routingTable->getRoutingInterface(getEntry->iface);

      Packet original_packet = ip.get_packet_copy();
      for (int i = IP_PACKET_SIZE;
           i < IP_PACKET_SIZE + 8; i++)
      {
        original_packet.push_back(packet_metadata.packet[i]);
      }

      auto icmp = create_t3_icmp(Type::T3, Code::C1, original_packet);
      auto ip_packet = create_ip_packet(iface.ip, target_ip,
                                        sr_ip_protocol::ip_protocol_icmp, icmp);
      auto eth_packet = create_ethernet_packet(
          iface.mac, target_mac, sr_ethertype::ethertype_ip, ip_packet);

      spdlog::info("Sending ICMP for failed arp rely");
      eth.print_header();
      EthHeaderModifier eth_packett(eth_packet);
      eth_packett.print_header();
      packetSender->sendPacket(eth_packet, getEntry->iface);
      packets.pop_front();
    }
    spdlog::info("Sent all ICMP for failed arp rely");
  }

  // Adds an awaiting packet. If the request entry does not exist, then we
  // create it
  // void add_awaiting_packet(uint32_t ip, const Packet &packet,
  //                          std::string iface) {

  //   auto packet_metadata = AwaitingPacket();
  //   packet_metadata.packet = packet;
  //   packet_metadata.iface = iface;

  //   if (!requests.count(ip)) {
  //     auto min_time = std::chrono::steady_clock::time_point::min();
  //     requests[ip] = {ip, min_time, 0, {}};
  //   }

  //   requests[ip].awaitingPackets.push_back(packet_metadata);
  // }
};

#endif // ARPCACHE_H
