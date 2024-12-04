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

    if (getEntry(ip) != std::nullopt)
    {
      while (!packets.empty())
      {
        auto packet_metadata = packets.front();
        packetSender->sendPacket(packet_metadata.packet, packet_metadata.iface);
        packets.pop_front();
      }
    }
  }

  // checks if arp has failed our conditions and send icmp
  bool check_if_arp_failed(uint32_t ip)
  {

    auto &request = requests[ip];

    auto one_second = std::chrono::seconds(1);
    auto curr_time = std::chrono::steady_clock::now();

    return request.timesSent >= 7 &&
           (curr_time - request.lastSent) > one_second;
  }

  void send_all_icmp(uint32_t ip)
  {
    auto &packets = requests[ip].awaitingPackets;

    // ICMPPacket icmp(ICMPPacket::Type::T3)

    if (getEntry(ip) != std::nullopt)
    {
      while (!packets.empty())
      {
        auto packet_metadata = packets.front();

        // Need to generate an ICMP message
        // packetSender->sendPacket(packet_metadata.packet,
        // packet_metadata.iface);
        packets.pop_front();
      }
    }
  }

  // Adds an awaiting packet. If the request entry does not exist, then we
  // create it
  void add_awaiting_packet(uint32_t ip, const Packet &packet,
                           std::string iface)
  {

    auto packet_metadata = AwaitingPacket();
    packet_metadata.packet = packet;
    packet_metadata.iface = iface;

    if (!requests.count(ip))
    {
      auto min_time = std::chrono::steady_clock::time_point::min();
      requests[ip] = {ip, min_time, 0, {}};
    }

    requests[ip].awaitingPackets.push_back(packet_metadata);
  }
};

#endif // ARPCACHE_H
