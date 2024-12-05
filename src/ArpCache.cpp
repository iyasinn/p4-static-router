#include "ArpCache.h"

#include <chrono>
#include <cstring>
#include <optional>
#include <spdlog/spdlog.h>
#include <thread>

#include "IArpCache.h"
#include "protocol.h"
#include "utils.h"

ArpCache::ArpCache(std::chrono::milliseconds timeout,
                   std::shared_ptr<IPacketSender> packetSender,
                   std::shared_ptr<IRoutingTable> routingTable)
    : timeout(timeout), packetSender(std::move(packetSender)),
      routingTable(std::move(routingTable))
{
  thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache()
{
  shutdown = true;
  if (thread && thread->joinable())
  {
    thread->join();
  }
}

void ArpCache::loop()
{
  while (!shutdown)
  {
    tick();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

void ArpCache::tick()
{
  std::unique_lock lock(mutex);

  for (auto &[ip, arp_request] : requests)
  {

    spdlog::info("ARP Request Check: {}", ip);

    // Is it in the cache
    if (entries.count(ip))
    {
      send_all_packets(ip);
      continue;
    }

    if (!check_one_second_elapsed(ip))
    {
      continue;
    }

    if (arp_request.timesSent >= 7)
    {
      send_all_icmp(ip);
      continue;
    }

    auto iface = get_iface(ip);
    send_arp_request(ip, iface.value());
  }

  // remove ARP Requests that dont have any requests
  std::erase_if(requests, [](const auto &req)
                { return req.second.awaitingPackets.empty(); });

  // Remove entries that have been in the cache for too long
  std::erase_if(entries, [this](const auto &entry)
                { return std::chrono::steady_clock::now() - entry.second.timeAdded >= timeout; });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr &mac)
{
  std::unique_lock lock(mutex);

  // Ignore if we did not issue the request
  if (!requests.count(ip))
  {
    spdlog::info("Ignoring ARP reply addEntry to cache because we did not "
                 "issue a request for IP: {}",
                 ip);
    return;
  }

  entries[ip].ip = ip;
  entries[ip].mac = mac;
  entries[ip].timeAdded = std::chrono::steady_clock::now();
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip)
{
  std::unique_lock lock(mutex);

  if (entries.count(ip))
  {
    return entries[ip].mac;
  }

  return std::nullopt;
}

void ArpCache::queuePacket(uint32_t ip, const Packet &packet,
                           const std::string &iface)
{
  std::unique_lock lock(mutex);

  // * Gateway ip is ip
  spdlog::info("Queing a packet for", ip);
  auto packet_metadata = AwaitingPacket();
  packet_metadata.packet = packet;
  packet_metadata.iface = iface;

  if (!requests.count(ip))
  {
    auto min_time = std::chrono::steady_clock::time_point::min();
    requests[ip] = {ip, min_time, 0, {}};
    requests[ip].awaitingPackets.push_back(packet_metadata);
    send_arp_request(ip, iface);
    return;
  }

  requests[ip].awaitingPackets.push_back(packet_metadata);
}
