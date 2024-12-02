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
      routingTable(std::move(routingTable)) {
  thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
  shutdown = true;
  if (thread && thread->joinable()) {
    thread->join();
  }
}

void ArpCache::loop() {
  while (!shutdown) {
    tick();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

void ArpCache::tick() {
  std::unique_lock lock(mutex);
  for (auto &[ip, arp_request] : requests) {

    // Is it in the cache
    if (getEntry(ip) != std::nullopt) {
      send_all_packets(ip);
      continue;
    }

    if (check_if_arp_failed(ip)) {
      send_all_icmp(ip);
      continue;
    }

    auto iface = get_iface(ip);

    // todo: check if this is valid behavior
    // if (iface == std::nullopt){
    //     send_all_icmp(ip);
    //     continue;
    // }

    send_arp_request(ip, iface.value());
  }

  // remove ARP Requests that dont have any requests
  std::erase_if(requests, [](const auto &req) {
    return req.second.awaitingPackets.size() > 0;
  });

  // Remove entries that have been in the cache for too long
  std::erase_if(entries, [this](const auto &entry) {
    return std::chrono::steady_clock::now() - entry.second.timeAdded >= timeout;
  });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr &mac) {
  std::unique_lock lock(mutex);

  // Ignore if we did not issue the request
  if (!requests.count(ip)) {
    return;
  }


  entries[ip].ip = ip;
  entries[ip].mac = mac;
  entries[ip].timeAdded = std::chrono::steady_clock::now();
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
  std::unique_lock lock(mutex);

  if (entries.count(ip)) {
    return entries[ip].mac;
  }

  return std::nullopt;
}

void ArpCache::queuePacket(uint32_t ip, const Packet &packet,
                           const std::string &iface) {
  std::unique_lock lock(mutex);

  if (getEntry(ip) != std::nullopt) {
    EthPacketHeader eth(packet);
    eth.update_dst_mac(getEntry(ip).value());
    packetSender->sendPacket(packet, iface);
    return;
  }

  add_awaiting_packet(ip, packet, iface);
}
