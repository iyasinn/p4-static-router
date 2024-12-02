#ifndef STATICROUTER_H
#define STATICROUTER_H
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "IArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"
#include "RouterTypes.h"

class StaticRouter {
public:
  StaticRouter(std::unique_ptr<IArpCache> arpCache,
               std::shared_ptr<IRoutingTable> routingTable,
               std::shared_ptr<IPacketSender> packetSender);

  /**
   * @brief Handles an incoming packet, telling the switch to send out the
   * necessary packets.
   * @param packet The incoming packet.
   * @param iface The interface on which the packet was received.
   */
  void handlePacket(std::vector<uint8_t> packet, std::string iface);

private:
  std::mutex mutex;

  std::shared_ptr<IRoutingTable> routingTable;
  std::shared_ptr<IPacketSender> packetSender;

  std::unique_ptr<IArpCache> arpCache;

  void handle_ip(Packet packet, const std::string &iface);

  void handle_arp(Packet packet, const std::string &iface);

  void handle_arp_request(Packet packet, const std::string &iface);

  void handle_arp_reply(Packet packet, const std::string &iface);
};

#endif // STATICROUTER_H
