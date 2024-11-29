#ifndef STATICROUTER_H
#define STATICROUTER_H
#include <cstdint>
#include <vector>
#include <memory>
#include <mutex>

#include "IArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"
#include "RouterTypes.h"


class StaticRouter {
public:
    StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                 std::shared_ptr<IPacketSender> packetSender);

    /**
     * @brief Handles an incoming packet, telling the switch to send out the necessary packets.
     * @param packet The incoming packet.
     * @param iface The interface on which the packet was received.
     */
    void handlePacket(std::vector<uint8_t> packet, std::string iface);

private:
    std::mutex mutex;

    std::shared_ptr<IRoutingTable> routingTable;
    std::shared_ptr<IPacketSender> packetSender;

    std::unique_ptr<IArpCache> arpCache;


    std::optional<RoutingInterface> getRoutingInterfaceWithIp(ip_addr ip){
        for (auto& [iface, interface] : routingTable->getRoutingInterfaces()){
            if (interface.ip == ip){
                return interface;
            }
        }
        return std::nullopt;
    }


    std::vector<uint8_t> generate_arp_reply_packet(){

        return std::vector<uint8_t>();

    }

};


#endif //STATICROUTER_H
