#include "RoutingTable.h"
#include "IRoutingTable.h"

#include <_types/_uint32_t.h>
#include <arpa/inet.h>
#include <fstream>
#include <spdlog/spdlog.h>
#include <sstream>

RoutingTable::RoutingTable(const std::filesystem::path &routingTablePath) {
  if (!std::filesystem::exists(routingTablePath)) {
    throw std::runtime_error("Routing table file does not exist");
  }

  std::ifstream file(routingTablePath);
  if (!file.is_open()) {
    throw std::runtime_error("Failed to open routing table file");
  }

  std::string line;
  while (std::getline(file, line)) {
    if (line.empty()) {
      continue;
    }

    std::istringstream iss(line);
    std::string dest, gateway, mask, iface;
    iss >> dest >> gateway >> mask >> iface;

    uint32_t dest_ip, gateway_ip, subnet_mask;

    if (inet_pton(AF_INET, dest.c_str(), &dest_ip) != 1 ||
        inet_pton(AF_INET, gateway.c_str(), &gateway_ip) != 1 ||
        inet_pton(AF_INET, mask.c_str(), &subnet_mask) != 1) {
      spdlog::error("Invalid IP address format in routing table file: {}",
                    line);
      throw std::runtime_error(
          "Invalid IP address format in routing table file");
    }

    routingEntries.push_back({dest_ip, gateway_ip, subnet_mask, iface});
  }
}

std::optional<RoutingEntry> RoutingTable::getRoutingEntry(ip_addr ip) {

  RoutingEntry LCM_routing_entry = routingEntries[0];
  int LCM_size = 0;

  for (RoutingEntry entry : routingEntries) {

    uint32_t masked_entry_addr = entry.dest & entry.mask;
    uint32_t masked_dest_addr = ip & entry.mask;

    int length = 0;

    for (int i = 0; i < 32; i++) {

      int shift = (31 - i);

      // Reached the end of the msak
      if (((entry.mask >> shift) & 1) == 0) {
        break;
      }

      // If bits match
      if (((masked_entry_addr >> shift) & 1) !=
          ((masked_dest_addr >> shift) & 1)) {
        break;
      }

      length += 1;
    }

    if (length > LCM_size) {
      LCM_size = length;
      LCM_routing_entry = entry;
    }
  }

  return LCM_size == 0 ? std::nullopt
                       : std::optional<RoutingEntry>(LCM_routing_entry);
}

RoutingInterface RoutingTable::getRoutingInterface(const std::string &iface) {
  return routingInterfaces.at(iface);
}

void RoutingTable::setRoutingInterface(const std::string &iface,
                                       const mac_addr &mac, const ip_addr &ip) {
  routingInterfaces[iface] = {iface, mac, ip};
}

const std::unordered_map<std::string, RoutingInterface> &
RoutingTable::getRoutingInterfaces() const {
  return routingInterfaces;
}
