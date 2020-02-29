/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

void
ArpCache::sendQueuedPackets(struct arp_hdr &reply_arp_hdr, uint32_t dest_ip_address)
{
  std::shared_ptr<ArpRequest> request = nullptr;
  for(const auto& entry: m_arpRequests)
    {
      if(entry->ip == dest_ip_address)
        {
          request = entry;
          break;
        }
    }
  
  if (request != nullptr)
    {
      for (const auto& pendingPacket: request->packets)
        {
          int packet_size = pendingPacket.packet.size();
          Buffer curr_packet (packet_size, 0);
          struct ethernet_hdr ether_hdr;
          memcpy(ether_hdr.ether_dhost, &reply_arp_hdr.arp_sha[0], ETHER_ADDR_LEN);
          memcpy(ether_hdr.ether_shost, &reply_arp_hdr.arp_tha[0], ETHER_ADDR_LEN);
          ether_hdr.ether_type = htons(0x0800);
          memcpy(&current_packet[0], &ether_hdr, sizeof(ether_hdr));
          memcpy(&curr_packet[14], &pendingPacket.packet[14], packet_size - sizeof(ether_hdr));
          std::string interfaceName = m_router.getRoutingTable().lookup(dest_ip_address).ifName;
          const Interface* sendInterface = m_router.findIfaceByName(interfaceName);
          m_router.sendPacket(curr_packet, sendInterface->name);

          printf("Pending packet send\n");
          std::cout << "Interface:" << sendInterface->name << std::endl;
          print_hdrs(curr_packet);
        }
       m_arpRequests.remove(request);
    }
}

void
ArpCache::handleArpRequest(std::shared_ptr<ArpRequest> req, bool &isRemoved)
{

    printf("In handleArpRequest\n");
    if(steady_clock::now() - req->timeSent > seconds(1))
    {
      if (req->nTimesSent >= MAX_SENT_TIME)/ // request time out
        {
          printf("Times Sent:%d\n", req->nTimesSent);
          printf("Removing the request\n");
          m_arpRequests.remove(req);
          isRemoved = true;
          return;
        }

      else
        {
          struct arp_hdr arp_header;
          struct ethernet_hdr ether_hdr;
          Buffer request_packet (42, 0); //Sending packet

          std::string interfaceName = m_router.getRoutingTable().lookup(req->ip).ifName;
          const Interface* sendInterface = m_router.findIfaceByName(interfaceName);

          memset(ether_hdr.ether_dhost, 255, ETHER_ADDR_LEN);
          memcpy(ether_hdr.ether_shost, &sendInterface->addr[0], ETHER_ADDR_LEN);
          ether_hdr.ether_type = htons(0x0806);
          printf("Assembled Ethernet\n");
          print_hdr_eth((uint8_t*)&ether_hdr);
          
          arp_header.arp_hrd = htons(0x0001);
          arp_header.arp_pro = htons(0x0800);
          arp_header.arp_hln = 6;
          arp_header.arp_pln = 4;
          arp_header.arp_op = htons(0x0001);
          memcpy(arp_header.arp_sha, &sendInterface->addr[0], ETHER_ADDR_LEN);
          memcpy(&arp_header.arp_sip, &sendInterface->ip, sizeof(arp_header.arp_sip));
          memset(arp_header.arp_tha, 255, ETHER_ADDR_LEN);
          memcpy(&arp_header.arp_tip, &req->ip, sizeof(arp_header.arp_tip));

          printf("Assembled Arp\n");
          print_hdr_arp((uint8_t*)&arp_header);

          memcpy(&request_packet[0], &ether_hdr, sizeof(ether_hdr));
          memcpy(&request_packet[14], &arp_header, sizeof(arp_header));
          m_router.curr_packet(request_packet, sendInterface->name);

          std::cout << "Interface:" << sendInterface->name << std::endl; 
          print_hdrs(request_packet);
          req->timeSent = steady_clock::now();
          req->nTimesSent++;
        }
    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  bool isRemoved = false;
  std::vector<std::shared_ptr<ArpEntry>> recordForRemoval;
      for(const auto& req: m_arpRequests)
        {
          handleArpRequest(req, isRemoved);
          if(isRemoved) //Avoid segfault
            break;
        }

  for(const auto& entry: m_cacheEntries)
    {
      if(!(entry->isValid))
        {
          recordForRemoval.push_back(entry);
        }
    }

  for(const auto& entry: recordForRemoval)
    {
      m_cacheEntries.remove(entry);
    }

}

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
