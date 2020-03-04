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

//////////////////////////////////////////////////////////////////////////

void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // create the broadcast address. 
  uint8_t broadcast_mac[ETHER_ADDR_LEN]; 
  for (int i=0; i < ETHER_ADDR_LEN; i++) 
     broadcast_mac[i] = 0xFF; 

  for (auto iter = m_arpRequests.begin(); iter != m_arpRequests.end(); ) {
    auto request = *iter; 

    /* Remove requests that have timed out */

    if (request->nTimesSent >= MAX_SENT_TIME) {
      std::cerr << "-x- -x- -x- ARP REQUEST SENT TOO MANY TIMES -x- -x- -x-\n"; 
      iter = m_arpRequests.erase(iter);
      continue; // don't increment the iterator; we've deleted an entry. 
    }

    /* Construct and Send an ARP request */

    // construct ethernet header. 
    ethernet_hdr arp_request_ether_header;
    const Interface *source_interface = m_router.findIfaceByName(request->packets.front().iface);
    memcpy(arp_request_ether_header.ether_shost, source_interface->addr.data(), ETHER_ADDR_LEN);
    memcpy(arp_request_ether_header.ether_dhost, broadcast_mac, ETHER_ADDR_LEN); 
    arp_request_ether_header.ether_type = htons(ethertype_arp);

    // construct arp header. 
    arp_hdr arp_request_header = {
        htons(arp_hrd_ethernet),
        htons(ethertype_ip),
        ETHER_ADDR_LEN,
        sizeof(uint32_t),
        htons(arp_op_request)
    };
    memcpy(arp_request_header.arp_sha, source_interface->addr.data(), ETHER_ADDR_LEN);
    arp_request_header.arp_sip = source_interface->ip;
    memcpy(arp_request_header.arp_tha, broadcast_mac, ETHER_ADDR_LEN); 
    arp_request_header.arp_tip = request->ip;

    // assemble outbound packet. 
    const size_t arp_response_min_size = sizeof(ethernet_hdr) + sizeof(arp_hdr);
    uint8_t response_raw[arp_response_min_size];
    memcpy(response_raw, &arp_request_ether_header, sizeof(ethernet_hdr));
    memcpy(response_raw + sizeof(ethernet_hdr), &arp_request_header, sizeof(arp_hdr));
    Buffer curr_arp_packet(response_raw, response_raw + arp_response_min_size);

    // send the packet. 
    m_router.sendPacket(curr_arp_packet, source_interface->name);

    std::cerr << "<-- <-- <-- ETHERNET REQUEST --> --> -->" << std::endl;
    print_hdr_eth(curr_arp_packet.data());
    std::cerr << "<-- <-- <-- ARP REQUEST --> --> -->" << std::endl;
    print_hdr_arp(curr_arp_packet.data() + sizeof(ethernet_hdr));

    // update the queued request's data. 
    request->timeSent = std::chrono::steady_clock::now();
    request->nTimesSent++;

    iter++; // only increment the iterator when we didn't delete an entry. 
  }

  // remove invalid cache entries.
  for (auto iter = m_cacheEntries.begin(); iter != m_cacheEntries.end(); ) {
    if (!(*iter)->isValid) {
      iter = m_cacheEntries.erase(iter);
      continue;
    }
    iter++;
  }
}

//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

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

/* vim:set expandtab shiftwidth=2 textwidth=79: */
