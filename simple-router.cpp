/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
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

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>




namespace simple_router {

static bool isMacOfInterest(const uint8_t* mac, const Interface& inputIface);

//////////////////////////////////////////////////////////////////////////

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " 
    << inIface << std::endl;

  /* Sanity check our packet */

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    fprintf(stderr, "Received packet, but interface is unknown, ignoring\n"); 
    return;
  }

  if (packet.size() < sizeof(ethernet_hdr)) {
    fprintf(stderr, "Received packet, but header is truncated, ignoring\n"); 
    return;
  }

  /* Parse the ethernet header */

  const uint8_t *raw_packet = packet.data(); 
  ethernet_hdr *eth_hdr = (ethernet_hdr *) raw_packet; 

  if (!isMacOfInterest(eth_hdr->ether_dhost, *iface)) {
    fprintf(stderr, "Received packet, but isn't addressed to router, "
        "ignoring\n"); 
    return; 
  }

  /* Handle the ethernet packet based on its type */

  uint16_t eth_type = ntohs(eth_hdr->ether_type); 

  if (eth_type == ethertype_arp) {
     handle_arp_packet(raw_packet + sizeof(ethernet_hdr), iface,
         eth_hdr->ether_shost); 

  } else if (eth_type == ethertype_ip) { 
    // TODO: merge in IP code. 
    // handle_ip_packet(raw_packet + sizeof(ethernet_hdr), iface); 

  } else { 
    fprintf(stderr, "Received packet, but type is unknown, ignoring\n"); 
    return; 
  }
}


void SimpleRouter::handle_arp_packet(uint8_t* arp_data, Interface* in_iface,
    uint8_t* src_mac)
{
  const arp_hdr* arp_h = (const arp_hdr *) arp_data; 

  // don't handle non-ethernet requests. 
  if (ntohs(arp_h->arp_hrd) != arp_hrd_ethernet) 
     return; 

  uint16_t arp_op_type = ntohs(arp_h->arp_op); 

  if (arp_op_type == arp_op_request) { 

    /* Handle ARP requests */

    // if the arp request isn't for us, we can exit. 
    if (arp_h->arp_tip != in_iface->ip)
       return; 

    // prepare an output buffer for the response. 
    int output_buf_size = sizeof(ethernet_hdr) + sizeof(arp_hdr); 
    uint8_t output_buf[output_buf_size]; 

    // copy in the ethernet header fields. 
    ethernet_hdr *output_eth_h = (ethernet_hdr *) output_buf; 
    output_eth_h->ether_type = htons(ethertype_arp); 
    memcpy(output_eth_h->ether_dhost, src_mac, ETHER_ADDR_LEN); 
    memcpy(output_eth_h->ether_shost, in_iface->addr.data(), ETHER_ADDR_LEN); 

    // copy in the ARP header information. 
    arp_hdr *output_arp_h = (arp_hdr *) (output_buf + sizeof(ethernet_hdr)); 
    memcpy(output_arp_h, arp_h, sizeof(arp_hdr)); // copy in all fields
    output_arp_h->arp_op = htons(arp_op_reply); 
    output_arp_h->arp_tip = arp_h->arp_sip; 
    memcpy(output_arp_h->arp_tha, arp_h->arp_sha, ETHER_ADDR_LEN); 
    output_arp_h->arp_sip = in_iface->ip; 
    memcpy(output_arp_h->arp_sha, in_iface->addr.data(), ETHER_ADDR_LEN); 

    // send the packet
    Buffer output_vec(output_buf, output_buf + output_buf_size); 
    sendPacket(output_vec, in_iface->name); 

  } else if (arp_op_type == arp_op_reply) { 

    /* Handle ARP replies */

    // extract information from the ARP header. 
    uint32_t arp_source_ip = arp_h->arp_sip; // TODO: byte order? confirm. 
    Buffer arp_source_mac; 
    for (int i=0; i < ETHER_ADDR_LEN; i++) 
      arp_source_mac.push_back(arp_h->arp_sha[i]); 

    // record the information to our ARP cache, and retrieve the packets
    // associated with the requests. 
    std::shared_ptr<ArpRequest> request = 
      m_arp.insertArpEntry(arp_source_mac, arp_source_ip); 

    // send out the queued outbound packets waiting on our ARP request. 
    for (auto pending_packet: request->packets) { 
      // add the newly-discovered destination MAC to the outbound packets. 
      ethernet_hdr *eth_h = (ethernet_hdr *) pending_packet.packet.data(); 
      memcpy(eth_h->ether_dhost, arp_source_mac.data(), ETHER_ADDR_LEN); 

      sendPacket(pending_packet.packet, pending_packet.iface); 
    }
      
    // remove our now_fulfilled ARP request from the queue. 
    m_arp.removeRequest(request); 

  } else { 
    // don't handle undocumented ARP packet types. 
    return; 
  }
}


/* 
 * returns true if the given MAC address is either 
 * a) addressed to the broadcast MAC address. 
 * b) addressed to the given router interface. 
 * TODO: verify; do we have to check through *all* our interfaces?
 */
static bool isMacOfInterest(const uint8_t* mac, const Interface& inputIface)
{
  uint8_t broadcast_mac[ETHER_ADDR_LEN]; 
  for (int i=0; i < ETHER_ADDR_LEN; i++) 
     broadcast_mac[i] = 0xFFU; 
  
  if (memcmp(mac, broadcast_mac, ETHER_ADDR_LEN) == 0)
     return true; 

  return memcmp(mac, inputIface.addr.data(), ETHER_ADDR_LEN) == 0;
}


//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {

/* vim:set expandtab shiftwidth=2 textwidth=79: */
