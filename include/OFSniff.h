#ifndef OFSNIFF_H
#define OFSNIFF_H

// Packet processing libs
#include <tins/tins.h> // Libtins

#include "OpenFlowPDUs.h"
#include "OFSniffCommon.h"
#include "EndpointLatencyMetadata.h"

using Tins::Sniffer;
using Tins::EthernetII;
using Tins::Timestamp;

/* bool bPacketIn
 *  true if intercepting an OpenFlow PacketIn (switch => ctrl)
 *  false if intercepting an OpenFlow PacketOut (ctrl => switch)
 */
void ProcessLLDP(Timestamp ts, IPv4EndpointType dpEndpoint, EthernetII& ethFrame,
                        EndpointLatencyMetadata& epLatMeta, bool bPacketIn);

/* Processes OpenFlow Echo Request and Replies
 * Measures RTT to-and-from switch when echos are initiated by the controller
 */
void ProcessEcho(Timestamp ts, IPv4EndpointType dpEndpoint, OFMsgPDU& ofMsg,
                        EndpointLatencyMetadata& epLatMeta, bool toSwitch);

void ParseOFPacket(Timestamp ts, IPv4EndpointType dpEndpoint, OFMsgPDU& ofMsg,
                    EndpointLatencyMetadata& epLatMeta, bool toSwitch);

/* OFSniffLoop is currently explicitly designed to not catch exceptions, as
 * different users may wish to handle different exceptions in their own way.
 */
void OFSniffLoop(Sniffer*& sniffer, uint16_t ofp_port,
                    EndpointLatencyMetadata& epLatMeta);

#endif
