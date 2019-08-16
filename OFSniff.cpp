#include <iostream>

// Packet processing libs
#include <ifaddrs.h>
#include <netinet/in.h>
#include <tins/tins.h>

// OpenFlow processing libs
#include <fluid/of10msg.hh>

#include "OpenFlowPDUs.h"
#include "OFSniffCommon.h"
#include "EndpointLatencyMetadata.h"
#include "LLDP_TLV.h"

using std::cout;
using std::endl;
using std::string;
using namespace Tins;

//#define PRINTOUT // For debugging
#define STATS_FILELOG false // TODO: Make into argument

/* bool bPacketIn
 *  true if intercepting an OpenFlow PacketIn (switch => ctrl)
 *  false if intercepting an OpenFlow PacketOut (ctrl => switch)
 */
void ProcessLLDP(Timestamp ts, IPv4EndpointType dpEndpoint, EthernetII& ethFrame,
                        EndpointLatencyMetadata& epLatMeta, bool bPacketIn) {
    if (ethFrame.payload_type() != ETHTYPE_LLDP) {
        cout << "ERROR: Unknown eth type: " << ethFrame.payload_type() << endl;
        return;
    }

    if (ethFrame.dst_addr() != LLDP_MAC_NEAREST_BRIDGE) {
        cout << "ERROR: Unknown dest MAC" << endl;
        return;
    }

    RawPDU* lldp = ethFrame.find_pdu<RawPDU>(); // libtins lacks an LLDP PDU
    if (lldp == nullptr) {
        cout << "ERROR: Could not find LLDP PDU in Ethernet frame" << endl;
        return;
    }

    //uint64_t datapath_id = 0;
    uint32_t port_no = 0; // NOTE: OpenFlow 1.0 has 16-bit long port #'s
    string packetID;
    double dp2CtrlRTT = 0; // "RTT" parsed from packets

    LLDP_TLV firstTLV = LLDP_TLV(lldp->payload().data()); // Creates linked list of TLVs
    for (LLDP_TLV* tlv = &firstTLV; tlv->next() != nullptr; tlv = tlv->next()) {
        switch (tlv->type()) {
            case LLDP_TLV_TYPE::CHASSIS_ID: {
                //datapath_id = std::stoull(tlv->pValue<char>() + CHASSIS_ID_DPID_OFFSET,
                //                            nullptr, 16); /* Offset for SAVI Ryu's LLDP ChassisID format
                //                                           * TODO: Make this vendor-neutral somehow */
                //cout << "Source dpid is: " << std::hex << datapath_id << endl;
                break;
            }
            case LLDP_TLV_TYPE::PORT_ID: {
                // Port ID TLV value has 1 Byte port subtype, then the port ID itself
                // NOTE: Ryu stores the port ID in network-order; must convert to host-order
                port_no = *((uint32_t*)(tlv->pValue<uint8_t>() + 1)); // Skip 1 Byte port subtype
                port_no = ntohl(port_no);
                break;
            }
            case LLDP_TLV_TYPE::TTL:
                // Currently not used
                // TODO: Implement this?
                break;
            case LLDP_TLV_TYPE::SYSTEM_NAME: {
                string sysName = tlv->pValue<char>();
                if (sysName.find(SYSTEM_NAME_PREFIX) != 0) {
                    cout << "WARNING: Received LLDP w/ system name: " << sysName << endl;
                    packetID = "";
                } else {
                    uint64_t firstSemiCol = sysName.find_first_of(';');
                    uint64_t lastSemiCol = sysName.find_last_of(';');
                    if (firstSemiCol != string::npos && firstSemiCol != lastSemiCol) {
                        packetID = sysName.substr(firstSemiCol + 1, PACKET_ID_LEN);
                        dp2CtrlRTT = stod(sysName.substr(lastSemiCol + 1));
                    } else {
                        // Malformed System Name, abort processing of this packet
                        cout << "ERROR: Malformed System Name field" << endl;
                        return;
                    }
                }
                break;
            }
            default:
                // Do nothing
                // TODO: Print error message?
                break;
        }
    }

    /* Four scenarios to consider:
     *  1) Incoming PacketIn is Ping (Two sub-scenarios)
     *      - This could be for measuring link latency, or for measuring
     *        the controller's connection + table processing latency
     *      - If the port TLV is OFPP_MAX, it is for connection + table latency
     *      - Else, it is for actual link latency measurement
     *          - Start timing until PacketOut Pong (#4 scenario) is received
     *  2) Incoming PacketIn is Pong
     *      - Calculate time difference since PacketOut Ping (#3 scenario),
     *        and subtract remote connection + processing delay (TODO, how to do this?)
     *  3) Outgoing PacketOut is Ping
     *      - Start timing until PacketIn Pong (#2 scenario) is received
     *  4) Outgoing PacketOut is Pong
     *      - Calculate time difference since PacketInPing (#1 scenario),
     *        this is the controller's processing time
     *
     *  The logic above works well when there's 1 controller per switch.
     *  If multiple switches are connected to the same controller, it will break.
     *      - Consider case of a PacketOut Ping, we note the time we first observed
     *        this packetID. When the Ping reaches other switch, it becomes a
     *        PacketIn Ping, but we've already begun tracking this packetID.
     *  Thus, we must have a per-switch tracking of when packets are seen.
     */
    PacketSeenType& pktSeenMap = epLatMeta.getPacketSeenMap(dpEndpoint);
    bool isPing = (!dp2CtrlRTT) ? true : false; // Just to improve readability...

    if (bPacketIn) {
        if (isPing) {
            // Scenario 1 above (PacketIn, Ping)

            /* An TLV port of OFPP_MAX has a special meaning in SAVI's Ryu LLDP design
             * Used for timing the OpenFlow connection + table processing
             */
            if (port_no == of10::OFPP_MAX) {
                auto pktSeenIt = pktSeenMap.find(packetID);
                if (pktSeenIt != pktSeenMap.end()) {
                    Timestamp reqTs = pktSeenIt->second;
                    pktSeenMap.erase(pktSeenIt);
                    epLatMeta.remOutstandingPkt(dpEndpoint, port_no, packetID);

                    double echoRTT = CalcTimestampDiff(reqTs, ts);
                    epLatMeta.updateEchoRTT(dpEndpoint, echoRTT);
#ifdef PRINTOUT
                    //cout << dpEndpoint << " Ctrl <=> Switch LLDP Echo latency: " << echoRTT << " ms" << endl;
                    cout << dpEndpoint << " Ctrl <=> Switch LLDP Echo MED is: " <<
                            epLatMeta.getEchoRTTMed(dpEndpoint) << " ms; stdev = " <<
                            sqrt(epLatMeta.getEchoRTTVar(dpEndpoint)) << endl;
#endif
                }
            } else {
                // For link latency measurement
                pktSeenMap[packetID] = ts;
                epLatMeta.addOutstandingPkt(dpEndpoint, port_no, packetID);
            }


            // FOR DEBUGGING
            /*
            IPv4EndpointType otherEndpoint = 0;
            for (IPv4EndpointType key : epLatMeta.getEndpoints()) {
                //cout << "endpoint: " << key << endl; // FOR DEBUGGING
                if (key != dpEndpoint)
                    otherEndpoint = key;
            }

            if (otherEndpoint) {
                PacketSeenType& otherPktSeen = epLatMeta.getPacketSeenMap(otherEndpoint);
                auto pktSeenIt = otherPktSeen.find(packetID);

                if (pktSeenIt != pktSeenMap.end()) {
                    Timestamp reqTs = pktSeenIt->second;
                    double switch2switch = CalcTimestampDiff(reqTs, ts);
                    cout << "PING SWITCH TO SWITCH IS: " << switch2switch << " ms" << endl;
                }
            } */
            // END DEBUGGING

        } else {
            // Scenario 2 above (PacketIn, Pong)
            auto pktSeenIt = pktSeenMap.find(packetID);
            if (pktSeenIt != pktSeenMap.end()) {
                Timestamp reqTs = pktSeenIt->second;
                pktSeenMap.erase(pktSeenIt);
                epLatMeta.remOutstandingPkt(dpEndpoint, port_no, packetID);

                double rtt = CalcTimestampDiff(reqTs, ts);

                // Calculate elapsed time between when packet first seen at one
                // switch, and when it appears at a neighbouring switch
                double estimatedLat = rtt - epLatMeta.getEchoRTTMed(dpEndpoint) - dp2CtrlRTT;
                if (estimatedLat < 0)
                    // Sometimes estimate is less than 0... Set to 0? Or ignore?
                    estimatedLat = 0;

                epLatMeta.updateLinkLat(dpEndpoint, port_no, estimatedLat);

                // FOR DEBUGGING: Gets remote connection's switch <=> controller RTT by
                //                accessing epLatMeta directly (ignores parsed dp2CtrlRTT)
                /*
                IPv4EndpointType otherEndpoint = 0;
                for (IPv4EndpointType key : epLatMeta.getEndpoints()) {
                    //cout << "endpoint: " << key << endl; // FOR DEBUGGING
                    if (key != dpEndpoint)
                        otherEndpoint = key;
                }

                if (otherEndpoint) {
                    double estimatedLat = rtt - epLatMeta.getEchoRTTMed(dpEndpoint) -
                                            epLatMeta.getDp2CtrlRTT(otherEndpoint);
                    if (estimatedLat < 0)
                        // Sometimes estimate is less than 0... Set to 0? Or ignore?
                        estimatedLat = 0;
                    epLatMeta.updateLinkLat(dpEndpoint, port_no, estimatedLat);
#ifdef PRINTOUT
                    //cout << "... Dp2CtrlRTT of other endpoint: " << epLatMeta.getDp2CtrlRTT(otherEndpoint) << " ms" << endl;
                    //cout << "... EchoRTT of this endpoint: " << epLatMeta.getEchoRTTMed(dpEndpoint) <<
                    //        " ms ; stdev = " << sqrt(epLatMeta.getEchoRTTVar(dpEndpoint)) << endl;
#endif
                }
                */
                // END DEBUGGING

#ifdef PRINTOUT
                cout << "... Dp2CtrlRTT of other endpoint: " << dp2CtrlRTT << " ms" << endl;
                cout << "... Estimated link RTT: " << estimatedLat << " ms" << endl;
                cout << "... Average link RTT: " << epLatMeta.getLinkLatAvg(dpEndpoint, port_no) <<
                        " ms ; stdev = " << sqrt(epLatMeta.getLinkLatVar(dpEndpoint, port_no)) << endl;
                cout << "... Median link RTT: " << epLatMeta.getLinkLatMed(dpEndpoint, port_no) << endl;
                cout << dpEndpoint << " LLDP REMOTE CONTROLLER ping-pong (pktId: " << packetID << ") elapsed time: " << rtt << " ms" << endl;
#endif
            }
        }
    } else {
        // PacketOut
        if (isPing) {
            // Scenario 3 above (PacketOut, Ping)
            pktSeenMap[packetID] = ts;
            epLatMeta.addOutstandingPkt(dpEndpoint, port_no, packetID);
        } else {
            // Scenario 4 above (PacketOut, Pong)
            auto pktSeenIt = pktSeenMap.find(packetID);
            if (pktSeenIt != pktSeenMap.end()) {
                Timestamp reqTs = pktSeenIt->second;
                pktSeenMap.erase(pktSeenIt);
                epLatMeta.remOutstandingPkt(dpEndpoint, port_no, packetID);

                double rtt = CalcTimestampDiff(reqTs, ts);

                epLatMeta.updatePktInRTT(dpEndpoint, rtt);
#ifdef PRINTOUT
                cout << dpEndpoint << " PKT IN RTT MED (pktId: " << packetID << ") elapsed time: " <<
                    epLatMeta.getPktInRTTMed(dpEndpoint) << " ms; stdev = " << sqrt(epLatMeta.getPktInRTTVar(dpEndpoint)) << endl;
#endif
            }
        }
    }

    return;
}

/* TODO: THIS HAS BEEN DEPRECATED, REMOVE?
 * Processes OpenFlow Echo Request and Replies
 * Measures RTT to-and-from switch when echos are initiated by the controller
 */
void ProcessEcho(Timestamp ts, IPv4EndpointType dpEndpoint, OFMsgPDU& ofMsg,
                        EndpointLatencyMetadata& epLatMeta, bool toSwitch) {
    /* Map datapath endpoint to vector of echo times
     * NOTE: Currently if switch re-connects, it'll get a new endpoint (new source port)
     *       Should we track across re-connections?
     *       We can do this if we intercept Hello messages, but this assumes
     *       we're already sniffing when switch connects.
     *       For now, ignore re-connects.
     */
    static PacketSeenType pktIDSeen; /* Don't need to worry about different switches here
                                      * Echo request & replies only to/from switch */

    switch (ofMsg.type()) {
        case of10::OFPT_ECHO_REQUEST: {
            // Currently only process for echo requests initiated by the controller
            if (!toSwitch)
                break;

            //cout << "Echo Request" << endl;
            of10::EchoRequest echoReq;
            echoReq.unpack((uint8_t*)ofMsg.get_buffer().data());

            string packetID = string((const char*)echoReq.data(), echoReq.data_len());
            pktIDSeen[packetID] = ts;
            break;
        }
        case of10::OFPT_ECHO_REPLY: {
            // Currently only process for echo requests initiated by the controller
            if (toSwitch)
                break;

            //cout << "Echo Reply" << endl;
            of10::EchoReply echoRep;
            echoRep.unpack((uint8_t*)ofMsg.get_buffer().data());

            string packetID = string((const char*)echoRep.data(), echoRep.data_len());
            double echoRTT = CalcTimestampDiff(pktIDSeen[packetID], ts);
            pktIDSeen.erase(packetID);

            epLatMeta.updateEchoRTT(dpEndpoint, echoRTT);
#ifdef PRINTOUT
            cout << dpEndpoint << " Echo RTT MED is: " << epLatMeta.getEchoRTTMed(dpEndpoint) << " ms; stdev = " << sqrt(epLatMeta.getEchoRTTVar(dpEndpoint)) << endl;
#endif
            break;
        }
        default:
            cout << "ERROR: Message type not OpenFlow Echo Request or Reply" << endl;
            return;
    }

    return;
}

void ParseOFPacket(Timestamp ts, IPv4EndpointType dpEndpoint, OFMsgPDU& ofMsg,
                    EndpointLatencyMetadata& epLatMeta, bool toSwitch) {
    switch (ofMsg.type()) {
        case of10::OFPT_PACKET_IN: {
            //cout << "OpenFlow PacketIn from port " << packetIn.in_port() << endl;
            // Convert generic OFMsgPDU to OFPacketInPDU
            of10::PacketIn packetIn;
            packetIn.unpack((uint8_t*)ofMsg.get_buffer().data());
            EthernetII ethFrame((const uint8_t*)packetIn.data(), packetIn.total_len());

            ProcessLLDP(ts, dpEndpoint, ethFrame, epLatMeta, true);
            break;
        }
        case of10::OFPT_PACKET_OUT: {
            //cout << "OpenFlow PacketOut" << endl;
            // Convert generic OFMsgPDU to OFPacketOutPDU
            of10::PacketOut packetOut;
            if (packetOut.unpack((uint8_t*)ofMsg.get_buffer().data()) == OF_ERROR) {
                cout << "ERROR: Unable to parse PacketOut message" << endl;
            }
            else {
                if (packetOut.buffer_id() == of10::OFP_NO_BUFFER) {
                    EthernetII ethFrame((const uint8_t*)packetOut.data(),
                                                    packetOut.data_len());

                    ProcessLLDP(ts, dpEndpoint, ethFrame, epLatMeta, false);
                }
            }
            break;
        }
        case of10::OFPT_FLOW_MOD: {
            //cout << "OpenFlow FlowMod" << endl;
            break;
        }
        case of10::OFPT_ECHO_REQUEST:
        case of10::OFPT_ECHO_REPLY: {
            ProcessEcho(ts, dpEndpoint, ofMsg, epLatMeta, toSwitch);
            break;
        }
        default:
            if (ofMsg.type() <= of10::OFPT_QUEUE_GET_CONFIG_REPLY)
                cout << "Unimplemented OF message type: " << (uint16_t)ofMsg.type() << endl;
            else
                cout << "Unknown OF message type: " << (uint16_t)ofMsg.type() << endl;
            break;
    }

    return;
}

/* OFSniffLoop is currently explicitly designed to not catch exceptions, as
 * different users may wish to handle different exceptions in their own way.
 */
void OFSniffLoop(Sniffer*& sniffer, uint16_t ofp_port,
                    EndpointLatencyMetadata& epLatMeta) {
    if (STATS_FILELOG && !epLatMeta.openStatsLog()) {
        cout << "ERROR: Unable to open statistics log for writing" << endl;
        exit(1);
    }

    bool toSwitch = false; // Is message to the switch?
    string pduType; // Used for debugging
    IPv4EndpointType dpEndpoint;
    for (auto packet = sniffer->begin(); packet != sniffer->end(); packet++) {

        if (const IP *ip = packet->pdu()->find_pdu<IP>()) {
            pduType = "IP";
            if (ip->flags() == 1) {
                cout << "ERROR: Currently do not support packets w/ IPv4's More Fragments flag set" << endl;
                continue;
            }

            // Right now, assume only TCP & UDP above IP
            if (const TCP *tcp = packet->pdu()->find_pdu<TCP>()) {
                pduType = "TCP";

                // Sanity-check connection to controller
                if (tcp->dport() == ofp_port || tcp->sport() == ofp_port) {
                    const RawPDU *raw = packet->pdu()->find_pdu<RawPDU>();
                    if (raw != nullptr) {
                        pduType = "OpenFlow packet";
                        toSwitch = (tcp->sport() == ofp_port) ? true : false;
                        dpEndpoint = toSwitch ?
                                GenIPv4Endpoint(ip->dst_addr(), tcp->dport()) :
                                GenIPv4Endpoint(ip->src_addr(), tcp->sport());

                        OFMsgPDU ofMsg = raw->to<OFMsgPDU>();

                        ParseOFPacket(packet->timestamp(), dpEndpoint, ofMsg, epLatMeta, toSwitch);
                    }
                } else {
                    cout << "ERROR: Packet doesn't seem to be related to the OpenFlow connection" << endl;
                }
            } else if (packet->pdu()->find_pdu<UDP>()) {
                pduType = "UDP";
            } else {
                pduType += "(Unknown transport protocol)";
            }
        } else {
            pduType = "Unknown";
        }

    }

    return;
}
