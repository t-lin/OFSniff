#ifndef LATENCYMETADATA_H
#define LATENCYMETADATA_H

#include <vector>
#include <unordered_map>

#include <tins/tins.h>

using std::unordered_map;
using std::string;
using std::vector;

using Tins::Timestamp;

// Maps packet IDs to Timestamps when they were first seen
typedef unordered_map<string, Timestamp> PacketSeenType;

typedef struct LinkLatMetadata {
    vector<double> linkLatSamples;
    double linkLatAvg;
    double linkLatVar;
    double linkLatSRTT;
    double linkLatMed;
} LinkLatMetadata;

/* Each instance of LatencyMetadata tracks data related to a single switch */
typedef struct LatencyMetadata {
    PacketSeenType packetSeen;

    /* Tracks per-port outstanding packet IDs.
     * Outstanding packets may occur if controller sends LLDPs out of ports
     * that are conected to hosts or other switches that don't understand
     * our LLDP-based link latency discovery protocol.
     */
    unordered_map<uint16_t, vector<string>> outstandingPkts;

    vector<double> echoRTTSamples;
    double echoRTTAvg;
    double echoRTTVar;
    double echoRTTMed;

    /* PacketIn RTT = Time from PacketIn Ping to PacketOut Pong */
    vector<double> pktInRTTSamples;
    double pktInRTTAvg;
    double pktInRTTVar;
    double pktInRTTMed;

    /* Tracks per-port link latency metadata.
     * Link latency samples over a window, sample average, and sample variance.
     */
    unordered_map<uint16_t, LinkLatMetadata> linkLatMeta;
} LatencyMetadata;


#endif
