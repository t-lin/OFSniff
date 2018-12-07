#include "EndpointLatencyMetadata.h"

EndpointLatencyMetadata::EndpointLatencyMetadata() {};

EndpointLatencyMetadata::~EndpointLatencyMetadata() {
    if ( _statsLog.is_open() )
        _statsLog.close();
};

/* Open statistics log file for writing
 * Function is idempotent
 */
bool EndpointLatencyMetadata::openStatsLog() {
    if ( !_statsLog.is_open() ) {
        time_t     now = time(0);
        struct tm  tstruct;
        char       buf[30];
        tstruct = *localtime(&now);
        strftime(buf, sizeof(buf), "%F.%T.log", &tstruct);

        _statsLog.open(buf, std::ios::out);

        return (_statsLog.is_open() && _statsLog.good());
    }

    return _statsLog.good();
}

// Returns by ref
// TODO: Re-evaluate need for this, remove this function when new accessors added
PacketSeenType& EndpointLatencyMetadata::getPacketSeenMap(IPv4EndpointType dpEndpoint) {
    return _endpoint2LatMeta[dpEndpoint].packetSeen;
}

void EndpointLatencyMetadata::addOutstandingPkt(const IPv4EndpointType dpEndpoint,
                        const uint16_t port_no, const string& packetID) {
    vector<string>& vPacketIDs = _endpoint2LatMeta[dpEndpoint].outstandingPkts[port_no];
    vPacketIDs.push_back(packetID);

    /* Check if outstanding packets over limit. If so, clean up from packetSeen.
     * TODO: Think about if this should be done within this function, or some
     *       other clean-up thread...
     */
    if (vPacketIDs.size() > MAX_OUTSTANDING_PKTS) {
        _endpoint2LatMeta[dpEndpoint].packetSeen.erase(vPacketIDs.front());
        vPacketIDs.erase(vPacketIDs.begin());
    }

}

void EndpointLatencyMetadata::remOutstandingPkt(const IPv4EndpointType dpEndpoint,
                        const uint16_t port_no, const string& packetID) {
    vector<string>& vPacketIDs = _endpoint2LatMeta[dpEndpoint].outstandingPkts[port_no];
    for (auto it = vPacketIDs.begin(); it != vPacketIDs.end(); it++)
        if (*it == packetID) {
            vPacketIDs.erase(it);
            break;
        }
}

void EndpointLatencyMetadata::updateEchoRTT(const IPv4EndpointType dpEndpoint, const double rtt) {
    LatencyMetadata& latMeta = _endpoint2LatMeta[dpEndpoint];
    updateStats(latMeta.echoRTTSamples, ECHO_RTT_WINDOW, rtt,
                latMeta.echoRTTAvg, latMeta.echoRTTVar, latMeta.echoRTTMed);

    if (_statsLog.is_open()) {
        _statsLog << dpEndpoint << " EchoRTT " << rtt << " " <<
            latMeta.echoRTTAvg << " " << latMeta.echoRTTVar << endl;
    }
}

void EndpointLatencyMetadata::updatePktInRTT(const IPv4EndpointType dpEndpoint, const double rtt) {
    LatencyMetadata& latMeta = _endpoint2LatMeta[dpEndpoint];
    updateStats(latMeta.pktInRTTSamples, PKT_IN_RTT_WINDOW, rtt,
                latMeta.pktInRTTAvg, latMeta.pktInRTTVar, latMeta.pktInRTTMed);

    if (_statsLog.is_open()) {
        _statsLog << dpEndpoint << " PktInRTT " << rtt << " " <<
            latMeta.pktInRTTAvg << " " << latMeta.pktInRTTVar << endl;
    }
}

void EndpointLatencyMetadata::updateLinkLat(const IPv4EndpointType dpEndpoint,
                    const uint16_t port_no, const double latEstimate) {
    /* Since the latency estimate is the result of a subtraction operation
     * involving other estimated values, it can potentially be 0. Using medians
     * may potentially result in 0 as well.
     *
     * Thus we use SRTT (aka exponential moving average or low-pass filter) to
     * smooth out the reuslts while avoiding the likelihood of 0.
     *
     * TODO: Consider using DEMA over EMA for faster response time?
     * TODO: Consider some way to adjust coefficient (the 0.125) dynamically?
     */
    LatencyMetadata& epLatMeta = _endpoint2LatMeta[dpEndpoint];
    LinkLatMetadata& linkLatMeta = epLatMeta.linkLatMeta[port_no];
    linkLatMeta.linkLatSRTT = linkLatMeta.linkLatSRTT + \
                             0.125 * (latEstimate - linkLatMeta.linkLatSRTT);

    /* Calculate stats based on SRTT samples */
    updateStats(linkLatMeta.linkLatSamples, LINK_LAT_WINDOW, linkLatMeta.linkLatSRTT,
                linkLatMeta.linkLatAvg, linkLatMeta.linkLatVar, linkLatMeta.linkLatMed);

    if (_statsLog.is_open()) {
        _statsLog << dpEndpoint << " LinkLatRTT-Port" << port_no <<
            " " << latEstimate << " " << linkLatMeta.linkLatAvg <<
            " " << linkLatMeta.linkLatVar << endl;
    }
}

double EndpointLatencyMetadata::getEchoRTTAvg(const IPv4EndpointType dpEndpoint) {
    return _endpoint2LatMeta[dpEndpoint].echoRTTAvg;
}

double EndpointLatencyMetadata::getPktInRTTAvg(const IPv4EndpointType dpEndpoint) {
    return _endpoint2LatMeta[dpEndpoint].pktInRTTAvg;
}

double EndpointLatencyMetadata::getEchoRTTVar(const IPv4EndpointType dpEndpoint) {
    return _endpoint2LatMeta[dpEndpoint].echoRTTVar;
}

double EndpointLatencyMetadata::getPktInRTTVar(const IPv4EndpointType dpEndpoint) {
    return _endpoint2LatMeta[dpEndpoint].pktInRTTVar;
}

double EndpointLatencyMetadata::getEchoRTTMed(const IPv4EndpointType dpEndpoint) {
    return _endpoint2LatMeta[dpEndpoint].echoRTTMed;
}

double EndpointLatencyMetadata::getPktInRTTMed(const IPv4EndpointType dpEndpoint) {
    return _endpoint2LatMeta[dpEndpoint].pktInRTTMed;
}

// TODO: Input should really be a pair of endpoints
double EndpointLatencyMetadata::getLinkLatAvg(const IPv4EndpointType dpEndpoint, const uint16_t port_no) {
    return _endpoint2LatMeta[dpEndpoint].linkLatMeta[port_no].linkLatAvg;
}

// TODO: Input should really be a pair of endpoints
double EndpointLatencyMetadata::getLinkLatVar(const IPv4EndpointType dpEndpoint, const uint16_t port_no) {
    return _endpoint2LatMeta[dpEndpoint].linkLatMeta[port_no].linkLatVar;
}

// TODO: Input should really be a pair of endpoints
double EndpointLatencyMetadata::getLinkLatMed(const IPv4EndpointType dpEndpoint, const uint16_t port_no) {
    return _endpoint2LatMeta[dpEndpoint].linkLatMeta[port_no].linkLatMed;
}

vector<IPv4EndpointType> EndpointLatencyMetadata::getEndpoints() {
    vector<IPv4EndpointType> keys;
    for (auto it : _endpoint2LatMeta)
        keys.push_back(it.first);

    return keys;
}

double EndpointLatencyMetadata::getDp2CtrlRTT(IPv4EndpointType dpEndpoint) {
     // Total datapath to controller latencies
    //return _endpoint2LatMeta[dpEndpoint].echoRTTAvg + _endpoint2LatMeta[dpEndpoint].pktInRTTMed;
    return _endpoint2LatMeta[dpEndpoint].echoRTTMed + _endpoint2LatMeta[dpEndpoint].pktInRTTMed;
}

