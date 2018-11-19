#ifndef ENDPOINTLATENCYMETADATA_H
#define ENDPOINTLATENCYMETADATA_H

#include <unordered_map>
#include <fstream>

#include "OFSniffCommon.h"
#include "LatencyMetadata.h"

using std::unordered_map;
using std::endl;

class EndpointLatencyMetadata {
    private:
        /* Window sizes for different measurement samples */
        const uint16_t ECHO_RTT_SAMPLES = 15;
        const uint16_t PKT_IN_RTT_SAMPLES = 60;
        const uint16_t LINK_LAT_SAMPLES = 20;

        /* Maximum outstanding packet IDs per port */
        const uint16_t MAX_OUTSTANDING_PKTS = 20;

        unordered_map<IPv4EndpointType, LatencyMetadata> _endpoint2LatMeta;

        std::ofstream _statsLog;

        double RTTAvg(const vector<double>& vTimes) {
            double sum = 0;
            for (auto i : vTimes)
                sum += i;

            return sum / vTimes.size();
        }

        // Sample (not population) variance
        double RTTVar(const vector<double>& vTimes, const double rttAvg) {
            double sum = 0, diff = 0;
            for (auto i : vTimes) {
                diff = i - rttAvg;
                sum += (diff * diff);
            }

            if (vTimes.size() > 1)
                return sum / (vTimes.size() - 1);
            else
                return 0; // Can't divide by 0, so this is undefined
        }

        /* Updates vTimes structure given the new value newVal
         *
         * sampleAvg and sampleVar contains current avg and variance.
         * The function will calculate updated avg and variance values, and
         * update the sampleAvg and sampleVar parameters.
         */
        void updateStats(vector<double>& vTimes, const uint16_t maxVecSize,
                    const double newVal, double& sampleAvg, double& sampleVar) {

            // SRTT TESTING / DEBUGGING
            //sampleAvg = sampleAvg + SRTT_GAIN * (newVal - sampleAvg);
            //return;
            // END DEBUGGING

            vTimes.push_back(newVal);
            if (vTimes.size() > maxVecSize) {
                double oldestVal = vTimes.front();
                double oldAvg = sampleAvg;

                vTimes.erase(vTimes.begin()); // Keep it bounded
                sampleAvg += (newVal - oldestVal) / maxVecSize;
                sampleVar += (newVal - oldestVal) * (newVal - sampleAvg + oldestVal - oldAvg) / (maxVecSize - 1);

            } else {
                /* If pre-insertion size is less than maxVecSize, then
                 * we shouldn't use simplified rolling update formulas. Do
                 * full calculations from scratch. */
                sampleAvg = RTTAvg(vTimes);
                sampleVar = RTTVar(vTimes, sampleAvg);
            }

            return;
        }

    public:
        EndpointLatencyMetadata();

        ~EndpointLatencyMetadata();

        /* Open statistics log file for writing
         * Function is idempotent
         */
        bool openStatsLog();

        // Returns by ref
        // TODO: Re-evaluate need for this, remove this function when new accessors added
        PacketSeenType& getPacketSeenMap(IPv4EndpointType dpEndpoint);

        void addOutstandingPkt(const IPv4EndpointType dpEndpoint,
                                const uint16_t port_no, const string& packetID);

        void remOutstandingPkt(const IPv4EndpointType dpEndpoint,
                                const uint16_t port_no, const string& packetID);

        void updateEchoRTT(const IPv4EndpointType dpEndpoint, const double rtt);

        void updatePktInRTT(const IPv4EndpointType dpEndpoint, const double rtt);

        void updateLinkLat(const IPv4EndpointType dpEndpoint,
                            const uint16_t port_no, const double latEstimate);

        double getEchoRTTAvg(const IPv4EndpointType dpEndpoint);

        double getEchoRTTVar(const IPv4EndpointType dpEndpoint);

        double getPktInRTTAvg(const IPv4EndpointType dpEndpoint);

        double getPktInRTTVar(const IPv4EndpointType dpEndpoint);

        // TODO: Input should really be a pair of endpoints
        double getLinkLatAvg(const IPv4EndpointType dpEndpoint, const uint16_t port_no);

        // TODO: Input should really be a pair of endpoints
        double getLinkLatVar(const IPv4EndpointType dpEndpoint, const uint16_t port_no);

        vector<IPv4EndpointType> getEndpoints();

        double getDp2CtrlRTT(IPv4EndpointType dpEndpoint);

};


#endif
