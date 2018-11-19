#ifndef OFSNIFFCOMMON_H
#define OFSNIFFCOMMON_H

#include <iostream>
#include <sys/time.h> // For struct timeval

// Packet processing libs
#include <ifaddrs.h>
#include <netinet/in.h>

// Libtins
#include <tins/tins.h>

using std::string;

using Tins::IPv4Address;
using Tins::Timestamp;

#define MILLION 1000000
#define THOUSAND 1000
#define ETHTYPE_LLDP 0x88cc

// START SAVI LLDP system-dependent macros
#define CHASSIS_ID_DPID_OFFSET 6 // Offsets prefix of string ("dpid:")
#define PACKET_ID_LEN 32
#define SYSTEM_NAME_PREFIX  "SAVI-SDN"
// END SAVI LLDP system-dependent macros

const unsigned char LLDP_MAC_NEAREST_BRIDGE[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};

// Inspired by Tin's TCP_IP Stream Identifier (16 Bytes to accomodate portNum)
typedef uint64_t IPv4EndpointType;

// IPv4Address class overloads uint32_t operator
// So we must use that first, then cast to uint64_t
inline IPv4EndpointType GenIPv4Endpoint(const IPv4Address ipAddr, const uint16_t portNum) {
    return ((uint64_t)((uint32_t)ipAddr) << 16) | portNum;
}

// Calculates difference between request and reply Timestamp values
// Returns in ms granularity
inline double CalcTimestampDiff(const Timestamp& request, const Timestamp& reply) {
    struct timeval elapsed;

    elapsed.tv_sec = reply.seconds() - request.seconds();
    if (reply.microseconds() < request.microseconds()) {
        elapsed.tv_sec--;
        elapsed.tv_usec = MILLION - request.microseconds() + reply.microseconds();
    } else {
        elapsed.tv_usec = reply.microseconds() - request.microseconds();
    }

    return (double)((elapsed.tv_sec * MILLION) + elapsed.tv_usec) / THOUSAND;
}

// From pping (https://github.com/pollere/pping)
// return the local ip address of 'ifname'
// XXX since an interface can have multiple addresses, both IP4 and IP6,
// this should really create a set of all of them and later test for
// membership. But for now we just take the first IP4 address.
inline string localAddrOf(const string ifname)
{
    string local{};
    struct ifaddrs* ifap;

    if (getifaddrs(&ifap) == 0) {
        for (auto ifp = ifap; ifp; ifp = ifp->ifa_next) {
            if (ifname == ifp->ifa_name &&
                  ifp->ifa_addr->sa_family == AF_INET) {
                uint32_t ip = ((struct sockaddr_in*)
                               ifp->ifa_addr)->sin_addr.s_addr;
                local = IPv4Address(ip).to_string();
                break;
            }
        }
        freeifaddrs(ifap);
    }
    return local;
}

#endif
