#include <iostream>
#include <signal.h>
//#include <thread>

// Packet processing libs
#include <tins/tins.h>

#include "OFSniff.h"

using std::cout;
using std::endl;
using std::string;
using namespace Tins;

#define MAX_CAP_LEN 1500 // Max Bytes to capture per packet

static Sniffer *sniffer = nullptr;

static void signalHandler(int sigVal) {
    if (sniffer)
        sniffer->stop_sniff();
}

int main(int argc, char *argv[]) {
    // Set up signal catching
    struct sigaction action;
    action.sa_handler = signalHandler;
    action.sa_flags = 0;
    sigemptyset (&action.sa_mask);
    sigaction (SIGINT, &action, NULL);
    sigaction (SIGTERM, &action, NULL);

    string iface;
    string filter;

    if (argc == 1) {
        cout << "Usage: " << argv[0] << " <interface name> \"<optional filter (pcap format)>\"" << endl;
        exit(0);
    } else if (argc == 2) {
        iface = argv[1];
        if (localAddrOf(iface).empty()) {
            cout << "ERROR: Could not identify interface" << endl;
            exit(1);
        }
    } else {
        iface = argv[1];
        filter = argv[2];
    }

    SnifferConfiguration config;
    if (!filter.empty())
        config.set_filter(filter);
    config.set_promisc_mode(false);
    config.set_snap_len(MAX_CAP_LEN);
    config.set_immediate_mode(true);

    sniffer = new Sniffer(iface, config);

    EndpointLatencyMetadata epLatMeta;

    OFSniffLoop(sniffer, epLatMeta);

    //std::thread sniffThread(OFSniffLoop, std::ref(sniffer), std::ref(epLatMeta));

    ///* Wait for thread to terminate.
    // * It likely won't terminate unless it crashes.
    // * Exit gracefully if it does.
    // */
    //sniffThread.join();

    if (sniffer)
        delete sniffer;

    return 0;
}

