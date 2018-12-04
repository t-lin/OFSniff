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
    string ofpPort;

    if (argc == 1) {
        cout << "Usage: " << argv[0] << " <interface name> <openflow listening port number>" << endl;
        exit(0);
    } else if (argc == 2) {
        iface = argv[1];
        if (localAddrOf(iface).empty()) {
            cout << "ERROR: Could not identify interface" << endl;
            exit(1);
        }
    } else {
        iface = argv[1];
        ofpPort = argv[2];

        // Verify that ofpPort is a number
        for (uint32_t i = 0; i < ofpPort.length(); i++) {
            if (!isdigit(ofpPort[i])) {
                cout << "ERROR: Second parameter is not a number" << endl;
                exit(1);
            }
        }

        // Verify ofpPort is a valid port number
        if (stoul(ofpPort) > 65535) {
            cout << "ERROR: Invalid port number (" << ofpPort << " > 65535)" << endl;
            exit(1);
        }
    }

    string filter = "tcp port " + ofpPort;

    SnifferConfiguration config;
    config.set_filter(filter);
    config.set_promisc_mode(false);
    config.set_snap_len(MAX_CAP_LEN);
    config.set_immediate_mode(true);

    try {
        sniffer = new Sniffer(iface, config);
    } catch (const std::exception &ex) {
        cout << "ERROR: Unable to create new Sniffer object" << endl;
        cout << ex.what() << endl;
        exit(1);
    }

    EndpointLatencyMetadata epLatMeta;

    try {
        OFSniffLoop(sniffer, (uint16_t)stoul(ofpPort), epLatMeta);
    } catch (const std::exception &ex) {
        cout << "ERROR: Unexpected exit of OFSniffLoop" << endl;
        cout << ex.what() << endl;
    }

    if (sniffer)
        delete sniffer;

    return 0;
}

