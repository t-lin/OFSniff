#include <Python.h>
#include <iostream>
#include <thread>
#include <exception>
#include <string>

// Packet processing libs
#include <tins/tins.h>

// OpenFlow connection processing
#include "OFSniff.h"

using std::cout;
using std::endl;

using namespace Tins;

#define MAX_CAP_LEN 1500 // Standard Ethernet frame length
#define STATS_FILELOG false // TODO: Make cmd-line arg

/* Class to wrap the thread and sniffer objects.
 * This class exists simply so we can use the destructor.
 *
 * When the Python interpreter ends and instances go out-of-scope,
 * we can have a graceful exit and clean-up of the sniff loop.
 */
class ThreadWrapper {
    public:
        std::thread threadHandle;
        Sniffer *sniffer;

        ThreadWrapper() {
            sniffer = nullptr;
        };

        ~ThreadWrapper() {
            if (sniffer) {
                sniffer->stop_sniff();
                threadHandle.join(); // Or use detach? In case thread doesn't stop...
            }
        };
};

// Global objects and handles
static ThreadWrapper threadWrap;
static EndpointLatencyMetadata epLatMeta;

/* Wraps OFSniffLoop to catch any exceptions that may occur.
 * This function can run in its own separate thread.
 * Used to either handle the exceptions or print out the error messages, then
 * gracefully exit the loop without crashing the program.
 */
void OFSniffLoopWrapper(Sniffer*& sniffer, uint16_t ofp_port,
                        EndpointLatencyMetadata& epLatMeta) {
    try {
        OFSniffLoop(sniffer, ofp_port, epLatMeta);
    } catch (const std::exception &ex) {
        // General exception handler for now, until we know of specific cases
        cout << "ERROR: Unexpected exit of OFSniffLoop" << endl;
        cout << ex.what() << endl;
    }

    return;
}

/* Parses argument for "endpoint" keyword
 * Writes parsed value to the "endpoint" output argument
 *
 * Returns true upon success, or false upon failure
 */
bool parseEndpointFromArgs(PyObject *args, PyObject *keywords, IPv4EndpointType& endpoint) {
    static char *kwlist[] = {(char*)"endpoint", NULL};

    // "K" = unsigned long long (aka uint64_t)
    if (!PyArg_ParseTupleAndKeywords(args, keywords, "K", kwlist, &endpoint))
        return false;

    return true;
}


/* ========== EXPOSED MODULE METHODS ========== */

static PyObject* _OFSniff_isSniffing(PyObject *self, PyObject *args) {
    if (threadWrap.sniffer)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

/* Creates new Sniffer and starts sniffing
 * Only starts sniff loop if there's no current sniffer
 */
static PyObject* _OFSniff_startSniffLoop(PyObject *self, PyObject *args, PyObject *keywords) {
    if ( !threadWrap.sniffer ) {
        char* iface = NULL;
        uint16_t ofp_port = 0;

        static char *kwlist[] = {(char*)"iface", (char*)"ofp_port", NULL};

        // "s" = char * (NULL-terminated C-string)
        // "H" = unsigned short (aka uint16_t)
        if (!PyArg_ParseTupleAndKeywords(args, keywords, "sH", kwlist, &iface, &ofp_port))
            cout << "ERROR: Unable to parse input parameters" << endl;

        string filter = "tcp port " + std::to_string(ofp_port);

        // Set sniffer configurations
        SnifferConfiguration sniffConfig;
        sniffConfig.set_filter(filter);
        sniffConfig.set_promisc_mode(false);
        sniffConfig.set_snap_len(MAX_CAP_LEN);
        sniffConfig.set_immediate_mode(true);

        threadWrap.sniffer = new Sniffer(iface, sniffConfig);

        if (threadWrap.sniffer != NULL) {
            try {
                threadWrap.threadHandle = std::thread(OFSniffLoopWrapper,
                                                std::ref(threadWrap.sniffer),
                                                ofp_port,
                                                std::ref(epLatMeta));
            } catch (const std::exception &ex) {
                cout << "ERROR in _OFSniff_startSniffLoop: Thread creation failed" << endl;
                cout << ex.what() << endl;
                Py_RETURN_FALSE;
            }
        }
        else {
            cout << "ERROR in _OFSniff_startSniffLoop: Sniffer allocation failed" << endl;
            Py_RETURN_FALSE;
        }
    } else {
        cout << "ERROR: Sniffing already started. Stop the current sniff loop first if changing sniffing parameters." << endl;
        Py_RETURN_FALSE;
    }

    Py_RETURN_TRUE;
}

static PyObject* _OFSniff_stopSniffLoop(PyObject *self, PyObject *args) {
    if (threadWrap.sniffer) {
        threadWrap.sniffer->stop_sniff();
        threadWrap.threadHandle.join(); // Or use detach? In case the thread doesn't end...

        threadWrap.sniffer = nullptr;
    }

    Py_RETURN_NONE;
}

static PyObject* _OFSniff_getEndpoints(PyObject *self, PyObject *args) {
    PyObject* pyList = PyList_New(0); // Create empty list

    if (threadWrap.sniffer) {
        vector<IPv4EndpointType> endpoints = epLatMeta.getEndpoints();
        if (pyList != NULL) {
            for (IPv4EndpointType ep : endpoints) {
                // "K" = unsigned long long (aka uint64_t)
                if (PyList_Append(pyList, Py_BuildValue("K", ep)) != 0) {
                    cout << "ERROR in _OFSniff_getEndpoints: Unable to append " <<
                        ep << " to Python List" << endl;
                }
            }

        } else {
            cout << "ERROR in _OFSniff_getEndpoints: Unable to create new Python List object" << endl;
        }
    } else {
        cout << "ERROR: No sniff loop started" << endl;
    }

    return pyList;
}

/* Takes one parameter:
 *  - endpoint: unsigned long long value
 *              Representing an endpoint, likely retrieved from getEndpoints()
 */
static PyObject* _OFSniff_getEchoRTTAvg(PyObject *self, PyObject *args, PyObject *keywords) {
    if (threadWrap.sniffer) {
        IPv4EndpointType endpoint = 0;
        if (parseEndpointFromArgs(args, keywords, endpoint))
            // "d" = double
            return Py_BuildValue("d", epLatMeta.getEchoRTTAvg(endpoint));
        else
            cout << "ERROR: Unable to parse input parameters" << endl;
    } else {
        cout << "ERROR: No sniff loop started" << endl;
    }

    Py_RETURN_NONE;
}

/* Takes one parameter:
 *  - endpoint: unsigned long long value
 *              Representing an endpoint, likely retrieved from getEndpoints()
 */
static PyObject* _OFSniff_getEchoRTTVar(PyObject *self, PyObject *args, PyObject *keywords) {
    if (threadWrap.sniffer) {
        IPv4EndpointType endpoint = 0;
        if (parseEndpointFromArgs(args, keywords, endpoint))
            // "d" = double
            return Py_BuildValue("d", epLatMeta.getEchoRTTVar(endpoint));
        else
            cout << "ERROR: Unable to parse input parameters" << endl;
    } else {
        cout << "ERROR: No sniff loop started" << endl;
    }

    Py_RETURN_NONE;
}

/* Takes one parameter:
 *  - endpoint: unsigned long long value
 *              Representing an endpoint, likely retrieved from getEndpoints()
 */
static PyObject* _OFSniff_getEchoRTTMed(PyObject *self, PyObject *args, PyObject *keywords) {
    if (threadWrap.sniffer) {
        IPv4EndpointType endpoint = 0;
        if (parseEndpointFromArgs(args, keywords, endpoint))
            // "d" = double
            return Py_BuildValue("d", epLatMeta.getEchoRTTMed(endpoint));
        else
            cout << "ERROR: Unable to parse input parameters" << endl;
    } else {
        cout << "ERROR: No sniff loop started" << endl;
    }

    Py_RETURN_NONE;
}

/* Takes one parameter:
 *  - endpoint: unsigned long long value
 *              Representing an endpoint, likely retrieved from getEndpoints()
 */
static PyObject* _OFSniff_getPktInRTTAvg(PyObject *self, PyObject *args, PyObject *keywords) {
    if (threadWrap.sniffer) {
        IPv4EndpointType endpoint = 0;
        if (parseEndpointFromArgs(args, keywords, endpoint))
            // "d" = double
            return Py_BuildValue("d", epLatMeta.getPktInRTTAvg(endpoint));
        else
            cout << "ERROR: Unable to parse input parameters" << endl;
    } else {
        cout << "ERROR: No sniff loop started" << endl;
    }

    Py_RETURN_NONE;
}

/* Takes one parameter:
 *  - endpoint: unsigned long long value
 *              Representing an endpoint, likely retrieved from getEndpoints()
 */
static PyObject* _OFSniff_getPktInRTTVar(PyObject *self, PyObject *args, PyObject *keywords) {
    if (threadWrap.sniffer) {
        IPv4EndpointType endpoint = 0;
        if (parseEndpointFromArgs(args, keywords, endpoint))
            // "d" = double
            return Py_BuildValue("d", epLatMeta.getPktInRTTVar(endpoint));
        else
            cout << "ERROR: Unable to parse input parameters" << endl;
    } else {
        cout << "ERROR: No sniff loop started" << endl;
    }

    Py_RETURN_NONE;
}

/* Takes one parameter:
 *  - endpoint: unsigned long long value
 *              Representing an endpoint, likely retrieved from getEndpoints()
 */
static PyObject* _OFSniff_getPktInRTTMed(PyObject *self, PyObject *args, PyObject *keywords) {
    if (threadWrap.sniffer) {
        IPv4EndpointType endpoint = 0;
        if (parseEndpointFromArgs(args, keywords, endpoint))
            // "d" = double
            return Py_BuildValue("d", epLatMeta.getPktInRTTMed(endpoint));
        else
            cout << "ERROR: Unable to parse input parameters" << endl;
    } else {
        cout << "ERROR: No sniff loop started" << endl;
    }

    Py_RETURN_NONE;
}

/* Takes two parameters:
 *  - endpoint: unsigned long long value
 *              Representing an endpoint, likely retrieved from getEndpoints()
 *  - port_no: unsigned short value
 *              Represents the port number of the switch which the link is connected to
 */
static PyObject* _OFSniff_getLinkLatAvg(PyObject *self, PyObject *args, PyObject *keywords) {
    if (threadWrap.sniffer) {
        IPv4EndpointType endpoint = 0;
        uint16_t port_no = 0;

        static char *kwlist[] = {(char*)"endpoint", (char*)"port_no", NULL};

        // "K" = unsigned long long (aka uint64_t)
        // "H" = unsigned short (aka uint16_t)
        if (PyArg_ParseTupleAndKeywords(args, keywords, "KH", kwlist, &endpoint, &port_no))
            return Py_BuildValue("d", epLatMeta.getLinkLatAvg(endpoint, port_no));
        else
            cout << "ERROR: Unable to parse input parameters" << endl;
    } else {
        cout << "ERROR: No sniff loop started" << endl;
    }

    Py_RETURN_NONE;
}

/* Takes two parameters:
 *  - endpoint: unsigned long long value
 *              Representing an endpoint, likely retrieved from getEndpoints()
 *  - port_no: unsigned short value
 *              Represents the port number of the switch which the link is connected to
 */
static PyObject* _OFSniff_getLinkLatVar(PyObject *self, PyObject *args, PyObject *keywords) {
    if (threadWrap.sniffer) {
        IPv4EndpointType endpoint = 0;
        uint16_t port_no = 0;

        static char *kwlist[] = {(char*)"endpoint", (char*)"port_no", NULL};

        // "K" = unsigned long long (aka uint64_t)
        // "H" = unsigned short (aka uint16_t)
        if (PyArg_ParseTupleAndKeywords(args, keywords, "KH", kwlist, &endpoint, &port_no))
            return Py_BuildValue("d", epLatMeta.getLinkLatVar(endpoint, port_no));
        else
            cout << "ERROR: Unable to parse input parameters" << endl;
    } else {
        cout << "ERROR: No sniff loop started" << endl;
    }

    Py_RETURN_NONE;
}

/* Takes two parameters:
 *  - endpoint: unsigned long long value
 *              Representing an endpoint, likely retrieved from getEndpoints()
 *  - port_no: unsigned short value
 *              Represents the port number of the switch which the link is connected to
 */
static PyObject* _OFSniff_getLinkLatMed(PyObject *self, PyObject *args, PyObject *keywords) {
    if (threadWrap.sniffer) {
        IPv4EndpointType endpoint = 0;
        uint16_t port_no = 0;

        static char *kwlist[] = {(char*)"endpoint", (char*)"port_no", NULL};

        // "K" = unsigned long long (aka uint64_t)
        // "H" = unsigned short (aka uint16_t)
        if (PyArg_ParseTupleAndKeywords(args, keywords, "KH", kwlist, &endpoint, &port_no))
            return Py_BuildValue("d", epLatMeta.getLinkLatMed(endpoint, port_no));
        else
            cout << "ERROR: Unable to parse input parameters" << endl;
    } else {
        cout << "ERROR: No sniff loop started" << endl;
    }

    Py_RETURN_NONE;
}

/* Takes one parameter:
 *  - endpoint: unsigned long long value
 *              Representing an endpoint, likely retrieved from getEndpoints()
 */
static PyObject* _OFSniff_getDp2CtrlRTT(PyObject *self, PyObject *args, PyObject *keywords) {
    if (threadWrap.sniffer) {
        IPv4EndpointType endpoint = 0;
        if (parseEndpointFromArgs(args, keywords, endpoint))
            // "d" = double
            return Py_BuildValue("d", epLatMeta.getDp2CtrlRTT(endpoint));
        else
            cout << "ERROR: Unable to parse input parameters" << endl;
    } else {
        cout << "ERROR: No sniff loop started" << endl;
    }

    Py_RETURN_NONE;
}


static PyMethodDef OFSniffMethods[] = {
    {"startSniffLoop", (PyCFunction)_OFSniff_startSniffLoop, METH_VARARGS, "Start sniffing in secondary thread"},
    {"stopSniffLoop", _OFSniff_stopSniffLoop, METH_VARARGS, "Stop sniffing"},
    {"isSniffing", _OFSniff_isSniffing, METH_VARARGS, "Indicates whether the sniff loop has started"},
    {"getEndpoints", (PyCFunction)_OFSniff_getEndpoints, METH_VARARGS, "Get endpoints"},
    {"getEchoRTTAvg", (PyCFunction)_OFSniff_getEchoRTTAvg, METH_VARARGS, "Get the average echo RTT for a given endpoint"},
    {"getEchoRTTVar", (PyCFunction)_OFSniff_getEchoRTTVar, METH_VARARGS, "Get the variance of echo RTT for a given endpoint"},
    {"getEchoRTTMed", (PyCFunction)_OFSniff_getEchoRTTMed, METH_VARARGS, "Get the median of echo RTT for a given endpoint"},
    {"getPktInRTTAvg", (PyCFunction)_OFSniff_getPktInRTTAvg, METH_VARARGS, "Get the average PacketIn RTT for a given endpoint"},
    {"getPktInRTTVar", (PyCFunction)_OFSniff_getPktInRTTVar, METH_VARARGS, "Get the variance of PacketIn RTT for a given endpoint"},
    {"getPktInRTTMed", (PyCFunction)_OFSniff_getPktInRTTMed, METH_VARARGS, "Get the median of PacketIn RTT for a given endpoint"},
    {"getLinkLatAvg", (PyCFunction)_OFSniff_getLinkLatAvg, METH_VARARGS, "Get the average link latency for a given endpoint and port"},
    {"getLinkLatVar", (PyCFunction)_OFSniff_getLinkLatVar, METH_VARARGS, "Get the variance of link latnecy for a given endpoint and port"},
    {"getLinkLatMed", (PyCFunction)_OFSniff_getLinkLatMed, METH_VARARGS, "Get the median of link latnecy for a given endpoint and port"},
    {"getDp2CtrlRTT", (PyCFunction)_OFSniff_getDp2CtrlRTT, METH_VARARGS, "Get the datapath to controller RTT for a given endpoint"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};


PyMODINIT_FUNC init_OFSniff() {
    // Create module and add methods
    Py_InitModule("_OFSniff", OFSniffMethods);
}
