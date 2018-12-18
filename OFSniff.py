# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (C) 2018, The SAVI Project.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import os
import errno

# Importing _OFSniff here will create a global instance of the sniffing thread/loop
import _OFSniff

if os.getuid() != 0:
    msg = "ERROR: OFSniff requires root access to sniff"
    #raise EnvironmentError(errno.EPERM, msg)
    print msg
    sys.exit(1)

# Given a numerical endpoint (i.e. those returned by OFSniff.getEndpoints()),
# return an (IP, port #) tuple where the IP is a string, the port is an int
# Endpoint expected to be either a long or an int
def endpointNum2Pair(endpoint):
    assert type(endpoint) in (long, int)
    port = int(endpoint & 0xffff)
    ip = endpoint >> 16 # IP is in network byte-order
    ip = [ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff]
    ip = '.'.join(str(octet) for octet in ip) # Convert to string

    return (ip, port)

# Given an (IP, port #) tuple, return a numerical endpoint
# IP is a string in decimal dot notation (i.e. 10.11.12.13)
# Port can be either a string or integer
def endpointPair2Num(ip, port):
    port = int(port)
    ip = [int(octet) for octet in ip.split('.')]
    ip = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0] # To network byte-order

    endpoint = (ip << 16) | port

    return endpoint


# Class OFSniff to wrap methods to call underlying _OFSniff methods
# Using this as a wrapper class allows the same instance to be passed
# and shared between multiple files with a single import
class OFSniff(object):
    def __init__(self):
        pass

    # If iface is None, OFSniff will sniff all interfaces
    # Returns True if loop successfully started w/ input parameters
    # Returns False otherwise
    def startSniffLoop(self, iface, ofp_port):
        if iface is None:
            iface = "any"

        assert type(iface) in (str, unicode)
        assert type(ofp_port) is int
        assert ofp_port <= 65535

        return _OFSniff.startSniffLoop(iface, ofp_port)

    def stopSniffLoop(self):
        _OFSniff.stopSniffLoop()
        return

    def isSniffing(self):
        return _OFSniff.isSniffing()

    def getEndpoints(self):
        return _OFSniff.getEndpoints()

    def getEchoRTTAvg(self, endpoint):
        assert type(endpoint) in (long, int)
        return _OFSniff.getEchoRTTAvg(endpoint)

    def getEchoRTTVar(self, endpoint):
        assert type(endpoint) in (long, int)
        return _OFSniff.getEchoRTTVar(endpoint)

    def getEchoRTTMed(self, endpoint):
        assert type(endpoint) in (long, int)
        return _OFSniff.getEchoRTTMed(endpoint)

    def getPktInRTTAvg(self, endpoint):
        assert type(endpoint) in (long, int)
        return _OFSniff.getPktInRTTAvg(endpoint)

    def getPktInRTTVar(self, endpoint):
        assert type(endpoint) in (long, int)
        return _OFSniff.getPktInRTTVar(endpoint)

    def getPktInRTTMed(self, endpoint):
        assert type(endpoint) in (long, int)
        return _OFSniff.getPktInRTTMed(endpoint)

    def getLinkLatAvg(self, endpoint, port_no):
        assert type(endpoint) in (long, int)
        assert type(port_no) is int
        return _OFSniff.getLinkLatAvg(endpoint, port_no)

    def getLinkLatVar(self, endpoint, port_no):
        assert type(endpoint) in (long, int)
        assert type(port_no) is int
        return _OFSniff.getLinkLatVar(endpoint, port_no)

    def getLinkLatMed(self, endpoint, port_no):
        assert type(endpoint) in (long, int)
        assert type(port_no) is int
        return _OFSniff.getLinkLatMed(endpoint, port_no)

    def getDp2CtrlRTT(self, endpoint):
        assert type(endpoint) in (long, int)
        return _OFSniff.getDp2CtrlRTT(endpoint)

