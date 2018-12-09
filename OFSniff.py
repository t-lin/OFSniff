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

__all__ = ('startSniffLoop', 'stopSniffLoop',
            'isSniffing', 'getEndpoints',
            'getEchoRTTAvg', 'getEchoRTTVar', 'getEchoRTTMed',
            'getPktInRTTAvg', 'getPktInRTTVar', 'getPktInRTTMed',
            'getLinkLatAvg', 'getLinkLatVar', 'getLinkLatMed',
            'getDp2CtrlRTT',)


# If iface is None, OFSniff will sniff all interfaces
# Returns True if loop successfully started w/ input parameters
# Returns False otherwise
def startSniffLoop(iface, ofp_port):
    if iface is None:
        iface = "any"

    assert type(iface) in (str, unicode)
    assert type(ofp_port) is int
    assert ofp_port <= 65535

    return _OFSniff.startSniffLoop(iface, ofp_port)

def stopSniffLoop():
    _OFSniff.stopSniffLoop()
    return

def isSniffing():
    return _OFSniff.isSniffing()

def getEndpoints():
    return _OFSniff.getEndpoints()

def getEchoRTTAvg(endpoint):
    assert type(endpoint) in (long, int)
    return _OFSniff.getEchoRTTAvg(endpoint)

def getEchoRTTVar(endpoint):
    assert type(endpoint) in (long, int)
    return _OFSniff.getEchoRTTVar(endpoint)

def getEchoRTTMed(endpoint):
    assert type(endpoint) in (long, int)
    return _OFSniff.getEchoRTTMed(endpoint)

def getPktInRTTAvg(endpoint):
    assert type(endpoint) in (long, int)
    return _OFSniff.getPktInRTTAvg(endpoint)

def getPktInRTTVar(endpoint):
    assert type(endpoint) in (long, int)
    return _OFSniff.getPktInRTTVar(endpoint)

def getPktInRTTMed(endpoint):
    assert type(endpoint) in (long, int)
    return _OFSniff.getPktInRTTMed(endpoint)

def getLinkLatAvg(endpoint, port_no):
    assert type(endpoint) in (long, int)
    assert type(port_no) is int
    return _OFSniff.getLinkLatAvg(endpoint, port_no)

def getLinkLatVar(endpoint, port_no):
    assert type(endpoint) in (long, int)
    assert type(port_no) is int
    return _OFSniff.getLinkLatVar(endpoint, port_no)

def getLinkLatMed(endpoint, port_no):
    assert type(endpoint) in (long, int)
    assert type(port_no) is int
    return _OFSniff.getLinkLatMed(endpoint, port_no)

def getDp2CtrlRTT(endpoint):
    assert type(endpoint) in (long, int)
    return _OFSniff.getDp2CtrlRTT(endpoint)
