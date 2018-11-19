#!/usr/bin/python
# Parses log file from OFSniff into separate files per (endpoint ID, metric) pair
# Output file formats are in CSV
import sys
import time

if len(sys.argv) != 2:
    print "ERROR: Incorrect # of args"
    print "Usage: logParse.py <OFSniff log file>"
    sys.exit();
else:
    data_file = sys.argv[1]

f = open(data_file, "r")

fileHandleMap = {} # Maps (epid, metric) to file handle

# Log file line format: <endpoint ID> <metric> <data> <avg> <variance>
#   Example: 1099520009516 PktInRTT 0.504 0.504 0
#
# NOTE: Lines end with new-line character
# NOTE: endpoint ID denotes a unique OpenFlow connection
#       It's a unique switch, but it's not the same as the DPID
for line in f:
    epid, metric, data, avg, var = line.split()

    keyTuple = (epid, metric)
    if keyTuple not in fileHandleMap.keys():
        # Open file in append mode, in case file w/ same name already exists
        fileHandleMap[keyTuple] = open("%s-%s.csv" % keyTuple, "a")

        # Write a header at start of each file
        # Also used as delimiter in case appending to existing file
        fileHandleMap[keyTuple].write("Data,Average,Variance\n")

    fileHandleMap[keyTuple].write("%s,%s,%s\n" % (data, avg, var))

# Close file handles
f.close()
for key, fh in fileHandleMap.items():
    fh.close()
