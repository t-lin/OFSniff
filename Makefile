MKFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
LIBTINS = $(HOME)/libtins
CPPFLAGS += -Iinclude -I$(LIBTINS)/include
LDFLAGS += -L$(LIBTINS)/lib -ltins -lpcap -lfluid_msg
CXXFLAGS += -std=c++14 -O3 -Wall -pthread -fPIC
EXENAME = OFSniff

all: main clib

main: build/main.o build/OFSniff.o build/EndpointLatencyMetadata.o build/LLDP_TLV.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $^ -o $(EXENAME) $(LDFLAGS)

build/OFSniff.o: OFSniff.cpp include/OFSniff.h include/OFSniffCommon.h include/EndpointLatencyMetadata.h include/OpenFlowPDUs.h include/LLDP_TLV.h
	mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

build/LLDP_TLV.o: LLDP_TLV.cpp include/LLDP_TLV.h
	mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

build/EndpointLatencyMetadata.o: EndpointLatencyMetadata.cpp include/EndpointLatencyMetadata.h
	mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

build/main.o: main.cpp include/OFSniff.h include/OFSniffCommon.h
	mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

clib: build/OFSniff.o build/EndpointLatencyMetadata.o build/LLDP_TLV.o
	mkdir -p build
	ar rcs build/lib$(EXENAME).a $^

pylib: CPPFLAGS += -I/usr/include/python2.7
pylib: py-OFSniff.cpp clib
	mkdir -p $(MKFILE_DIR)build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -DNDEBUG -g -fwrapv -fno-strict-aliasing -Wdate-time -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Werror=format-security -c $< -o $(MKFILE_DIR)build/py_OFSniff.o
	$(CXX) $(CXXFLAGS) -g -shared -Wl,-O1 -Wl,-Bsymbolic-functions -Wl,-Bsymbolic-functions -Wl,-z,relro -fno-strict-aliasing -DNDEBUG -fwrapv -Wstrict-prototypes -Wdate-time -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Werror=format-security $(MKFILE_DIR)build/py_OFSniff.o -L$(MKFILE_DIR)build -lOFSniff $(LDFLAGS) -o $(MKFILE_DIR)build/py_OFSniff.so

debug: CXXFLAGS += -g
debug: all

profile: CXXFLAGS += -pg
profile: all

clean:
	rm -f $(EXENAME)
	rm -rf build/*

