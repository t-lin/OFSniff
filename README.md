# OFSniff
A library for passively sniffing the OpenFlow connection to get latency information.

## Installing Prerequisites
**Tested in Ubuntu 14.04 and 16.04**

Apt packages:
```
sudo apt-get install git build-essential cmake libpcap-dev libssl-dev \
libboost-dev libboost-regex-dev autoconf libtool pkg-config python-dev
```

OFSniff also depends on two other libraries, _libtins_ and _libfluid_msg_.

Installing _libtins_:
```
git clone https://github.com/mfontanini/libtins.git
cd libtins
git submodule init && git submodule update
echo "set(CMAKE_POSITION_INDEPENDENT_CODE ON)" >> cmake/libtinsConfig.cmake.in
mkdir build && cd build && cmake ../ -DLIBTINS_ENABLE_CXX11=1
make
sudo make install
```

Installing _libfluid_msg_:
```
git clone https://github.com/OpenNetworkingFoundation/libfluid_msg
cd libfluid_msg
./autogen.sh
./configure
make
sudo make install
```

## Compiling _OFSniff_
**Tested in Ubuntu 14.04 and 16.04**

There are three compilation options:
* Stand-alone sniffing program: `make main`
* C++ static library: `make clib`
* Python C++ extension library: `make pylib`

To simply compile all, just use: `make` or `make all`

