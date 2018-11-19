#include "LLDP_TLV.h"

#include <iostream>
#include "string.h"

LLDP_TLV::LLDP_TLV() {};

/* LLDP TLV Format:
 * ---------------------------------------------
 * | 7 bits type | 9 bits length | n bits data |
 * ---------------------------------------------
 */
LLDP_TLV::LLDP_TLV(uint8_t* buffer) {
    _type = buffer[0] >> 1;
    _length = ((uint16_t)(buffer[0] & 0x1) << 8) + buffer[1];
    _value = new uint8_t[_length + 1]; // In case this is a string, +1 for NULL char
    _value[_length] = '\0';
    if (_length)
        memcpy(_value, buffer + 2, _length);

    if (_type == 0 || _length == 0)
        // TODO; What if malformed LLDP only has type or length 0, but not both?
        return;
    else
        _next = new LLDP_TLV(buffer + 2 + _length);
};

LLDP_TLV::~LLDP_TLV() {
    if (_value)
        delete []_value;

    if (_next)
        delete _next;
};

uint16_t LLDP_TLV::type() {
    return _type;
};

uint16_t LLDP_TLV::length() {
    return _length;
};

/* Returns pointer (of type VAL_TYPE) to the value
 *  e.g. int *a = someLLDPTLV.pValue<int>();
 */
// VAL_TYPE* LLDP_TLV::pValue() definition in header file

LLDP_TLV* LLDP_TLV::next() {
    return _next;
};

LLDP_TLV& LLDP_TLV::rnext() {
    if (_next)
        return *_next;
    else
        throw std::runtime_error("ERROR: No next TLV in LLDP");
};
