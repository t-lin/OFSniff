#ifndef OPENFLOWPDUS_H
#define OPENFLOWPDUS_H

#include <iostream>
#include <vector>

// Tins packet processing libs
#include <tins/tins.h>

// OpenFlow processing libs
#include <fluid/of10msg.hh>

using std::cout;
using std::endl;
using std::vector;

using Tins::PDU;

/* NOTE: Currently provides PDU definitions based on OpenFlow 1.0 */
using fluid_msg::OFMsg;
using namespace fluid_msg;

/* OpenFlow Message (Stores entire message)
 * Only provides methods for reading headers
 * Can use buffer data to create specific types of OpenFlow messages
 */

// NOTE: Not just header, it's Header + Message
class OFMsgPDU : public PDU, public OFMsg {
    public:

        /*
         * Unique protocol identifier. For user-defined PDUs, you **must**
         * use values greater or equal to PDU::USER_DEFINED_PDU;
         */
        static const PDU::PDUType pdu_flag = PDU::USER_DEFINED_PDU;
        //static const PDU::PDUType pdu_flag;

        /*
         * Constructor from buffer. This constructor will be called while
         * sniffing packets, whenever a PDU of this type is found.
         *
         * The "data" parameter points to a buffer of length "sz".
         */
        OFMsgPDU(const uint8_t* data, uint32_t sz) : OFMsg(0, 0),
                                                     buffer_(data, data + sz) {
            // Initialize OFMsg w/ 0's for now, unpack will fix that
            // Have to do this since libfluid's OFMsg has no default constructor
            // Save a copy of data into buffer_, for later parsing
            if (data != nullptr && sz != 0) {
                uint32_t res = this->unpack((uint8_t*)data);
                if (res != 0) {
                    cout << "ERROR during OFMsgPDU constructor from buffer w/ size " << sz << endl;
                }
            }
        }

        /*
         * Clones the PDU. This method is used when copying PDUs.
         */
        OFMsgPDU* clone() const {
            return new OFMsgPDU(*this);
        }

        /*
         * Retrieves the size of this PDU.
         */
        uint32_t header_size() const {
            /* NOTE: Not just header, it's Header + Message
             * TODO: Separate class into OF header and individual OF messages?
             *       This may be difficult, considering libfluid_msg uses
             *       inheritence to combine PDUs and SDUs together...
             */
            return (uint32_t)this->length_;
        }

        /*
         * This method must return pdu_flag.
         */
        PDUType pdu_type() const {
            return pdu_flag;
        }

        /*
         * Serializes the PDU. The serialization output should be written
         * to the buffer pointed to by "data", which is of size "sz". The
         * "sz" parameter will be equal to the value returned by
         * OFMsgPDU::header_size.
         *
         * Note that before libtins 4.0, there would be an extra
         * const PDU* parameter after "sz" which would contain the parent
         * PDU. On libtins 4.0 this parameter was removed as you can get
         * the parent PDU by calling PDU::parent_pdu()
         */
        void write_serialization(uint8_t *data, uint32_t sz) {
            if (sz > (uint32_t)this->length_) {
                cout << "ERROR write_serialization sz greater than total_len_" << endl;
                return;
            }
            std::memcpy(data, buffer_.data(), sz);
        }

        // This is just a getter to retrieve the buffer member.
        const vector<uint8_t>& get_buffer() const {
            return buffer_;
        }

    private:
        vector<uint8_t> buffer_; /* This is needed just to satisfy Tins PDU.
                                       * libfluid_msg's OFMsg doesn't save the buffer.
                                       */
};



// ============================================================================

/* Primarily uses data_ field inherited from libfluid
 * The buffer_ field from Tins is just a vector object version of data_
 *   - Implementation must be careful to maintain this when data_ changes
 */
class OFPacketInPDU : public PDU, public of10::PacketIn {
    public:
        /*
         * Unique protocol identifier. For user-defined PDUs, you **must**
         * use values greater or equal to PDU::USER_DEFINED_PDU;
         */
        static const PDU::PDUType pdu_flag = PDU::USER_DEFINED_PDU;

        /*
         * Constructor from buffer. This constructor will be called while
         * sniffing packets, whenever a PDU of this type is found.
         *
         * The "data" parameter points to a buffer of length "sz".
         */
        OFPacketInPDU(const uint8_t* data, uint32_t sz) : buffer_(data, data + sz) {
            if (data != nullptr && sz != 0) {
                uint32_t res = this->unpack((uint8_t*)data);
                if (res != 0) {
                    cout << "ERROR during OFPacketInPDU constructor from buffer w/ size " << sz << endl;
                }
            }
        }

        /*
         * Clones the PDU. This method is used when copying PDUs.
         */
        OFPacketInPDU* clone() const {
            return new OFPacketInPDU(*this);
        }

        /*
         * Retrieves the size of this PDU.
         */
        uint32_t header_size() const {
            return this->length_;
        }

        /*
         * This method must return pdu_flag.
         */
        PDUType pdu_type() const {
            return pdu_flag;
        }
        /*
         * Serializes the PDU. The serialization output should be written
         * to the buffer pointed to by "data", which is of size "sz". The
         * "sz" parameter will be equal to the value returned by
         * OFPacketInPDU::header_size.
         *
         * Note that before libtins 4.0, there would be an extra
         * const PDU* parameter after "sz" which would contain the parent
         * PDU. On libtins 4.0 this parameter was removed as you can get
         * the parent PDU by calling PDU::parent_pdu()
         */
        void write_serialization(uint8_t *data, uint32_t sz) {
            if (sz > (uint32_t)this->length_) {
                cout << "ERROR write_serialization sz greater than total_len_" << endl;
                return;
            }
            std::memcpy(data, this->data_, sz); // For PacketIn
        }

        // This is just a getter to retrieve the buffer member.
        const vector<uint8_t>& get_buffer() const {
            return buffer_;
            //return move(vector<uint8_t>((uint8_t*)this->data_, (uint8_t*)this->data_ + this->total_len_));
        }

    private:
        vector<uint8_t> buffer_;
};



// ============================================================================

/* Uses both buffer_ field from Tins and data_ field from libfluid
 *
 * buffer_ field: Holds raw data of entire PDU
 * data_ field: Holds packet data (only valid when buffer_id = -1)
 */
class OFPacketOutPDU : public PDU, public of10::PacketOut {
    public:
        /*
         * Unique protocol identifier. For user-defined PDUs, you **must**
         * use values greater or equal to PDU::USER_DEFINED_PDU;
         */
        static const PDU::PDUType pdu_flag = PDU::USER_DEFINED_PDU;

        /*
         * Constructor from buffer. This constructor will be called while
         * sniffing packets, whenever a PDU of this type is found.
         *
         * The "data" parameter points to a buffer of length "sz".
         */
        OFPacketOutPDU(const uint8_t* data, uint32_t sz) : buffer_(data, data + sz) {
            if (data != nullptr && sz != 0) {
                uint32_t res = this->unpack((uint8_t*)data);
                if (res != 0) {
                    cout << "ERROR during OFPacketOutPDU constructor from buffer w/ size " << sz << endl;
                }
            }
        }

        /*
         * Clones the PDU. This method is used when copying PDUs.
         */
        OFPacketOutPDU* clone() const {
            return new OFPacketOutPDU(*this);
        }

        /*
         * Retrieves the size of this PDU.
         */
        uint32_t header_size() const {
            return this->length_;
        }

        /*
         * This method must return pdu_flag.
         */
        PDUType pdu_type() const {
            return pdu_flag;
        }
        /*
         * Serializes the PDU. The serialization output should be written
         * to the buffer pointed to by "data", which is of size "sz". The
         * "sz" parameter will be equal to the value returned by
         * OFPacketOutPDU::header_size.
         *
         * Note that before libtins 4.0, there would be an extra
         * const PDU* parameter after "sz" which would contain the parent
         * PDU. On libtins 4.0 this parameter was removed as you can get
         * the parent PDU by calling PDU::parent_pdu()
         */
        void write_serialization(uint8_t *data, uint32_t sz) {
            if (sz > (uint32_t)this->length_) {
                cout << "ERROR write_serialization sz greater than total_len_" << endl;
                return;
            }
            std::memcpy(data, buffer_.data(), sz);
        }

        // This is just a getter to retrieve the buffer member.
        // NOTE: This has nothing to do with PacketOut's buffer_id field
        const vector<uint8_t>& get_buffer() const {
            return buffer_;
            //return move(vector<uint8_t>((uint8_t*)this->data_, (uint8_t*)this->data_ + this->data_len_));
        }

    private:
        vector<uint8_t> buffer_;
};


#endif
