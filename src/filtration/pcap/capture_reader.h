//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class for capturing network packets and pass them to filtration.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef CAPTURE_READER_H
#define CAPTURE_READER_H
//------------------------------------------------------------------------------
#include <ostream>

#include <pcap/pcap.h>


#include "filtration/pcap/capture_reader.h"
#include "filtration/pcap/bpf.h"

#include <unistd.h>
#include <iostream>
#include <memory>
#include <sys/mman.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <utils/log.h>
#include <cstring>
#include <thread>

#include "filtration/pcap/base_reader.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

class PacketRing {
    public:
        PacketRing(const std::string&, const std::string&);
        ~PacketRing();
        void start_af_packet_capture(void* user, pcap_handler callback);
        void break_loop();

        uint64_t get_received_packets() const { return received_packets; }
        uint64_t get_received_bytes() const { return received_bytes; }
        const tpacket_stats_v3& packet_stats() const { return stats; }
        pcap_t* get_handle() const { return handle; }
    private:
        struct Ring {
            struct iovec *rd;
            uint8_t *mapped_buffer;
            /* This structure is defined in /usr/include/linux/if_packet.h and establishes a
            circular buffer (ring) of unswappable memory. */
            struct tpacket_req3 req;
        };

    int setup_socket(const std::string& interface_name, int fanout_group_id);
    void walk_block(struct block_desc *pbd/*, const int block_num*/);
    u_char* user;
    pcap_handler callback;
    uint64_t received_packets;
    uint64_t received_bytes;
    const std::string& filter;
    bool loop_stopped;
    int packet_socket;
    struct tpacket_stats_v3 stats;
    struct Ring ring; 
    pcap_t*           handle;
}; 

class CaptureReader : public BaseReader
{
public:
    enum class Direction : int
    {
        INOUT,
        IN,
        OUT,
    };

    struct Params
    {
        std::string interface{};
        std::string filter{};
        int         snaplen{0};
        int         timeout_ms{0};
        int         buffer_size{0};
        bool        promisc{true};
        Direction   direction{Direction::INOUT};
    };

    virtual bool loop(void* user, pcap_handler callback, int count = 0);
    virtual void break_loop();

    CaptureReader(const Params& params);
    ~CaptureReader() = default;

    void print_statistic(std::ostream& out) const override;

private:
    PacketRing packet_ring;
};

std::ostream& operator<<(std::ostream&, const CaptureReader::Params&);

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif // CAPTURE_READER_H
//------------------------------------------------------------------------------
