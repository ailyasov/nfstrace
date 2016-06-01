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
#include <vector>
#include <thread>

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
#include <atomic>
#include <condition_variable>

#include "filtration/pcap/base_reader.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{
class CaptureReader;
class PacketRing {
    public:
        PacketRing(CaptureReader& reader);
        ~PacketRing();
        void start_af_packet_capture();

        uint64_t get_received_packets() const { return received_packets; }
        uint64_t get_received_bytes() const { return received_bytes; }
        const tpacket_stats_v3& packet_stats() const { return stats; }
    int packet_socket;
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
    uint64_t received_packets;
    uint64_t received_bytes;
    struct tpacket_stats_v3 stats;
    struct Ring ring;
    CaptureReader& capture_reader;
};

class CaptureReader : public BaseReader
{
friend class PacketRing;
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

    void print_statistic(std::ostream& out) override;

private:
    void fanout_thread();

    pcap_handler callback;
    u_char* user;
    const std::string interface;
    struct sock_fprog filter;
    unsigned int num_cpus;
    bool loop_stopped;
    std::atomic<unsigned int> total_received_packets;
    std::atomic<unsigned int> total_received_bytes;
    std::atomic<unsigned int> total_drops;
    std::condition_variable cv_threads_completed;
    bool threads_completed;
    std::mutex mx;
    std::unique_ptr<BPF> bpf;
};

std::ostream& operator<<(std::ostream&, const CaptureReader::Params&);

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif // CAPTURE_READER_H
//------------------------------------------------------------------------------
