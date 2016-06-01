//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Capture packets from NIC by libpcap.
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
#include <signal.h>
#include <arpa/inet.h> // inet_ntop
#include <algorithm>
#include "filtration/pcap/capture_reader.h"

//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

// 4194304 bytes
constexpr static unsigned int blocksiz = 1 << 22;
// 2048 bytes
constexpr static unsigned int framesiz = 1 << 11;
constexpr static unsigned int blocknum = 64;

struct block_desc 
{
    uint32_t version;
    uint32_t offset_to_priv;
    struct tpacket_hdr_v1 h1;
};

struct pfring_pkthdr {
    /* pcap header */
    struct timeval ts; /* time stamp */
    u_int32_t caplen; /* length of portion present */
    u_int32_t len; /* length of whole packet (off wire) */
};

PacketRing::PacketRing(CaptureReader& reader):
    capture_reader{reader}
{
    memset(&ring, 0, sizeof(ring));
    //A socket selects a group by
    //encoding the ID in the first 16 bits of the integer option value.
    int fanout_group_id = getpid() & 0xffff;
    setup_socket(capture_reader.interface, fanout_group_id);
}

PacketRing::~PacketRing()
{
    close(packet_socket);
    munmap(ring.mapped_buffer, ring.req.tp_block_size * ring.req.tp_block_nr);
    free(ring.rd);
}

CaptureReader::CaptureReader(const Params& params)
        : BaseReader{params.interface},
          interface{params.interface},
          threads_completed{false}
{
    this->num_cpus = std::thread::hardware_concurrency();
    char ebuf[PCAP_ERRBUF_SIZE];

    const char* device = interface.c_str();
    handle = pcap_create(device, ebuf);
    if(handle == NULL)
    {
        throw PcapError("pcap_create", ebuf);
    }
    bpf_u_int32 localnet, netmask = 0;
    if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0)
    {
        throw PcapError("pcap_lookupnet", ebuf);
    }

    int status = pcap_activate(handle);
    if(status < 0)
    {
        throw PcapError("pcap_activate", ebuf);
    }

    this->bpf = std::unique_ptr<BPF>(new BPF(handle, params.filter.c_str(), netmask));
    bpf_program* bpf_prg = *bpf;
    filter = { (unsigned short) bpf_prg->bf_len, (struct sock_filter *) bpf_prg->bf_insns };
}

void PacketRing::walk_block(struct block_desc *pbd/*, const int block_num*/)
{
    int num_pkts = pbd->h1.num_pkts, i;
    unsigned long bytes = 0;
    struct tpacket3_hdr *ppd;

    ppd = (struct tpacket3_hdr *) ((uint8_t *) pbd + pbd->h1.offset_to_first_pkt);
    for (i = 0; i < num_pkts; ++i)
    {
        bytes += ppd->tp_snaplen;

        struct pfring_pkthdr packet_header;
        memset(&packet_header, 0, sizeof(packet_header));
        packet_header.len = ppd->tp_snaplen;
        packet_header.caplen = ppd->tp_snaplen;

        u_char* data_pointer = (u_char*)((uint8_t *) ppd + ppd->tp_mac);
        pcap_pkthdr pkthdr;
        pkthdr.caplen = packet_header.caplen;
        pkthdr.len = packet_header.len;
        pkthdr.ts = packet_header.ts;

        capture_reader.callback(capture_reader.user, &pkthdr, data_pointer);

        ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd + ppd->tp_next_offset);
    }

    received_packets += num_pkts;
    received_bytes += bytes;
}

// Get interface number by name
static int get_interface_number_by_device_name(int socket_fd, std::string interface_name){
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    if (interface_name.size() > IFNAMSIZ)
    {
        return -1;
    }

    strncpy(ifr.ifr_name, interface_name.c_str(), sizeof(ifr.ifr_name));

    // get interface index
    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) == -1)
    {
        return -1;
    }

    return ifr.ifr_ifindex;
}

static void flush_block(struct block_desc *pbd)
{
    pbd->h1.block_status = TP_STATUS_KERNEL;
}

int PacketRing::setup_socket(const std::string& interface_name, int fanout_group_id)
{

    // creation of the capture socket
    this->packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    LOG("setup_socket packet_socket: %d", this->packet_socket);

    if (this->packet_socket == -1)
    {
        throw std::runtime_error("Can't create AF_PACKET socket");
    }

    int version = TPACKET_V3;
    int setsockopt_packet_version = setsockopt(this->packet_socket, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    if (setsockopt_packet_version < 0)
    {
        throw std::runtime_error("setsockopt version");
    }
    setsockopt_packet_version = setsockopt(this->packet_socket, SOL_SOCKET, SO_ATTACH_FILTER, &capture_reader.filter, sizeof(capture_reader.filter));
    if (setsockopt_packet_version < 0)
    {
        throw std::runtime_error("Can't set BPF filter");
    }

    int interface_number = get_interface_number_by_device_name(this->packet_socket, interface_name);

    if (interface_number == -1)
    {
        throw std::runtime_error("Can't get interface number by interface name");
    }

    // Switch to PROMISC mode
    struct packet_mreq sock_params;
    memset(&sock_params, 0, sizeof(sock_params));
    sock_params.mr_type = PACKET_MR_PROMISC;
    sock_params.mr_ifindex = interface_number;

    int set_promisc = setsockopt(this->packet_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&sock_params, sizeof(sock_params));

    if (set_promisc == -1)
    {
        throw std::runtime_error("Can't enable promisc mode");
    }

    struct sockaddr_ll bind_address;
    memset(&bind_address, 0, sizeof(bind_address));

    // fill sockaddr_ll struct to prepare binding
    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);
    bind_address.sll_ifindex = interface_number;

    memset(&ring.req, 0, sizeof(ring.req));

    ring.req.tp_block_size = blocksiz;/* Minimal size of contiguous block */
    ring.req.tp_frame_size = framesiz; /* Number of blocks */
    ring.req.tp_block_nr = blocknum;/* Size of frame */
    ring.req.tp_frame_nr = (blocksiz * blocknum) / framesiz;/* Total number of frames */

    ring.req.tp_retire_blk_tov = 60; // Timeout in msec
    ring.req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    // allocation of the circular buffer (ring)
    int setsockopt_rx_ring = setsockopt(packet_socket, SOL_PACKET , PACKET_RX_RING , (void*)&ring.req , sizeof(ring.req));

    if (setsockopt_rx_ring == -1)
    {
        throw std::runtime_error("Can't enable RX_RING for AF_PACKET socket");
    }

    // mapping of the allocated buffer to the user process
    ring.mapped_buffer = (uint8_t*)mmap(NULL, ring.req.tp_block_size * ring.req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, packet_socket, 0);

    if (ring.mapped_buffer == MAP_FAILED)
    {
        throw std::runtime_error("mmap failed!");
    }

    // Allocate iov structure for each block
    ring.rd = (struct iovec*)malloc(ring.req.tp_block_nr * sizeof(struct iovec));

    // Initilize iov structures
    for (unsigned int i = 0; i < ring.req.tp_block_nr; ++i)
    {
        ring.rd[i].iov_base = ring.mapped_buffer + (i * ring.req.tp_block_size);
        ring.rd[i].iov_len = ring.req.tp_block_size;
    }

    //bind socket to the interface
    int bind_result = bind(packet_socket, (struct sockaddr *)&bind_address, sizeof(bind_address));

    if (bind_result == -1)
    {
        throw std::runtime_error("Can't bind to AF_PACKET socket");
    }

    //PACKET_FANOUT is since Linux 3.1
    //To scale processing across threads
    if (fanout_group_id)
    {
        // PACKET_FANOUT_LB - round robin
        // PACKET_FANOUT_CPU - send packets to CPU where packet arrived
        int fanout_type = PACKET_FANOUT_CPU;
        int fanout_arg = (fanout_group_id | (fanout_type << 16));
        int setsockopt_fanout = setsockopt(this->packet_socket, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));
        if (setsockopt_fanout < 0)
        {
            throw std::runtime_error("Can't configure fanout");
        }
    }

    return packet_socket;
}

void PacketRing::start_af_packet_capture()
{ 
    LOG("start_af_packet_capture packet_socket: %d", packet_socket);
    unsigned int current_block_num = 0;
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));

    pfd.fd = packet_socket;
    pfd.events = POLLIN | POLLERR;
    pfd.revents = 0;
    sigset_t sigmask;
    /*  Un-mask all signals while in ppoll() so any signal will cause
     *  ppoll() to return prematurely. */
    sigemptyset(&sigmask);
    const struct timespec timeout = { 1, 0 };
    while (!capture_reader.loop_stopped)
    {
        struct block_desc *pbd = (struct block_desc *) ring.rd[current_block_num].iov_base;


        if ((pbd->h1.block_status & TP_STATUS_USER) == 0)
        {
            // to wait for incoming packets
            int res = ppoll(&pfd, 1, &timeout, &sigmask);

            //exit if ppoll returned by a signal
            if(res == EINTR)
            {
                break;
            }

            continue;
        }

        walk_block(pbd/*TODO , current_block_num*/);
        flush_block(pbd);
        current_block_num = (current_block_num + 1) % blocknum;
    }

    socklen_t len = sizeof(stats);
    int err = getsockopt(packet_socket, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
    if(err < 0)
    {
        std::string err_message("getsockopt PACKET_STATISTICS. err: " + err);
        throw std::runtime_error(err_message);
    }
}

bool CaptureReader::loop(void* user, pcap_handler callback, int count)
{
    std::vector<std::thread> threads;
    (void)count;
    this->callback = callback;
    this->user = (u_char*) user;
//    fanout_thread();
    for(unsigned i = 0; i < num_cpus; i++) {
        threads.emplace_back(&CaptureReader::fanout_thread, this);
    }
    for(unsigned i = 0; i < num_cpus; i++) {
        threads[i].join();
    }
    threads_completed = true;
    std::unique_lock<std::mutex> lock(mx);
    cv_threads_completed.notify_all();
    return true;
}

void CaptureReader::break_loop()
{
    loop_stopped = true;
}

void CaptureReader::fanout_thread()
{
    PacketRing packet(*this);
    packet.start_af_packet_capture();
    total_received_packets += packet.get_received_packets();
    total_received_bytes += packet.get_received_bytes();
    total_drops += packet.packet_stats().tp_drops;
}

void CaptureReader::print_statistic(std::ostream& out)
{
    (void)out;
    std::unique_lock<std::mutex> lock(mx);
    while(!threads_completed)
    {
        cv_threads_completed.wait(lock);
    }
    out << "Statistics from interface: " << source << '\n'
            << "  packets received by filtration: " <<  total_received_packets.load() << '\n'
            << "  bytes received by filtration: " << total_received_bytes.load() << '\n'
            << "  packets dropped by kernel     : " << total_drops.load() << '\n';
//          << "  packets dropped by interface  : " << stat.ps_ifdrop;
} 

std::ostream& operator<<(std::ostream& out, const CaptureReader::Params& params)
{
    out << "Read from interface: " << params.interface << '\n'
        << "  BPF filter  : " << params.filter << '\n'
        << "  snapshot len: " << params.snaplen << " bytes\n"
        << "  read timeout: " << params.timeout_ms << " ms\n"
        << "  buffer size : " << params.buffer_size << " bytes\n"
        << "  promiscuous mode: " << (params.promisc ? "on" : "off") << '\n'
        << "  capture traffic : ";
    switch(params.direction)
    {
        using Direction = CaptureReader::Direction;
    case Direction::IN:
        out << "in";
        break;
    case Direction::OUT:
        out << "out";
        break;
    case Direction::INOUT:
        out << "inout";
        break;
    }
    return out;
}

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
