/*
 * Created Jul 19, 2020.
 */

#include "icmp.h"
#include "formatter.h"
#include "net.h"
#include "utils.h"
#include "assertf.h"

#include <stdexcept>

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

#define IPHDR_LEN(iph)          ((uint32_t) (iph)->ihl << 2u)

/**
 * Initialize an ICMP packet(IP header included in buffer)
 */
std::unique_ptr<IcmpPacket> IcmpPacket::parse(const char *buffer, size_t size) {
    assert_nonnull(buffer);
    assert_nonzero(size, %zu);

    if (size < sizeof(struct iphdr)) {
        return nullptr;
    }

    auto iph = (struct iphdr *) buffer;
    auto iph_len = IPHDR_LEN(iph);
    if (iph_len < sizeof(struct iphdr)) {
        return nullptr;
    }

    if (iph->protocol != IPPROTO_ICMP) {
        if (iph->protocol == IPPROTO_ICMPV6) {
            /* TODO: support ICMPV6 protocol */
        } else {
            // XXX: Should never happen
            panicf("unknown IP protocol: %#x", iph->protocol);
        }
        return nullptr;
    }

    if (!verify_iphdr_checksum(iph)) {
        return nullptr;
    }

    if (iph_len + sizeof(struct icmphdr) > size) {
        return nullptr;
    }

    auto icmph = (struct icmphdr *) (buffer + iph_len);
    auto icmp_len = size - iph_len;
    if (!verify_icmphdr_checksum(icmph, icmp_len)) {
        return nullptr;
    }

    return std::unique_ptr<IcmpPacket>(new IcmpPacket(buffer, size));
}

IcmpPacket::IcmpPacket(const char *buffer0, size_t size0) {
    buffer = new char[size0];
    size = size0;
    (void) memcpy(buffer, buffer0, size);
    iph = reinterpret_cast<struct iphdr *>(buffer);
    auto iph_len = IPHDR_LEN(iph);
    icmph = reinterpret_cast<struct icmphdr *>(buffer + iph_len);
    icmp_len = size - iph_len;
}

#define IPHDR_CHECKSUM_OFFSET       offsetof(struct iphdr, check)

uint16_t IcmpPacket::calc_iphdr_checksum(const struct iphdr *iph) {
    static_assert(IPHDR_CHECKSUM_OFFSET % 2 == 0);

    auto iph_len = IPHDR_LEN(iph);
    assert_eq(iph_len & 1u, 0, %u);

    uint32_t i;
    uint32_t cksum = 0;
    const uint16_t *p;
    for (i = 0, p = (uint16_t *) iph; i < iph_len; i += 2, p++) {
        /* Skip header checksum itself */
        if (i != IPHDR_CHECKSUM_OFFSET) {
            // TODO: ntohs(*p)
            cksum += *p;
        }
    }
    cksum = (cksum & 0xffffu) + (cksum >> 16u);
    cksum += cksum >> 16u;
    return ~cksum;
}

bool IcmpPacket::verify_iphdr_checksum(const struct iphdr *iph) {
    return iph->check == calc_iphdr_checksum(iph);
}

#define ICMPHDR_CHECKSUM_OFFSET     offsetof(struct icmphdr, checksum)

uint16_t IcmpPacket::calc_icmphdr_checksum(const struct icmphdr *icmph, size_t n) {
    static_assert(ICMPHDR_CHECKSUM_OFFSET % 2 == 0);

    uint32_t i;
    uint32_t cksum = 0;
    const uint16_t *p;
    for (i = 0, p = (uint16_t *) icmph; i < n; i += 2, p++) {
        if (i != ICMPHDR_CHECKSUM_OFFSET) {
            cksum += *p;
        }
    }
    if (n & 1u) {
        cksum += *((uint8_t *) p);
    }
    cksum = (cksum & 0xffffu) + (cksum >> 16u);
    cksum += cksum >> 16u;
    return ~cksum;
}

bool IcmpPacket::verify_icmphdr_checksum(const struct icmphdr *icmph, size_t n) {
    return icmph->checksum == calc_icmphdr_checksum(icmph, n);
}

void IcmpPacket::hexdump() const {
    std::ostringstream oss;
    auto iph_len = IPHDR_LEN(iph);
    oss << "IP proto: " << (int) iph->protocol << " "
        << "ver: " << iph->version << " "
        << "id: 0x" << std::setfill('0') << std::setw(4) << std::hex << ntohs(iph->id) << std::dec << " "
        << "length: " << iph_len << " "
        << "tos: " << int(iph->tos) << " "
        << "tot_len: " << ntohs(iph->tot_len) << " "
        << "frag_off: " << iph->frag_off << " "
        << "ttl: " << int(iph->ttl) << " "
        << "check: 0x" << std::setfill('0') << std::setw(4) << std::hex << iph->check << std::dec
        << std::endl;
    oss << net::ip_to_str(iph->saddr) << " -> " << net::ip_to_str(iph->daddr) << std::endl;
    oss << "ICMP length: " << icmp_len << " "
        << "header: " << sizeof(*icmph) << " "
        << "data: " << icmp_len - sizeof(*icmph) << " "
        << "type: " << (uint16_t) icmph->type << " "
        << "code: " << (uint16_t) icmph->code << " ";
    if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHOREPLY) {
        oss << "id: " << ntohs(icmph->un.echo.id) << " "
            << "seq: " << ntohs(icmph->un.echo.sequence) << " ";
    } else {
        oss << "rest of header: 0x" << std::setfill('0') << std::setw(8) << std::hex
            << ntohl(icmph->un.gateway) << std::dec << " ";
    }
    oss << "checksum: 0x" << std::setfill('0') << std::setw(4) << std::hex
        << icmph->checksum << std::dec
        << std::endl;
    oss << "Raw packet hexdump:" << std::endl;
    utils::hexdump(buffer, size, oss);
    std::cout << oss.str();
}

void IcmpPacket::rewrite(const Config & config, std::unordered_map<IcmpKey, IcmpValue> & map) {
    switch (config.run_type) {
    case Config::CLIENT:
        client_rewrite(config, map);
        break;
    case Config::SERVER:
        server_rewrite(config, map);
        break;
    default:
        panicf("unknown run type: %d", config.run_type);
    }
}

#define MAGIC_DATA          "opqrstuvwxyz{|}~"
#define MAGIC_DATA_LEN      (sizeof(MAGIC_DATA) - 1)

void IcmpPacket::client_rewrite(const Config & config, std::unordered_map<IcmpKey, IcmpValue> & map) {
    assert_eq(Config::CLIENT, config.run_type, %d);

    // TODO: handle for ICMP_ECHOREPLY and send back to original sender

    if (icmph->type != ICMP_ECHO || icmph->code != 0) return;

    IcmpKey k = {iph->daddr, icmph->un.echo.id, icmph->un.echo.sequence};
    IcmpValue v = {utils::epoch_ms(), iph->saddr};
    if (map.contains(k)) {
        std::cout << k.str() << ": " << map[k].str() << " will be overwritten by " << v.str();
    }
    map[k] = v;

    uint32_t server_addr = 0x01020304;

    char data[sizeof(uint32_t) + MAGIC_DATA_LEN];
    *((uint32_t *) data) = iph->daddr;
    (void) memcpy(data + sizeof(uint32_t), MAGIC_DATA, MAGIC_DATA_LEN);

    content_append(data, sizeof(data));

    iph->saddr = 0;
    iph->daddr = server_addr;

    calc_iphdr_checksum(iph);
    calc_icmphdr_checksum(icmph, icmp_len);

    // TODO: send (buffer, size) to raw socket fd in Icmp class
}

void IcmpPacket::server_rewrite(const Config & config, std::unordered_map<IcmpKey, IcmpValue> & map) {
    assert_eq(Config::SERVER, config.run_type, %d);

}

// Append data to ICMP content
// XXX: ICMP checksum will be invalid
void IcmpPacket::content_append(const char *data, size_t len) {
    assert_nonnull(data);
    assert_nonzero(len, %zu);
    char *p = new char[size + len];
    (void) memcpy(p, buffer, size);
    (void) memcpy(p + size, data, len);
    iph = nullptr;
    icmph = nullptr;
    delete buffer;
    buffer = p;
    size += len;
    iph = reinterpret_cast<struct iphdr *>(buffer);
    icmph = reinterpret_cast<struct icmphdr *>(buffer + IPHDR_LEN(iph));
    icmp_len += len;
}

Icmp::Icmp() {
    fd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        if (errno == EPERM) {
            throw std::runtime_error("raw socket requires root privilege");
        }
        throw std::runtime_error(Formatter() << "socket(2) fail: " << strerror(errno));
    }

    assert_false(net::get_ip_hdr_inc(fd), %d);
    net::set_ip_hdr_inc(fd);
}

void Icmp::poll(const std::function<Func> & callback) {
    assert_nonnull(callback);

    struct pollfd fds = {fd, POLLIN, 0};
    int e;
    char buffer[kMaxIcmpPacketSize];
    ssize_t nread;
    while (true) {
        e = ::poll(&fds, 1, -1);
        if (e < 0) {
            if (errno == EINTR) continue;
            panicf("poll(2) fail: %s", strerror(errno));
        }
        assert_eq(e, 1, %d);
        assert_eq(fds.revents, POLLIN, %#x);

out_read:
        nread = read(fd, buffer, sizeof(buffer));
        if (nread < 0) {
            if (errno == EINTR) goto out_read;
            panicf("read(2) fail: %s", strerror(errno));
        }
        assert_nonzero(nread, %zd);

        // TODO: Schedule into thread pool
        auto packet = IcmpPacket::parse(buffer, (size_t) nread);
        if (packet) {
            // TODO:
            // Append magic data
            // Rewrite src/dst addrs(bookkeeping original addrs in a hashmap)
            // Send out ICMP packet to dst addr
            callback(std::move(packet), map);
        } else {
            std::ostringstream oss;
            oss << "hexdump of unrecognizable ICMP packet(" << nread <<  " bytes):" << std::endl;
            utils::hexdump(buffer, nread, oss);
            std::cout << oss.str();
        }
    }
}

