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

    auto iph = reinterpret_cast<const struct iphdr *>(buffer);
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

    auto icmph = reinterpret_cast<const struct icmphdr *>(buffer + iph_len);
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
    auto p = reinterpret_cast<const uint16_t *>(iph);
    for (i = 0; i < iph_len; i += 2, p++) {
        /* Skip header checksum itself */
        if (i != IPHDR_CHECKSUM_OFFSET) {
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

uint16_t IcmpPacket::calc_icmphdr_checksum(const struct icmphdr *icmph, size_t icmp_len) {
    static_assert(ICMPHDR_CHECKSUM_OFFSET % 2 == 0);

    uint32_t i;
    uint32_t cksum = 0;
    auto p = reinterpret_cast<const uint16_t *>(icmph);
    for (i = 0; i < icmp_len; i += 2, p++) {
        if (i != ICMPHDR_CHECKSUM_OFFSET) {
            cksum += *p;
        }
    }
    if (icmp_len & 1u) {
        cksum += *((uint8_t *) p);
    }
    cksum = (cksum & 0xffffu) + (cksum >> 16u);
    cksum += cksum >> 16u;
    return ~cksum;
}

bool IcmpPacket::verify_icmphdr_checksum(const struct icmphdr *icmph, size_t icmp_len) {
    return icmph->checksum == calc_icmphdr_checksum(icmph, icmp_len);
}

void IcmpPacket::calc_checksums() {
    iph->check = calc_iphdr_checksum(iph);
    icmph->checksum = calc_icmphdr_checksum(icmph, icmp_len);
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

bool IcmpPacket::rewrite(const Config & config, std::unordered_map<IcmpKey, IcmpValue> & map) {
    switch (config.run_type) {
    case Config::CLIENT:
        return client_rewrite(config, map);
    case Config::SERVER:
        return server_rewrite(config, map);
    default:
        panicf("unknown run type: %d", config.run_type);
    }
}

#define MAGIC_DATA          "[0123456789abcdef]"
#define MAGIC_LEN           (sizeof(MAGIC_DATA) - 1)    /* EOS not included */

/**
 * Check if the ICMP packet content ends with specific data
 */
bool IcmpPacket::data_ends_with(const char *data, size_t len) {
    assert_nonnull(data);
    if (icmp_len >= len) {
        auto p = reinterpret_cast<const char *>(icmph) + icmp_len - len;
        return !memcmp(p, data, len);
    }
    return false;
}

bool IcmpPacket::client_rewrite_echo_request(const Config & config, std::unordered_map<IcmpKey, IcmpValue> & map) {
    IcmpKey k = {iph->daddr, icmph->un.echo.id, icmph->un.echo.sequence};
    IcmpValue v = {utils::epoch_ms(), iph->saddr};
    if (map.find(k) != map.end()) {
        std::cout << k.str() << ": " << map[k].str() << " will be overwritten by " << v.str() << std::endl;
    }
    map[k] = v;

    char data[sizeof(uint32_t) + MAGIC_LEN];
    *((uint32_t *) data) = iph->daddr;
    (void) memcpy(data + sizeof(uint32_t), MAGIC_DATA, MAGIC_LEN);

    content_append(data, sizeof(data));

    iph->saddr = INADDR_ANY;
    iph->daddr = config.client.addr;

    calc_checksums();

    return true;
}

bool IcmpPacket::client_rewrite_echo_reply(std::unordered_map<IcmpKey, IcmpValue> & map) {
    if (!data_ends_with(MAGIC_DATA, MAGIC_LEN)) return false;
    if (icmp_len < sizeof(*icmph) + sizeof(uint32_t) + MAGIC_LEN) return false;
    auto daddr = *reinterpret_cast<uint32_t *>(reinterpret_cast<char *>(icmph) + icmp_len - (sizeof(uint32_t) + MAGIC_LEN));

    IcmpKey k = {daddr, icmph->un.echo.id, icmph->un.echo.sequence};
    auto it = map.find(k);
    if (it == map.end()) return false;

    iph->saddr = daddr;
    iph->daddr = it->second.saddr;

    // Reduce the bookkeeping ICMP data previously wrote by client
    constexpr auto reduce_size = sizeof(uint32_t) + MAGIC_LEN;
    iph->tot_len = htons(ntohs(iph->tot_len) - reduce_size);
    size -= reduce_size;
    icmp_len -= reduce_size;

    calc_checksums();

    (void) map.erase(it);

    return true;
}

/**
 * @return      true if packet data rewritten.
 */
bool IcmpPacket::client_rewrite(const Config & config, std::unordered_map<IcmpKey, IcmpValue> & map) {
    assert_eq(config.run_type, Config::CLIENT, %d);

    if (icmph->type == ICMP_ECHO && icmph->code == 0) {
        return client_rewrite_echo_request(config, map);
    }

    if (icmph->type == ICMP_ECHOREPLY && icmph->code == 0) {
        return client_rewrite_echo_reply(map);
    }

    return false;
}

bool IcmpPacket::server_rewrite_echo_request(std::unordered_map<IcmpKey, IcmpValue> & map) {
    if (!data_ends_with(MAGIC_DATA, MAGIC_LEN)) return false;
    if (icmp_len < sizeof(*icmph) + sizeof(uint32_t) + MAGIC_LEN) return false;
    auto daddr = *reinterpret_cast<uint32_t *>(reinterpret_cast<char *>(icmph) + icmp_len - (sizeof(uint32_t) + MAGIC_LEN));

    IcmpKey k = {daddr, icmph->un.echo.id, icmph->un.echo.sequence};
    // iph->saddr is the IP address of previous hop
    IcmpValue v = {utils::epoch_ms(), iph->saddr};
    if (map.find(k) != map.end()) {
        std::cout << k.str() << ": " << map[k].str() << " will be overwritten by " << v.str() << std::endl;
    }
    map[k] = v;

    iph->saddr = INADDR_ANY;
    iph->daddr = daddr;

    // Reduce the bookkeeping ICMP data previously wrote by client
    constexpr auto reduce_size = sizeof(uint32_t) + MAGIC_LEN;
    iph->tot_len = htons(ntohs(iph->tot_len) - reduce_size);
    size -= reduce_size;
    icmp_len -= reduce_size;

    calc_checksums();

    return true;
}

bool IcmpPacket::server_rewrite_echo_reply(std::unordered_map<IcmpKey, IcmpValue> & map) {
    IcmpKey k = {iph->saddr, icmph->un.echo.id, icmph->un.echo.sequence};
    auto it = map.find(k);
    if (it == map.end()) return false;

    iph->saddr = INADDR_ANY;
    iph->daddr = it->second.saddr;

    char data[sizeof(uint32_t) + MAGIC_LEN];
    *((uint32_t *) data) = it->first.daddr;
    (void) memcpy(data + sizeof(uint32_t), MAGIC_DATA, MAGIC_LEN);
    content_append(data, sizeof(data));

    calc_checksums();

    (void) map.erase(it);

    return true;
}

bool IcmpPacket::server_rewrite(const Config & config, std::unordered_map<IcmpKey, IcmpValue> & map) {
    assert_eq(config.run_type, Config::SERVER, %d);

    if (icmph->type == ICMP_ECHO && icmph->code == 0) {
        return server_rewrite_echo_request(map);
    }

    if (icmph->type == ICMP_ECHOREPLY && icmph->code == 0) {
        return server_rewrite_echo_reply(map);
    }

    return false;
}

bool IcmpPacket::send(int fd) {
    assert_ge(fd, 0, %d);
    struct sockaddr_in sin{};
    sin.sin_family = PF_INET;
    sin.sin_addr.s_addr = iph->daddr;
    ssize_t nwrite;
    bool write_ok = false;
out_send:
    nwrite = ::sendto(fd, buffer, size, 0, (struct sockaddr *) &sin, sizeof(sin));
    if (nwrite < 0) {
        if (errno == EINTR) goto out_send;
        std::cerr << "send(2) fail  errno: " << errno << " " << strerror(errno) << std::endl;
    } else if (static_cast<size_t>(nwrite) != size) {
        // Should never happen
        panicf("send(2) incomplete write: %zd vs %zu", nwrite, size);
    } else {
        write_ok = true;
        std::cout << nwrite << " bytes sent out to raw socket" << std::endl;
    }
    return write_ok;
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
    iph->tot_len = htons(ntohs(iph->tot_len) + len);
    icmph = reinterpret_cast<struct icmphdr *>(buffer + IPHDR_LEN(iph));
    icmp_len += len;
}

Icmp::Icmp(const Config & config) : pool(config.thread_pool_size) {
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

void Icmp::read(const std::function<Func> & callback) {
    assert_nonnull(callback);

    char static_buf[kMaxIcmpPacketSize];
    ssize_t nread;
    while (true) {
out_read:
        nread = ::read(fd, static_buf, sizeof(static_buf));
        if (nread < 0) {
            if (errno == EINTR) goto out_read;
            panicf("read(2) fail: %s", strerror(errno));
        }
        assert_nonzero(nread, %zd);

        char *buf = new char[nread];
        (void) memcpy(buf, static_buf, nread);
        (void) pool.enqueue([=, &callback]() {
            auto packet = IcmpPacket::parse(buf, (size_t) nread);
            if (packet) {
                callback(std::move(packet), map, fd);
            } else {
                std::ostringstream oss;
                oss << "hexdump of unrecognizable ICMP packet(" << nread <<  " bytes):" << std::endl;
                utils::hexdump(buf, nread, oss);
                std::cout << oss.str();
            }
            delete[] buf;
        });
    }
}

