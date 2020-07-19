/*
 * Created Jul 19, 2020.
 */

#include "icmp.h"
#include "formatter.h"
#include "net.h"

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
std::optional<IcmpPacket> IcmpPacket::parse(const char *buffer, size_t size)
{
    assert_nonnull(buffer);
    assert_nonzero(size, %zu);

    if (size < sizeof(struct iphdr)) {
        return std::nullopt;
    }

    auto iph = (struct iphdr *) buffer;
    auto iph_len = IPHDR_LEN(iph);
    if (iph_len < sizeof(struct iphdr)) {
        return std::nullopt;
    }

    if (iph->protocol != IPPROTO_ICMP) {
        if (iph->protocol == IPPROTO_ICMPV6) {
            /* TODO: support ICMPV6 protocol */
        } else {
            // XXX: Should never happen
            panicf("unknown IP protocol: %#x", iph->protocol);
        }
        return std::nullopt;
    }

    if (!verify_iphdr_checksum(iph)) {
        return std::nullopt;
    }

    if (iph_len + sizeof(struct icmphdr) > size) {
        return std::nullopt;
    }

    auto icmph = (struct icmphdr *) (buffer + iph_len);
    auto icmp_len = size - iph_len;
    if (!verify_icmphdr_checksum(icmph, icmp_len)) {
        return std::nullopt;
    }

    return IcmpPacket(buffer, size);
}

IcmpPacket::IcmpPacket(const char *buffer0, size_t size0)
{
    buffer = new char[size0];
    size = size0;
    (void) memcpy(buffer, buffer0, size);
    iph = reinterpret_cast<struct iphdr *>(buffer);
    auto iph_len = IPHDR_LEN(iph);
    icmph = reinterpret_cast<struct icmphdr *>(buffer + iph_len);
    icmp_len = size - iph_len;
}

#define IPHDR_CHECKSUM_OFFSET       offsetof(struct iphdr, check)

uint16_t IcmpPacket::calc_iphdr_checksum(const struct iphdr *iph)
{
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

bool IcmpPacket::verify_iphdr_checksum(const struct iphdr *iph)
{
    return iph->check == calc_iphdr_checksum(iph);
}

#define ICMPHDR_CHECKSUM_OFFSET     offsetof(struct icmphdr, checksum)

uint16_t IcmpPacket::calc_icmphdr_checksum(const struct icmphdr *icmph, size_t n)
{
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

bool IcmpPacket::verify_icmphdr_checksum(const struct icmphdr *icmph, size_t n)
{
    return icmph->checksum == calc_icmphdr_checksum(icmph, n);
}

Icmp::Icmp()
{
    fd = socket(PF_INET, SOCK_RAW,  IPPROTO_ICMP);
    if (fd < 0) {
        if (errno == EPERM) {
            throw std::runtime_error("raw socket requires root privilege");
        }
        throw std::runtime_error(Formatter() << "socket(2) fail: " << strerror(errno));
    }

    assert_false(net::get_ip_hdr_inc(fd), %d);
    net::set_ip_hdr_inc(fd);
}

void Icmp::poll()
{
    struct pollfd fds = {fd, POLLIN, 0};
    int e;
    char buffer[kMaxIcmpPacketSize];
    ssize_t nread;
    while (true) {
        e = ::poll(&fds, 1, -1);
        if (e < 0) {
            if (errno == EINTR) {
                continue;
            }
            panicf("poll(2) fail: %s", strerror(errno));
        }
        assert_eq(e, 1, %d);
        assert_eq(fds.revents, POLLIN, %#x);

        while (true) {
            nread = read(fd, buffer, sizeof(buffer));
            if (nread < 0) {
                if (errno == EINTR) continue;
                panicf("read(2) fail: %s", strerror(errno));
            }
            assert_nonzero(nread, %zd);

            // TODO: Schedule into thread pool
        }
    }
}

