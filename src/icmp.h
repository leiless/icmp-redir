/*
 * Created Jul 19, 2020.
 */

#ifndef ICMP_REDIR_ICMP_H
#define ICMP_REDIR_ICMP_H

#include <optional>
#include <unistd.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

class IcmpPacket {
public:
    static std::optional<IcmpPacket> parse(const char *, size_t);
    ~IcmpPacket() { delete buffer; }

private:
    IcmpPacket(const char *, size_t);

    static uint16_t calc_iphdr_checksum(const struct iphdr *);
    static bool verify_iphdr_checksum(const struct iphdr *);
    static uint16_t calc_icmphdr_checksum(const struct icmphdr *, size_t);
    static bool verify_icmphdr_checksum(const struct icmphdr *, size_t);

    char *buffer;
    size_t size;
    struct iphdr *iph;
    struct icmphdr *icmph;
    // Total ICMP packet length(header + data)
    size_t icmp_len;
};

class Icmp {
public:
    Icmp();
    ~Icmp() { (void) close(fd); }

    void poll();
private:
    static constexpr auto kMaxIcmpPacketSize = 65536u;
    int fd;
};

#endif
