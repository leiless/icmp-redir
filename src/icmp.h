/*
 * Created Jul 19, 2020.
 */

#ifndef ICMP_REDIR_ICMP_H
#define ICMP_REDIR_ICMP_H

#include <unistd.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <iostream>
#include <memory>

using IcmpKey = struct IcmpKey {
    // Destination IPv4 address
    uint32_t daddr;
    // ICMP header fields
    uint16_t id;
    uint16_t seq;
    bool operator==(const IcmpKey & rhs) const {
        return daddr == rhs.daddr && id == rhs.id && seq == rhs.seq;
    }
};

// see:
//  https://stackoverflow.com/questions/17016175/c-unordered-map-using-a-custom-class-type-as-the-key
//  https://www.geeksforgeeks.org/how-to-create-an-unordered_map-of-user-defined-class-in-cpp/
namespace std {
    template<>
    struct hash<IcmpKey> {
        size_t operator()(const IcmpKey & k) const {
            // see: https://stackoverflow.com/a/1646913/13600780
            size_t res = 17;
            res = res * 31 + k.daddr;
            res = res * 31 + k.id;
            res = res * 31 + k.seq;
            return res;
        }
    };
}

using IcmpValue = struct IcmpValue {
    // Item creation time in milliseconds
    uint64_t ctime;
    // Source IPv4 address
    uint32_t saddr;
};

class IcmpPacket {
public:
    static std::unique_ptr<IcmpPacket> parse(const char *, size_t);
    ~IcmpPacket() { delete buffer; }

    void hexdump() const;
private:
    IcmpPacket(const char *, size_t);

    static uint16_t calc_iphdr_checksum(const struct iphdr *);
    static bool verify_iphdr_checksum(const struct iphdr *);
    static uint16_t calc_icmphdr_checksum(const struct icmphdr *, size_t);
    static bool verify_icmphdr_checksum(const struct icmphdr *, size_t);

    char *buffer;
    size_t size;
    // Always points to buffer
    struct iphdr *iph;
    struct icmphdr *icmph;
    // Total ICMP packet length(header + data)
    size_t icmp_len;
};

class Icmp {
public:
    Icmp();
    ~Icmp() { (void) close(fd); }

    void poll(void (*)(std::unique_ptr<IcmpPacket>));
private:
    static constexpr auto kMaxIcmpPacketSize = 65536u;
    int fd;
};

#endif

