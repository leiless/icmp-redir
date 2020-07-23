/*
 * Created Jul 23, 2020.
 */

#include "net.h"
#include "assertf.h"

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

bool net::get_ip_hdr_inc(int fd) {
    bool on;
    socklen_t len = sizeof(on);
    int e = getsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, &len);
    if (e != 0) {
        panicf("getsockopt(2) IP_HDRINCL fail: %s", strerror(errno));
    }
    assert_eq(len, sizeof(on), %u);
    assertf(on == 0 || on == 1, "bad IP_HDRINCL value: %#x", on);
    return on;
}

void net::set_ip_hdr_inc(int fd, bool on) {
    int e = setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    assert_zero(e, %d);
}

/**
 * @param ip    Network byte order of IP address
 */
std::string net::ip_to_str(uint32_t ip) {
    static constexpr auto kIpStrBufSize = 16u;
    struct in_addr addr = { .s_addr = ip };
    char output[kIpStrBufSize];
    (void) strncpy(output, inet_ntoa(addr), sizeof(output));
    return output;
}

std::tuple<uint32_t, bool> net::str_to_ip(const std::string & s) {
    struct in_addr in{};
    int ret = inet_pton(AF_INET, s.c_str(), &in);
    return std::make_tuple(in.s_addr, ret != 0);
}

