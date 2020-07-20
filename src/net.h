#ifndef ICMP_REDIR_NET_H
#define ICMP_REDIR_NET_H

#include <stdexcept>

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "assertf.h"
#include "formatter.h"

namespace net {
    bool get_ip_hdr_inc(int fd) {
        bool on;
        socklen_t len = sizeof(on);
        int e = getsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, &len);
        if (e != 0) {
            throw std::runtime_error(Formatter() << "getsockopt(2) IP_HDRINCL fail: " << strerror(errno));
        }
        assert_eq(len, sizeof(on), %u);
        assertf(on == 0 || on == 1, "bad IP_HDRINCL value: %#x", on);
        return on;
    }

    void set_ip_hdr_inc(int fd, bool on = true) {
        int e = setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
        assert_zero(e, %d);
    }

    /**
     * @param ip    Network byte order of IP address
     */
    std::string ip_to_str(uint32_t ip) {
        static constexpr auto kIpStrBufSize = 16u;
        struct in_addr addr = { .s_addr = ip };
        char output[kIpStrBufSize];
        (void) strncpy(output, inet_ntoa(addr), sizeof(output));
        return output;
    }
}

#endif

