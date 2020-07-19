#ifndef ICMP_REDIR_NET_H
#define ICMP_REDIR_NET_H

#include <stdexcept>

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>

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
}

#endif

