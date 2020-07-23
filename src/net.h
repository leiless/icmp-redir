/*
 * Created Jul 19, 2020.
 */

#ifndef ICMP_REDIR_NET_H
#define ICMP_REDIR_NET_H

#include <string>

namespace net {
    bool get_ip_hdr_inc(int);
    void set_ip_hdr_inc(int, bool = true);
    std::string ip_to_str(uint32_t);
}

#endif

