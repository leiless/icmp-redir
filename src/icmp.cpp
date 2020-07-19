/*
 * Created Jul 19, 2020.
 */

#include "icmp.h"
#include "formatter.h"

#include <stdexcept>

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>

icmp::icmp()
{
    fd = socket(PF_INET, SOCK_RAW,  IPPROTO_ICMP);
    if (fd < 0) {
        if (errno == EPERM) {
            throw std::runtime_error("raw socket requires root privilege");
        }
        throw std::runtime_error(Formatter() << "socket(2) fail: " << strerror(errno));
    }


}

