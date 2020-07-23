/*
 * Created Jul 19, 2020.
 */

#ifndef ICMP_REDIR_UTILS_H
#define ICMP_REDIR_UTILS_H

#include <iostream>

namespace utils {
    void hexdump(const char *, size_t, std::ostream & = std::cout);
    uint64_t epoch_ms();
}

#endif

