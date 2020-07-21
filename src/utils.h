#ifndef ICMP_REDIR_UTILS_H
#define ICMP_REDIR_UTILS_H

#include <sys/time.h>
#include <cstdint>
#include <cstddef>
#include <cctype>
#include <iostream>
#include <iomanip>

namespace utils {
    void hexdump(const char *buffer, size_t size, std::ostream & os = std::cout) {
        size_t i, j, n;
        uint32_t c;
        for (i = 0; i < size; i += 16) {
            os << std::setfill('0') << std::setw(8) << std::hex << i << "  ";
            n = std::min(static_cast<size_t>(16), size - i);
            for (j = 0; j < n; j++) {
                // see: https://stackoverflow.com/questions/49692184/why-is-stdhex-not-printing-as-hexadecimal-specially-with-char
                c = (uint32_t) buffer[i + j] & 0xffu;
                os << std::setw(2) << c << " ";
            }
            /* Pad with "  " if size not aligned with 16 */
            for (j = 0; j < 16 - n; j++) {
                os << "   ";
            }
            os << " |";
            for (j = 0; j < n; j++) {
                os << (isprint(buffer[i + j]) ? buffer[i + j] : '.');
            }
            os << "|" << std::endl;
        }
        if (i != 0) {
            os << std::setfill('0') << std::setw(8) << std::hex << i << std::endl;
        }
    }

    // see: https://stackoverflow.com/a/19555210/13600780
    uint64_t epoch_ms() {
        struct timeval tv{};
        int e = gettimeofday(&tv, nullptr);
        assert_zero(e, %d);
        return tv.tv_sec * 1000u + tv.tv_usec / 1000u;
    }
}

#endif

