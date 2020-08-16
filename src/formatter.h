#ifndef ICMP_REDIR_FORMATTER_H
#define ICMP_REDIR_FORMATTER_H

#include <stdexcept>
#include <sstream>

// see: https://stackoverflow.com/questions/12261915/how-to-throw-stdexceptions-with-variable-messages
class Formatter {
public:
    template <typename Arg>
    Formatter & operator<<(const Arg & value) {
        stream << value;
        return *this;
    }

    // see: https://stackoverflow.com/questions/3044690/operator-stdstring-const
    operator std::string() const {
        return stream.str();
    }
private:
    std::stringstream stream;
};

#endif

