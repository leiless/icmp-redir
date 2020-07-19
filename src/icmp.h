/*
 * Created Jul 19, 2020.
 */

#ifndef ICMP_REDIR_ICMP_H
#define ICMP_REDIR_ICMP_H

#include <unistd.h>

class icmp {
public:
    icmp();
    ~icmp() {
        (void) close(fd);
    }
private:
    int fd;
};

#endif

