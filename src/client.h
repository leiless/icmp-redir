/*
 * Created Jul 19, 2020.
 */

#ifndef ICMP_REDIR_CLIENT_H
#define ICMP_REDIR_CLIENT_H

#include "config.h"

class Client {
public:
    explicit Client(Config &);
    void run();
private:
    const Config & config;
};

#endif

