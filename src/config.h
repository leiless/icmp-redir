/*
 * Created Jul 18, 2020.
 */

#ifndef ICMP_REDIR_CONFIG_H
#define ICMP_REDIR_CONFIG_H

#include <string>

class Config {
public:
    enum RunType {
        SERVER,
        CLIENT,
    } run_type;
    uint8_t thread_pool_size;
    class ClientConfig {
    public:
        // TODO: support IPv6
        uint32_t addr;
    } client;
    class ServerConfig {
    public:
        /* Currently there is no server specific options */
    } server;

    Config(int, char **);
private:
    int argc;   // Unused currently
    const char **argv;

    void usage(int) __attribute__ ((noreturn));
};

#endif

