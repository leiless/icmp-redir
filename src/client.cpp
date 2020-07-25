/*
 * Created Jul 19, 2020.
 */

#include "client.h"
#include "assertf.h"
#include "icmp.h"

Client::Client(Config & config) : config(config) {
    assert_eq(config.run_type, Config::CLIENT, %d);
}

void Client::run() {
    Icmp().read([&] (std::unique_ptr<IcmpPacket> packet, std::unordered_map<IcmpKey, IcmpValue> & map, int fd) {
        packet->hexdump();
        if (packet->rewrite(config, map)) {
            std::cout << "---- Rewrote ICMP packet ----" << std::endl;
            packet->hexdump();
            // TODO: reply dest unreachable if failed to send?
            (void) packet->send(fd);
        }
    });
}

