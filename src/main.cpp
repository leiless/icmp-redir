/*
 * Created Jul 18, 2020.
 */

#include <iostream>

#include "compile.h"
#include "assertf.h"
#include "config.h"
#include "icmp.h"

int main(int argc, char *argv[]) {
    Config config = Config(argc, argv);

    std::cout << "Build timestamp: " << BUILD_TIMESTAMP << std::endl;
    std::cout << "     Build user: " << BUILD_USER << std::endl;
    std::cout << "    HEAD commit: " << BUILD_HEAD_COMMIT << std::endl;

    switch (config.run_type) {
    case Config::SERVER:
        /* Fallthrough */
    case Config::CLIENT:
        Icmp(config).read([&] (std::unique_ptr<IcmpPacket> packet, std::unordered_map<IcmpKey, IcmpValue> & map, int fd) {
            packet->hexdump();
            if (packet->rewrite(config, map)) {
                std::cout << "---- Rewrote ICMP packet ----" << std::endl;
                packet->hexdump();
                (void) packet->send(fd);
            }
        });
        break;
    default:
        panicf("unknown run type: %d", config.run_type);
    }
    return 0;
}

