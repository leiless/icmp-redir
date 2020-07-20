/*
 * Created Jul 19, 2020.
 */

#include "client.h"
#include "assertf.h"
#include "icmp.h"

Client::Client(Config & config) : config(config)
{
    assert_eq(config.run_type, Config::CLIENT, %d);
}

void Client::run()
{
    Icmp().poll([] (std::unique_ptr<IcmpPacket> packet) {
        packet->hexdump();
    });
}

