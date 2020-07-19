/*
 * Created Jul 18, 2020.
 */

#include <iostream>

#include "config.h"
#include "client.h"

int main(int argc, char *argv[])
{
    Config config = Config(argc, argv);
    switch (config.run_type) {
    case Config::SERVER:

        break;
    case Config::CLIENT:
        Client(config).run();
        break;
    }
    return 0;
}

