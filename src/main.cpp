/*
 * Created Jul 18, 2020.
 */

#include <iostream>

#include "config.h"
#include "client.h"

int main(int argc, char *argv[]) {
    Config config = Config(argc, argv);

    std::cout << "Build timestamp: " << BUILD_TIMESTAMP << std::endl;
    std::cout << "     Build user: " << BUILD_USER << std::endl;
    std::cout << "    HEAD commit: " << BUILD_HEAD_COMMIT << std::endl;

    switch (config.run_type) {
    case Config::SERVER:
        /* TODO */
        break;
    case Config::CLIENT:
        Client(config).run();
        break;
    }
    return 0;
}

