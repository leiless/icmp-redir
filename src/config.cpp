/*
 * Created Jul 18, 2020.
 */

#include "config.h"
#define ASSERTF_DEF_ONCE
#include "assertf.h"

#include <iostream>
#include <sstream>
#include <getopt.h>
#include <cstring>

#define CSTR_EQ(s1, s2)             (!strcmp(s1, s2))

#define DEFAULT_THREAD_POOL_SIZE    2

Config::Config(int argc, char **argv)
{
    this->argc = argc;
    this->argv = (const char **) argv;

    const char *mode = argc > 1 ? argv[1] : nullptr;

    static const struct option long_opts[] = {
            {"addr", required_argument, nullptr, 'a'},
            {"thread", required_argument, nullptr, 't'},
            {"version", no_argument, nullptr, 'v'},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, no_argument, nullptr, 0},
    };

    std::string addr;
    uint8_t thread = 0;

    int c;
    int opt_index = 0;
    while ((c = getopt_long(argc, argv, "a:t:vh", long_opts, &opt_index)) != -1) {
        switch (c) {
        case 'a':
            addr = optarg;
            break;
        case 't': {
            unsigned long n = std::stoul(optarg);
            if (n == 0 || (n & ~0xffUL) != 0) {
                std::stringstream ss;
                ss << "bad thread pool size: " << std::showbase << std::hex << n;
                throw std::runtime_error(ss.str());
            }
            thread = (uint8_t) n;
            break;
        }
        case 'v':
            std::cout << "HEAD commit: " << BUILD_HEAD_COMMIT << std::endl;
            exit(EXIT_SUCCESS);
        case 'h':
            usage(EXIT_SUCCESS);
        case '?':
            /* fallthrough */
        default:
            usage(EXIT_FAILURE);
        }
    }

    if (argc - optind != 1) {
        usage(EXIT_FAILURE);
    }

    assert_nonnull(mode);
    if (CSTR_EQ(mode, "client")) {
        run_type = CLIENT;
        if (addr.empty()) {
            throw std::runtime_error("missing address in client mode");
        }
        client.addr = addr;
    } else if (CSTR_EQ(mode, "server")) {
        run_type = SERVER;
    } else {
        std::cerr << argv[0] << ": unrecognized run type '" << mode << "'" << std::endl;
        usage(EXIT_FAILURE);
    }

    if (thread != 0) {
        thread_pool_size = thread;
    } else {
        thread_pool_size = DEFAULT_THREAD_POOL_SIZE;
    }
}

void Config::usage(int exit_status)
{
    auto & os = exit_status ? std::cerr : std::cout;

    os << "Usage:\n"
            << "\t" << basename(argv[0]) << "\n"
            << "\t\tclient -a|--addr ADDR [-t|--thread THREAD]\n"
            << "\t\tserver [-t|--thread THREAD]\n"
            << "\t\t-v|--version\n"
            << "\t\t-h|--help\n"
            << std::endl;

    exit(exit_status);
}

