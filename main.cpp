#include "main.h"

volatile sig_atomic_t g_running = 1;

void signalHandler(int signum) {
    if (signum == SIGINT) {
        printf("\nCtrl+C\n");
        g_running = 0;
    }
}

void usage() {
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage();
        return 1;
    }
    signal(SIGINT, signalHandler);
    NetFilterConf NFConf;

    std::string HostName = argv[1];
    size_t HashedHostname = NetFilterConf::Hashing(HostName);
    NetFilterConf::SetHostName(HashedHostname);

    NFConf.SetNetFilterOpening();    

    while (g_running) {
        switch (NFConf.RunNetFilter()) {
            case RUN_CONTINUE:
                continue;
            case RUN_BREAK:
                break;
            default:
                printf("Error");
                break;
        }
    }

    NFConf.SetNetFilterEnding();

    return 0;
}