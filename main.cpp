#include "main.h"

volatile sig_atomic_t g_running = 1;

void signalHandler(int signum) {
    if (signum == SIGINT) {
        printf("\nCtrl+C");
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
    
    NetFilterConf NFConf_;

    

    NFConf_.setHostName(argv[1]);
    NFConf_.SetNetFilterOpening();    

    while (g_running) {
        NFConf_.RunNetFilter();
    }

    NFConf_.SetNetFilterEnding();

    return 0;
}