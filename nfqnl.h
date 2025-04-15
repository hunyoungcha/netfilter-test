#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include "packet_structs.h"
#include <iostream>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define RUN_CONTINUE 1
#define RUN_BREAK 2
#define HTTP 80

#define TCP 0x06

class NetFilterConf {
    public:
        NetFilterConf();
        ~NetFilterConf();

        void SetNetFilterOpening();
        int RunNetFilter();
        void SetNetFilterEnding();

        void setHostName(char* arg);
    
    
        private:
        static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
        static std::string FindString(std::string httpData);
        static u_int32_t pkt_filter(struct nfq_data *tb);
    
        std::string hostname_;
        struct nfq_handle *h_;
        struct nfq_q_handle *qh_;
        struct nfnl_handle *nh_;
        int fd_;
        int rv_;
        char buf_[4096] __attribute__ ((aligned));
};