#include "nfqnl.h"

NetFilterConf::NetFilterConf() {
    system("iptables -F");
    system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    system("iptables -A INPUT -j NFQUEUE --queue-num 0");
}

NetFilterConf::~NetFilterConf() {
    system("iptables -F");
}

void NetFilterConf::setHostName(char* arg) {
	hostname_ = arg;
}


u_int32_t NetFilterConf::print_pkt(struct nfq_data *tb) {
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	int ret;
	bool isIp;

	unsigned char *data;

	if (!(ph = nfq_get_msg_packet_hdr(tb))) {
		printf("Packet Header Error");
		exit(1);		
	}

	id = ntohl(ph->packet_id);
	ret = nfq_get_payload(tb, &data);

	if (ret < 0) {
		printf("Payload Len Error");
		exit(-1);

	}

	struct IpHdr* IpHdr = (struct IpHdr *) data;


	return id;

}

int NetFilterConf::cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	u_int32_t id = NetFilterConf::print_pkt(nfa);
	printf("entering callback\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void NetFilterConf::SetNetFilterOpening() {

    printf("opening library handle\n");
	h_ = nfq_open();
	if (!h_) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h_, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h_, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh_ = nfq_create_queue(h_,  0, &cb, NULL);
	if (!qh_) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}
	
	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh_, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd_ = nfq_fd(h_);

	

}

int NetFilterConf::RunNetFilter() {
	if ((rv_ = recv(fd_, buf_, sizeof(buf_), 0)) >= 0) {
		printf("pkt received\n");
		nfq_handle_packet(h_, buf_, rv_);
		return RUN_CONTINUE;
	}
	/* if your application is too slow to digest the packets that
		* are sent from kernel-space, the socket buffer that we use
		* to enqueue packets may fill up returning ENOBUFS. Depending
		* on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		* the doxygen documentation of this library on how to improve
		* this situation.
		*/
	if (rv_ < 0 && errno == ENOBUFS) {
		printf("losing packets!\n");
		return RUN_CONTINUE;
	}
	perror("recv failed");
	RUN_BREAK;
}

void NetFilterConf::SetNetFilterEnding() {
	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh_);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h_, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h_);
}
