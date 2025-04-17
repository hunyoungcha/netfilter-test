#include "nfqnl.h"

size_t NetFilterConf::hostname_;


NetFilterConf::NetFilterConf() {
    system("iptables -F");
    system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    system("iptables -A INPUT -j NFQUEUE --queue-num 0");
}

NetFilterConf::~NetFilterConf() {
    system("iptables -F");
}

size_t NetFilterConf::Hashing(std::string &string) {
	std::hash<std::string> hash_string;
	size_t result = hash_string(string);
	
	return result;
}

void NetFilterConf::SetHostName(size_t HasedHostName) {
	NetFilterConf::hostname_ = HasedHostName;
}

u_int32_t NetFilterConf::pkt_filter(struct nfq_data *tb, int& NF_FLAGS) {
	struct nfqnl_msg_packet_hdr *ph;
	int ret;
	std::string FoundHostName ;

	unsigned char *data;

	if (!(ph = nfq_get_msg_packet_hdr(tb))) {
		printf("Packet Header Error");
		exit(1);		
	}

	u_int32_t id = ntohl(ph->packet_id);
	ret = nfq_get_payload(tb, &data);

	if (ret < 0) {
		printf("Payload Len Error");
		exit(-1);
	}

	struct IpHdr* ip = (struct IpHdr *)data;
	if (ip->Protocol == TCP) {
		int ipLen = (ip->VersionAndIhl & 0x0F) * 4;

		struct TcpHdr* tcp = (struct TcpHdr *)(data + ipLen);
		int tcpLen = (tcp->DataOffsetAndReserved >> 4) * 4;
		
		if (tcp->DPort() == HTTP) {
			int payloadLen = ntohs(ip->TotalLength) - ipLen - tcpLen;
			std::string httpData((char*)(data + ipLen + tcpLen), payloadLen);

			FoundHostName = FindHost(httpData);
			
		}

		if (!FoundHostName.empty()) {
			if (NetFilterConf::Hashing(FoundHostName) == hostname_) {
				NF_FLAGS = NF_DROP;
			}
			
		}
	}
	return id;
}

std::string NetFilterConf::FindHost(std::string httpData) {
	std::string findString = "Host: ";
	std::string hostname;

	size_t pos = httpData.find(findString);
	if (pos != std::string::npos) {
		size_t posStart = pos + findString.length();
		size_t posEnd = httpData.find("\r\n", posStart);

		if (posEnd != std::string::npos) {
			hostname = httpData.substr(posStart, posEnd - posStart);
			std::cout << "Hostname: " << hostname << std::endl;
		}
	}

	return hostname;
}

int NetFilterConf::cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	int NF_FLAGS = NF_ACCEPT;

	u_int32_t id = NetFilterConf::pkt_filter(nfa, NF_FLAGS);
	return nfq_set_verdict(qh, id, NF_FLAGS, 0, NULL);
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
		// printf("pkt received\n");
		nfq_handle_packet(h_, buf_, rv_);
		return RUN_CONTINUE;
	}

	if (rv_ < 0 && errno == ENOBUFS) {
		printf("losing packets!\n");
		return RUN_CONTINUE;
	}
	perror("recv failed");
	return RUN_BREAK;
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
