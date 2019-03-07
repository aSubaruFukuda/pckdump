#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "analyze.h"

#if defined(PCAP)
#include <pcap.h>

#define CAPTURE_FILE_NAME "test.pcap"
#define TCPDUMP_MAGIC 0xa1b2c3d4
#endif

int initialize_raw_socket(char *ifdev);
int set_promiscuous_mode(int soc, struct ifreq *req);

int main(int argc, char *argv[]) {
	int soc, size;
	u_char buf[65535];

	if (argc <= 1) {
		fprintf(stderr, "device-name");
	}
	if ((soc = initialize_raw_socket(argv[1])) == -1) {
		fprintf(stderr, "initialize_raw_socket:error: %s\n", argv[1]);
		return -1;
	}
#if defined(PCAP)
		FILE *cap_fp;
		struct pcap_file_header pcap_header;
		uint32_t jp_timezone;
		cap_fp = fopen(CAPTURE_FILE_NAME, "wb+");
		if (cap_fp == NULL) {
			perror("fopen");
			close(soc);
			return -1;
		}
		memset(&pcap_header, 0, sizeof(struct pcap_file_header));
		pcap_header.magic = TCPDUMP_MAGIC;
		pcap_header.version_major = PCAP_VERSION_MAJOR;
		pcap_header.version_minor = PCAP_VERSION_MINOR;
		jp_timezone = 3600 * 9;
		pcap_header.thiszone = jp_timezone;
		pcap_header.sigfigs = 0;
		pcap_header.snaplen = 2048;
		pcap_header.linktype = DLT_EN10MB;
		fwrite(&pcap_header, sizeof(struct pcap_file_header), 1, cap_fp);
#endif
	while (1) {
		if((size = read(soc, buf, sizeof(buf))) <= 0) {
			perror("read");
		} else {
			if (analyze_packet(buf, size) == -1) {
				close(soc);
				return -1;
			}
#if defined(PCAP)
			struct pcap_pkthdr pcap_pkt_hdr;
			gettimeofday(&pcap_pkt_hdr.ts, NULL);
			pcap_pkt_hdr.len = pcap_pkt_hdr.caplen = size;
			fwrite(&pcap_pkt_hdr, sizeof(struct pcap_pkthdr), 1, cap_fp);
			fwrite(buf, size, 1, cap_fp);
#endif
		}
	}
	close(soc);
	return 0;
}

int initialize_raw_socket(char *ifdev) {
	struct ifreq ifreq;
	struct sockaddr_ll sa;
	int soc;

	if((soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket");
		return -1;
	}

	memset(&ifreq, 0, sizeof(struct ifreq));
	if (strlen(ifdev) >= sizeof(ifreq.ifr_name)) {
		fprintf(stderr, "%s: too long interface name.\n", ifdev);
		close(soc);
		return -1;
	}
	strcpy(ifreq.ifr_name, ifdev);

	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0) {
		perror("ioctl");
		close(soc);
		return -1;
	}
	sa.sll_ifindex = ifreq.ifr_ifindex;
	if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		close(soc);
		return -1;
	}

	if(set_promiscuous_mode(soc, &ifreq)) {
		return -1;
	}
	return soc;
}

int set_promiscuous_mode(int soc, struct ifreq *req) {
	if (ioctl(soc, SIOCGIFFLAGS, req) < 0) {
		perror("ioctl");
		close(soc);
		return -1;
	}
	req->ifr_flags = req->ifr_flags | IFF_PROMISC;
	if (ioctl(soc, SIOCSIFFLAGS, req) < 0) {
		perror("ioctl");
		close(soc);
		return -1;
	}
	return 0;
}
