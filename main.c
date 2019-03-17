#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "analyze.h"
#include <pcap.h>
#include <pcap/dlt.h>

#define PCAP_FILE_NAME "test.pcap"
#define TCPDUMP_MAGIC 0xa1b2c3d4
#define BUFFER_LENGTH 65535

int initialize_raw_socket(char *ifname);
int set_promiscuous_mode(int soc, struct ifreq *req);

int main(int argc, char *argv[]) {
	int soc, size;
	u_char buf[BUFFER_LENGTH];
	FILE *capfp;
	struct pcap_file_header pcaphdr;
	struct pcap_pkthdr pkthdr4pcap;

	if (argc <= 1) {
		fprintf(stderr, "device-name");
	}
	if ((soc = initialize_raw_socket(argv[1])) == -1) {
		fprintf(stderr, "error @initialize_raw_socket: %s\n", argv[1]);
		return -1;
	}
	capfp = fopen(PCAP_FILE_NAME, "wb+");
	if (capfp == NULL) {
		perror("fopen");
		close(soc);
		return -1;
	}
	memset(&pcaphdr, 0, sizeof(struct pcap_file_header));
	pcaphdr.magic = TCPDUMP_MAGIC;
	pcaphdr.version_major = PCAP_VERSION_MAJOR;
	pcaphdr.version_minor = PCAP_VERSION_MINOR;
	pcaphdr.thiszone = -3600 * 9;
	pcaphdr.sigfigs = 0;
	pcaphdr.snaplen = 65535;
	pcaphdr.linktype = DLT_EN10MB;
	fwrite(&pcaphdr, sizeof(struct pcap_file_header), 1, capfp);
	while (1) {
		if((size = read(soc, buf, BUFFER_LENGTH)) <= 0) {
			perror("read");
		} else {
			if (analyze_packet(buf, size) == -1) {
				close(soc);
				return -1;
			}
			gettimeofday(&pkthdr4pcap.ts, NULL);
			pkthdr4pcap.len = pkthdr4pcap.caplen = size;
			fwrite(&pkthdr4pcap, sizeof(struct pcap_pkthdr), 1, capfp);
			fwrite(buf, size, 1, capfp);
		}
	}
	close(soc);
	return 0;
}

int initialize_raw_socket(char *ifname) {
	struct ifreq myif;
	struct sockaddr_ll myaddr;
	int soc;

	if((soc = socket(AF_PACKET, SOCK_RAW, htonl(ETH_P_ALL))) == -1) {
		perror("socket");
		return -1;
	}
	// All We have to do is specify ifreq.ifr_name to use network interface device.
	// for detail, refer to "man 7 netdevice"
	memset(&myif, 0, sizeof(struct ifreq));
	strncpy(myif.ifr_name, ifname, sizeof(myif.ifr_name) - 1);
	if (ioctl(soc, SIOCGIFINDEX, &myif) == -1) {
		perror("ioctl");
		close(soc);
		return -1;
	}
	// bind systemcall only use following members of sockaddr_ll structure.
	// for detail, refer to "man 7 packet"
	myaddr.sll_family = AF_PACKET;
	myaddr.sll_protocol = htons(ETH_P_ALL);
	myaddr.sll_ifindex = myif.ifr_ifindex;
	if (bind(soc, (struct sockaddr *)&myaddr, sizeof(struct sockaddr_ll)) < 0) {
		perror("bind");
		close(soc);
		return -1;
	}
	if(set_promiscuous_mode(soc, &myif)) {
		return -1;
	}
	return soc;
}

int set_promiscuous_mode(int soc, struct ifreq *myif) {
	if (ioctl(soc, SIOCGIFFLAGS, myif) < 0) {
		perror("ioctl");
		close(soc);
		return -1;
	}
	myif->ifr_flags = myif->ifr_flags | IFF_PROMISC;
	if (ioctl(soc, SIOCSIFFLAGS, myif) < 0) {
		perror("ioctl");
		close(soc);
		return -1;
	}
	return 0;
}
