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

int initialize_raw_socket(char *ifdev);
int set_promiscuous_mode(int soc, struct ifreq *req);

int main(int argc, char *argv[]) {
	int soc, size;
	u_char buf[65535];

	if (argc != 1) {
		fprintf(stderr, "device-name");
	}
	if ((soc = initialize_raw_socket(argv[1])) == -1) {
		fprintf(stderr, "initialize_raw_socket:error: %s\n", argv[1]);
		return -1;
	}
	while (1) {
		if((size = read(soc, buf, sizeof(buf))) <= 0) {
			perror(read);
		} else {
			if (analyze_packet(buf, size) == -1) {
			close(soc);
				return -1;
			}
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
