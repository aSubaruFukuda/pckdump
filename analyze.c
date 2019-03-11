#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "show.h"
#include "analyze.h"

int analyze_packet(u_char *data, int size) {
	printf("PACKET START=====================================>\n");
	analyze_ether(data, size);
	printf("<=======================================PACKET END\n");
	return 0;
}

int analyze_ether(u_char *data, int size) {
	u_char *ptr;
	int rest;
	struct ether_header *eh;
	u_int16_t eth_type;

	ptr = data;
	rest = size;
	if (rest < sizeof(struct ether_header)) {
		fprintf(stderr, "rest(%d) < sizeof(struct ether_header)\n", rest);
		return -1;
	}
	eh = (struct ether_header *)ptr;
	ptr += sizeof(struct ether_header);
	rest -= sizeof(struct ether_header);
	show_ethernet_header(eh, stdout);
	eth_type = ntohs(eh->ether_type);
	switch (eth_type) {
		case ETHERTYPE_ARP:
			analyze_arp(ptr, rest);
			break;
		case ETHERTYPE_IP:
			analyze_ip(ptr, rest);
			break;
		case ETHERTYPE_IPV6:
			analyze_ipv6(ptr, rest);
			break;
		default:
			fprintf(stderr, "unsupported ETHERNET TYPE: %04X", eth_type);
	}
	return 0;
}

int analyze_arp(u_char *data, int size) {
	u_char *ptr;
	int rest;
	struct ether_arp *arp;

	ptr = data;
	rest = size;
	if (rest < sizeof(struct ether_arp)) {
		fprintf(stderr, "rest(%d)<sizeof(struct ether_arp)\n", rest);
		return -1;
	}
	arp = (struct ether_arp *)ptr;
	ptr += sizeof(struct ether_arp);
	rest -= sizeof(struct ether_arp);
	show_arp_header(arp, stdout);
	return 0;
}

int analyze_ip(u_char *data, int size) {
	u_char *ptr;
	int rest;
	struct iphdr *iphdr;
	u_char *option;
	int option_len;
	u_int8_t ip_type;

	ptr = data;
	rest = size;
	if (rest < sizeof(struct iphdr)) {
		fprintf(stderr, "rest(%d)<sizeof(struct iphdr)\n", rest);
		return -1;
	}
	iphdr = (struct iphdr *)ptr;
	ptr += sizeof(struct iphdr);
	rest -= sizeof(struct iphdr);
	option_len = iphdr->ihl * 4 - sizeof(struct iphdr);
	if (option_len > 0) {
		if (1500 <= option_len) {
			fprintf(stderr, "IP option_len(%d):too big\n", option_len);
			return -1;
		}
		option = ptr;
		ptr += option_len;
		rest -= option_len;
	}
	//if (checkIPchecksum(iphdr, option, option_len) == 0 ) {
	//	fprintf(stderr, "checksum error");
	//	return -1;
	//}
	show_ip_header(iphdr, option, option_len, stdout);
	ip_type = iphdr->protocol;
	switch(ip_type) {
		case IPPROTO_ICMP:
			analyze_icmp(ptr, rest);
			break;
		case IPPROTO_TCP:
			analyze_tcp(ptr, rest);
			break;
		case IPPROTO_UDP:
			analyze_udp(ptr, rest);
			break;
		default:
			fprintf(stderr, "unsupported IP protocol TYPE: %02X", ip_type);
			break;
	}
	return 0;
}

int analyze_ipv6(u_char *data, int size) {
	u_char *ptr;
	int rest;
	struct ip6_hdr *ip6;
	uint8_t ip6_type;

	ptr = data;
	rest = size;
	if (rest < sizeof(struct ip6_hdr)) {
		fprintf(stderr, "rest(%d)<sizeof(struct ip6_hdr)\n", rest);
		return -1;
	}
	ip6 = (struct ip6_hdr *)ptr;
	ptr += sizeof(struct ip6_hdr);
	rest -= sizeof(struct ip6_hdr);
	show_ipv6_header(ip6, stdout);
	ip6_type = ip6->ip6_nxt;
	switch(ip6_type) {
		case IPPROTO_ICMPV6:
			analyze_icmp6(ptr, rest);
			break;
		case IPPROTO_TCP:
			analyze_tcp(ptr, rest);
			break;
		case IPPROTO_UDP:
			analyze_udp(ptr, rest);
			break;
		default:
			fprintf(stderr, "unsupported IPv6 next header type: %02X", ip6_type);
			break;
	}
	return 0;
}
int analyze_icmp(u_char *data, int size) {
	u_char *ptr;
	int rest;
	struct icmp *icmp;

	ptr = data;
	rest = size;
	if (rest < sizeof(struct icmp)) {
		fprintf(stderr, "rest(%d)<sizeof(struct icmp)\n", rest);
		return -1;
	}
	icmp = (struct icmp *)ptr;
	ptr += sizeof(struct icmp);
	rest -= sizeof(struct icmp);
	show_icmp_header(icmp, stdout);
	return 0;
}

int analyze_icmp6(u_char *data, int size) {
	u_char *ptr;
	int rest;
	struct icmp6_hdr *icmp6;

	ptr = data;
	rest = size;
	if (rest < sizeof(struct icmp6_hdr)) {
		fprintf(stderr, "rest(%d)<sizeof(struct icmp6_hdr)\n", rest);
		return -1;
	}
	icmp6 = (struct icmp6_hdr *)ptr;
	ptr += sizeof(struct icmp6_hdr);
	rest -= sizeof(struct icmp6_hdr);
	show_icmpv6_header(icmp6, stdout);
	return 0;
}

int analyze_tcp(u_char *data, int size) {
	u_char *ptr;
	int rest;
	struct tcphdr *tcphdr;

	ptr = data;
	rest = size;
	if (rest < sizeof(struct tcphdr)) {
		fprintf(stderr, "rest(%d)<sizeof(struct tcphdr)\n", rest);
		return -1;
	}
	tcphdr = (struct tcphdr *)ptr;
	ptr += sizeof(struct tcphdr);
	rest -= sizeof(struct tcphdr);
	show_tcp_header(tcphdr, stdout);
	return 0;
}

int analyze_udp(u_char *data, int size) {
	u_char *ptr;
	int rest;
	struct udphdr *udphdr;

	ptr = data;
	rest = size;
	if (rest < sizeof(struct udphdr)) {
		fprintf(stderr, "rest(%d)<sizeof(struct udphdr)\n", rest);
		return -1;
	}
	udphdr = (struct udphdr *)ptr;
	ptr += sizeof(struct udphdr);
	rest -= sizeof(struct udphdr);
	show_udp_header(udphdr, stdout);
	return 0;
}
