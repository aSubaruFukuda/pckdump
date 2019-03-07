#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
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
#include <arpa/inet.h>

char *get_mac_addr_str(u_char *hwaddr, char *buf, socklen_t size) {
	snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
			hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	return buf;
}
char *get_ip4arp_str(u_int8_t *ip, char *buf, socklen_t size) {
	snprintf(buf, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
	return buf;
}
char *get_ip4ip_str(u_int32_t *ip, char *buf, socklen_t size) {
	struct in_addr *addr;
	addr = (struct in_addr *)ip;
	inet_ntop(AF_INET, addr, buf, size);
	return buf;
}
char *get_ip6addr_str(void *ip6_addr, char *buf, socklen_t size) {
	inet_ntop(AF_INET6, ip6_addr, buf, size);
	return buf;
}
int get_icmp_type_and_code_str(
		uint8_t icmp_type, char *type_buf, socklen_t type_buf_size,
		uint8_t icmp_code, char *code_buf, socklen_t code_buf_size) {
	int type_arr_len;
	int code_unrech_arr_len;
	int code_redirect_arr_len;
	int code_tm_exceed_arr_len;

	char *type_arr[] = {
		"ICMP_ECHOREPLY",
		"undef",
		"undef",
		"ICMP_DEST_UNREACH",
		"ICMP_SOURCE_QUENCH",
		"ICMP_REDIRECT",
		"undef",
		"undef",
		"ICMP_ECHO",
		"undef",
		"undef",
		"ICMP_TIME_EXCEEDED",
		"ICMP_PARAMETERPROB",
		"ICMP_TIMESTAMP",
		"ICMP_TIMESTAMPREPLY",
		"ICMP_INFO_REQUEST",
		"ICMP_INFO_REPLY",
		"ICMP_ADDRESS",
		"ICMP_ADDRESSREPLY"
	};
	char *code_unrech_arr[] = {
		"ICMP_NET_UNREACH",
		"ICMP_HOST_UNREACH",
		"ICMP_PROT_UNREACH",
		"ICMP_PORT_UNREACH",
		"ICMP_FRAG_NEEDED",
		"ICMP_SR_FAILED",
		"ICMP_NET_UNKNOWN",
		"ICMP_HOST_UNKNOWN",
		"ICMP_HOST_ISOLATED",
		"ICMP_NET_ANO",
		"ICMP_HOST_ANO",
		"ICMP_NET_UNR_TOS",
		"ICMP_HOST_UNR_TOS",
		"ICMP_PKT_FILTERED",
		"ICMP_PREC_VIOLATION",
		"ICMP_PREC_CUTOFF"
	};
	char *code_redirect_arr[] = {
		"ICMP_REDIR_NET",
		"ICMP_REDIR_HOST",
		"ICMP_REDIR_NETTOS",
		"ICMP_REDIR_HOSTTOS"
	};
	char *code_tm_exceed_arr[] = {
		"ICMP_EXC_TTL",
		"ICMP_EXC_FRAGTIME"
	};
	type_arr_len = sizeof(type_arr);
	code_unrech_arr_len = sizeof(code_unrech_arr) / sizeof (char *);
	code_redirect_arr_len = sizeof(code_redirect_arr) / sizeof (char *);
	code_tm_exceed_arr_len = sizeof(code_tm_exceed_arr) / sizeof (char *);
	if (icmp_type < (type_arr_len - 1)) {
		strncpy(type_buf, type_arr[icmp_type], type_buf_size);
	}else {
		snprintf(type_buf, type_buf_size, "unknown type");
	}
	switch (icmp_type) {
		case ICMP_DEST_UNREACH:
			if (icmp_code < (code_unrech_arr_len - 1)) {
				strncpy(code_buf, code_unrech_arr[icmp_code], code_buf_size);
			}else {
				snprintf(code_buf, code_buf_size, "unknown code");
			}
			break;
		case ICMP_REDIRECT:
			if (icmp_code < (code_redirect_arr_len - 1)) {
				strncpy(code_buf, code_redirect_arr[icmp_code], code_buf_size);
			}else {
				snprintf(code_buf, code_buf_size, "unknown code");
			}
			break;
		case ICMP_TIME_EXCEEDED:
			if (icmp_code < (code_tm_exceed_arr_len - 1)) {
				strncpy(code_buf, code_tm_exceed_arr[icmp_code], code_buf_size);
			}else {
				snprintf(code_buf, code_buf_size, "unknown code");
			}
			break;
		default:
			snprintf(code_buf, code_buf_size, "no code");
			break;
	}
	return 0;
}

int *get_icmp6_type_and_code_str(
		uint8_t icmp6_type, char *type_buf, socklen_t type_buf_size,
		uint8_t icmp6_code, char *code_buf, socklen_t code_buf_size) {

	char *type_arr1[] = {
		"ICMP6_DST_UNREACH",
		"ICMP6_PACKET_TOO_BIG",
		"ICMP6_TIME_EXCEEDED",
		"ICMP6_PARAM_PROB"
	};
	char *type_arr2[] = {
		"ICMP6_ECHO_REQUEST",
		"ICMP6_ECHO_REPLY",
		"MLD_LISTENER_QUERY",
		"MLD_LISTENER_REPORT",
		"MLD_LISTENER_REDUCTION",
		"ND_ROUTER_SOLICIT",
		"ND_ROUTER_ADVERT",
		"ND_NEIGHBOR_SOLICIT",
		"ND_NEIGHBOR_ADVERT",
		"ND_REDIRECT"
	};
	char *code_arr1[] = {
		"ICMP6_DST_UNREACH_NOROUTE",
		"ICMP6_DST_UNREACH_ADMIN",
		"ICMP6_DST_UNREACH_BEYONDSCOPE",
		"ICMP6_DST_UNREACH_ADDR",
		"ICMP6_DST_UNREACH_NOPORT"
	};
	char *code_arr2[] = {
		"ICMP6_TIME_EXCEED_TRANSIT",
		"ICMP6_TIME_EXCEED_REASSEMBLY"
	};
	char *code_arr3[] = {
		"ICMP6_PARAMPROB_HEADER",
		"ICMP6_PARAMPROB_NEXTHEADER",
		"ICMP6_PARAMPROB_OPTION"
	};
	if (icmp6_type != 0 && icmp6_type <= 4) {
		strncpy(type_buf, type_arr1[icmp6_type], type_buf_size);
	} else if (128 <= icmp6_type && icmp6_type <= 137) {
		strncpy(type_buf, type_arr2[icmp6_type-128], type_buf_size);
	}else {
		snprintf(type_buf, type_buf_size, "unknown");
	}
	if (icmp6_type == ICMP6_DST_UNREACH && icmp6_code < sizeof(code_arr1)) {
		strncpy(code_buf, code_arr1[icmp6_code], code_buf_size);
	} else if (icmp6_type == ICMP6_TIME_EXCEEDED && icmp6_code < sizeof(code_arr2)) {
		strncpy(code_buf, code_arr2[icmp6_code], code_buf_size);
	} else if (icmp6_type == ICMP6_PARAM_PROB && icmp6_code < sizeof(code_arr3)) {
		strncpy(code_buf, code_arr3[icmp6_code], code_buf_size);
	} else {
		snprintf(code_buf, code_buf_size, "unknown");
	}
	return 0;
}
int show_ethernet_header(struct ether_header *eh, FILE *fp) {
	char buf[128];
	fprintf(fp, "----------ETHERNET HEADER----------\n");
	fprintf(fp, "dest=%s\n", get_mac_addr_str(eh->ether_dhost, buf, sizeof(buf)));
	fprintf(fp, "src=%s\n", get_mac_addr_str(eh->ether_shost, buf, sizeof(buf)));
	fprintf(fp, "type=%02X", ntohs(eh->ether_type));
	switch(ntohs(eh->ether_type)) {
		case ETHERTYPE_IP:
			fprintf(fp, "(IP)\n");
			break;
		case ETHERTYPE_IPV6:
			fprintf(fp, "(IPv6)\n");
			break;
		case ETHERTYPE_ARP:
			fprintf(fp, "(ARP)\n");
			break;
		default:
			fprintf(fp, "(unknown)\n");
			break;
	}
	return 0;
}

int show_arp_header(struct ether_arp *arp, FILE *fp) {
	char buf[128];

	fprintf(fp, "----------ARP HEADER----------\n");
	if (ntohs(arp->arp_hrd) == 0x0001) {
		fprintf(fp, "hw_type=%04x(Ethernet)\n", arp->arp_hrd);
	} else {
		fprintf(fp, "hw_type=%04x(unknown)\n", arp->arp_hrd);
	}
	if (ntohs(arp->arp_pro) == 0x0001) {
		fprintf(fp, "proto_type=%04x(IP)\n", arp->arp_pro);
	} else {
		fprintf(fp, "proto_type=%04x(unknown)\n", arp->arp_pro);
	}
	if (arp->arp_hln == 0x06) {
		fprintf(fp, "hw_len=%02x(MAC length)\n", arp->arp_hln);
	} else {
		fprintf(fp, "hw_len=%02x(unknown)\n", arp->arp_hln);
	}
	if (arp->arp_pln == 0x01) {
		fprintf(fp, "proto_len=%02x(IP length)\n", arp->arp_pln);
	} else {
		fprintf(fp, "proto_len=%02x(unknown)\n", arp->arp_pln);
	}
	if (ntohs(arp->arp_op) == ARPOP_REQUEST) {
		fprintf(fp, "operation=%04x(REQUEST)\n", ntohs(arp->arp_op));
	} else if (ntohs(arp->arp_op) == ARPOP_REPLY) {
		fprintf(fp, "operation=%04x(REPLY)\n", ntohs(arp->arp_op));
	} else {
		fprintf(fp, "operation=%04x(unknown)\n", ntohs(arp->arp_op));
	}
	fprintf(fp, "hw_src=%s\n", get_mac_addr_str(arp->arp_sha, buf, sizeof(buf)));
	fprintf(fp, "ip_src=%s\n", get_ip4arp_str(arp->arp_spa, buf, sizeof(buf)));
	fprintf(fp, "hw_dst=%s\n", get_mac_addr_str(arp->arp_tha, buf, sizeof(buf)));
	fprintf(fp, "ip_dst=%s\n", get_ip4arp_str(arp->arp_tpa, buf, sizeof(buf)));
	return 0;
}

int show_ip_header(struct iphdr *ip, u_char *option, int option_len, FILE *fp) {
	char buf[128];
	int i;
	uint8_t ip_type;

	fprintf(fp, "----------IPv4 HEADER----------\n");
	fprintf(fp, "version=%u\n", ip->version);
	fprintf(fp, "hdr_len=%u\n", ip->ihl);
	fprintf(fp, "tos=%02X\n", ip->tos);
	fprintf(fp, "total_len=%u\n", ntohs(ip->tot_len));
	fprintf(fp, "id=%u\n", ntohs(ip->id));
	//flag_off
	fprintf(fp, "ttl=%u\n", ntohs(ip->ttl));
	ip_type = ip->protocol;
	switch(ip_type) {
		case IPPROTO_ICMP:
			fprintf(fp, "proto_type=%02X(%s)\n", ip_type, "ICMP");
			break;
		case IPPROTO_TCP:
			fprintf(fp, "proto_type=%02X(%s)\n", ip_type, "TCP");
			break;
		case IPPROTO_UDP:
			fprintf(fp, "proto_type=%02X(%s)\n", ip_type, "UDP");
			break;
		default:
			fprintf(fp, "proto_type=%02X(%s)\n", ip_type, "unknown");
			break;
	}
	fprintf(fp, "check=%04X\n", ntohs(ip->check));
	fprintf(fp, "src_addr=%s\n", get_ip4ip_str(&ip->saddr, buf, sizeof(buf)));
	fprintf(fp, "src_addr=%s\n", get_ip4ip_str(&ip->daddr, buf, sizeof(buf)));
	if (option_len) {
		fprintf(fp, "option:");
		for (i = 0; i < option_len; i++) {
			if (i==0) {
				fprintf(fp, "%02x", option[i]);
			} else {
				fprintf(fp, ":%02x", option[i]);
			}
		}
	}
	return 0;
}

int show_ipv6_header(struct ip6_hdr *ip6, FILE *fp) {
	char buf[128];
	uint8_t nxt_hdr;
	uint32_t ip6_flow_le;
	uint32_t ver, tc, fl;

	fprintf(fp, "----------IPv6 HEADER----------\n");
	ip6_flow_le = ntohs(ip6->ip6_flow);
	ver = ip6_flow_le >> 28;
	fprintf(fp, "ver=%u\n", ver);
	tc = (ip6_flow_le & 0x0FF00000) >> 20;
	fprintf(fp, "TrCl=%x\n", tc);
	fl = (ip6_flow_le & 0x000FFFFF);
	fprintf(fp, "flow_label=%x\n", fl);
	fprintf(fp, "payload_len=%u\n", ntohs(ip6->ip6_plen));
	nxt_hdr = ip6->ip6_nxt;
	switch(nxt_hdr) {
		case IPPROTO_ICMPV6:
			fprintf(fp, "nxt_hdr=%02X(%s)\n", nxt_hdr, "ICMPv6");
			break;
		case IPPROTO_TCP:
			fprintf(fp, "nxt_hdr=%02X(%s)\n", nxt_hdr, "TCP");
			break;
		case IPPROTO_UDP:
			fprintf(fp, "nxt_hdr=%02X(%s)\n", nxt_hdr, "UDP");
			break;
		default:
			fprintf(fp, "nxt_hdr=%02X(%s)\n", nxt_hdr, "unknown");
			break;
	}
	fprintf(fp, "hop_lim=%u\n", ip6->ip6_hlim);
	fprintf(fp, "src_addr=%s\n", get_ip6addr_str(&ip6->ip6_src, buf, sizeof(buf)));
	fprintf(fp, "dst_addr=%s\n", get_ip6addr_str(&ip6->ip6_dst, buf, sizeof(buf)));
	return 0;
}

int show_icmp_header(struct icmp *icmp, FILE *fp) {
	char buf1[64], buf2[64];

	fprintf(fp, "----------ICMP HEADER----------\n");
	get_icmp_type_and_code_str(
			icmp->icmp_type, buf1, sizeof(buf1), icmp->icmp_code, buf2, sizeof(buf2));
	fprintf(fp, "type=%u(%s)\n", icmp->icmp_type, buf1);
	fprintf(fp, "code=%u(%s)\n", icmp->icmp_code, buf2);
	fprintf(fp, "cksum=%u\n", ntohs(icmp->icmp_cksum));
	if (icmp->icmp_type == ICMP_ECHO || icmp->icmp_type == ICMP_ECHOREPLY) {
		fprintf(fp, "id=%u\n", ntohs(icmp->icmp_id));
		fprintf(fp, "seq=%u\n", ntohs(icmp->icmp_seq));
	}
	return 0;
}

int show_icmpv6_header(struct icmp6_hdr *icmp6, FILE *fp) {
	char buf1[64], buf2[64];

	fprintf(fp, "----------ICMPv6 HEADER----------\n");
	get_icmp6_type_and_code_str(
			icmp6->icmp6_type, buf1, sizeof(buf1), icmp6->icmp6_code, buf2, sizeof(buf2));
	fprintf(fp, "type=%u(%s)\n", icmp6->icmp6_type, buf1);
	fprintf(fp, "code=%u(%s)\n", icmp6->icmp6_code, buf2);
	fprintf(fp, "cksum=%u\n", ntohs(icmp6->icmp6_cksum));
	if (icmp6->icmp6_type == ICMP6_ECHO_REQUEST || icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
		fprintf(fp, "id=%u\n", ntohs(icmp6->icmp6_id));
		fprintf(fp, "seq=%u\n", ntohs(icmp6->icmp6_seq));
	}
	return 0;
}

int show_tcp_header(struct tcphdr *tcp, FILE *fp) {
	fprintf(fp, "----------TCP HEADER----------\n");
	fprintf(fp, "src=%u\n", ntohs(tcp->source));
	fprintf(fp, "dst=%u\n", ntohs(tcp->dest));
	fprintf(fp, "seq=%u\n", ntohs(tcp->seq));
	fprintf(fp, "ack_seq=%u\n", ntohs(tcp->ack_seq));
	fprintf(fp, "data_ofs=%u\n", ntohs(tcp->doff));
	fprintf(fp, "urg_flg=%u\n", ntohs(tcp->urg));
	fprintf(fp, "ack_flg=%u\n", ntohs(tcp->ack));
	fprintf(fp, "psh_flg=%u\n", ntohs(tcp->psh));
	fprintf(fp, "rst_flg=%u\n", ntohs(tcp->rst));
	fprintf(fp, "syn_flg=%u\n", ntohs(tcp->syn));
	fprintf(fp, "fin_flg=%u\n", ntohs(tcp->fin));
	fprintf(fp, "window=%u\n", ntohs(tcp->window));
	fprintf(fp, "cksum=%u\n", ntohs(tcp->check));
	fprintf(fp, "urg_ptr=%u\n", ntohs(tcp->urg_ptr));
	return 0;
}
int show_udp_header(struct udphdr *udp, FILE *fp) {
	fprintf(fp, "----------UDP HEADER----------\n");
	fprintf(fp, "src=%u\n", ntohs(udp->source));
	fprintf(fp, "dst=%u\n", ntohs(udp->dest));
	fprintf(fp, "len=%u\n", ntohs(udp->len));
	fprintf(fp, "cksum=%u\n", ntohs(udp->check));
	return 0;
}

