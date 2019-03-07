int show_ethernet_header(struct ether_header *eh, FILE *fp);
int show_arp_header(struct ether_arp *arp, FILE *fp);
int show_ip_header(struct iphdr *ip, u_char *option, int option_len, FILE *fp);
int show_ipv6_header(struct ip6_hdr *ip6, FILE *fp);
int show_icmp_header(struct icmp *icmp, FILE *fp);
int show_icmpv6_header(struct icmp6_hdr *icmp6, FILE *fp);
int show_tcp_header(struct tcphdr *tcp, FILE *fp);
int show_udp_header(struct udphdr *udp, FILE *fp);
