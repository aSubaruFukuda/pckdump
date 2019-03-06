int print_ethernet_header(struct ether_header *eh, FILE *fp);
int print_arp_header(struct ether_arp *arp, FILE *fp);
int print_ip_header(struct iphdr *ip, u_char *option, int option_len, FILE *fp);
int print_ip6_header(struct ip6_hdr *ip6, FILE *fp);
int print_icmp_header(struct icmp *icmp, FILE *fp);
int print_icmp6_header(struct icmp6_hdr *icmp6, FILE *fp);
int print_tcp_header(struct tcphdr *tcp, FILE *fp);
int print_udp_header(struct udphdr *udp, FILE *fp);
