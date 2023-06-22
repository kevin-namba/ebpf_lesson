#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "../../common/bpf_helpers.h"
#include "../../common/bpf_endian.h"

// The parsing helper functions from the packet01 lesson have moved here
#include "../../common/parsing_helpers.h"
#include "../../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
// #include "../common/xdp_stats_kern_user.h"
// #include "../common/xdp_stats_kern.h"

static inline unsigned short checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;

    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}


int xdp_pass(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	struct ethhdr *eth;
	struct icmphdr_common *icmphdr;
	struct icmphdr_common icmphdr_old;
	int eth_type, ip_type, icmp_type;
	int action = XDP_PASS;
	__u16 echo_reply, old_csum;
    unsigned char src[ETH_ALEN];
	unsigned char dst[ETH_ALEN];
	// dst: 80:ee:73:e0:0b:27
	dst[0] = 128;
	dst[1] = 238;
	dst[2] = 115;
	dst[3] = 224;
	dst[4] = 11;
	dst[5] = 39;


	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1){
		goto out;
	}
	bpf_trace_printk("%d",eth_type);
	/* Set a proper destination address */

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type == -1){
			goto out;
		}
		if (iphdr->saddr == 17541312){
				bpf_trace_printk("this is icmp request\\n");
				// 192.168.11.2
				u_int32_t d_ip = 34318528;
				memcpy(eth->h_dest, dst, ETH_ALEN);
				iphdr->daddr = d_ip;
				iphdr->check = 0;
    			iphdr->check = checksum((unsigned short *)iphdr, sizeof(struct iphdr));
				action = XDP_PASS;
		} else {
			action = XDP_PASS;
		}
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}

out:
	return action;
}