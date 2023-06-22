#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "../common/bpf_helpers.h"
#include "../common/bpf_endian.h"

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
// #include "../common/xdp_stats_kern_user.h"
// #include "../common/xdp_stats_kern.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define SWAP_ORDER_16(X) ( (((X) & 0xff00) >> 8) | (((X) & 0xff) << 8))
#define MAX_TCP_SIZE 1480

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

static __always_inline unsigned short generic_checksum(unsigned short volatile *buf, void *data_end, unsigned long sum, int max) {
    
    for (int i = 0; i < max; i += 2) {
	if ((void *)(buf + 1) > data_end)
	    break;
        sum += *buf;
        buf++;
    }

    if((void *)buf +1 <= data_end) {
	sum +=  bpf_htons((*((unsigned char *)buf)) << 8);
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static __always_inline unsigned short ipv4_checksum(unsigned short *buf, void *data_end)
{
    return generic_checksum(buf, data_end, 0, sizeof(struct iphdr));
}

static __always_inline __u32 l4_checksum(struct iphdr *iph, void *l4, void *data_end)
{
    __u16 csum = 0;
    csum += *(((__u16 *) &(iph->saddr))+0); // 1st 2 bytes
    csum += *(((__u16 *) &(iph->saddr))+1); // 2nd 2 bytes
    csum += *(((__u16 *) &(iph->daddr))+0); // 1st 2 bytes
    csum += *(((__u16 *) &(iph->daddr))+1); // 2nd 2 bytes
    csum += bpf_htons((__u16)iph->protocol); // protocol is a u8
    csum += bpf_htons((__u16)(data_end - (void *)l4)); 
    return generic_checksum((unsigned short *) l4, data_end, csum, MAX_TCP_SIZE);
}

int xdp_redirect_to_lan_func(struct xdp_md *ctx)
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
    // 192.168.11.2
	u_int32_t s_ip = 17541312;
    // 192.168.11.255
	// u_int32_t d_ip = 4278954176;
	// 192.168.11.1
	u_int32_t d_ip = 17541312;
    // src: 80:ee:73:e0:0b:27
	src[0] = 128;
	src[1] = 238;
	src[2] = 115;
	src[3] = 224;
	src[4] = 11;
	src[5] = 39;
	// dst: 80:ee:73:e0:0c:31
    dst[0] = 128;
	dst[1] = 238;
	dst[2] = 115;
	dst[3] = 224;
	dst[4] = 12;
	dst[5] = 49;

	unsigned ifindex = 3/* TODO: put your values here */;
    bpf_trace_printk("to edge\\n");

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1){
		goto out;
	}
	/* Set a proper destination address */
	bpf_trace_printk("%d", bpf_htons(eth_type));

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type == -1){
			goto out;
		}
		bpf_trace_printk("this is ip\\n");
		if (ip_type == IPPROTO_ICMP){
			bpf_trace_printk("this is icmp\\n");
			icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
			if (icmp_type == ICMP_ECHO){
				bpf_trace_printk("this is icmp request\\n");
				// memcpy(eth->h_source, src, ETH_ALEN);
				memcpy(eth->h_dest, dst, ETH_ALEN);
				// iphdr->saddr = s_ip;
				// iphdr->daddr = d_ip;
				// iphdr->check = 0;
    			// iphdr->check = checksum((unsigned short *)iphdr, sizeof(struct iphdr));
				action = bpf_redirect(ifindex, 0);
			}
			if (icmp_type == ICMP_ECHOREPLY){
				bpf_trace_printk("this is icmp reply\\n");
				// memcpy(eth->h_source, src, ETH_ALEN);
				memcpy(eth->h_dest, dst, ETH_ALEN);
				// iphdr->saddr = s_ip;
				// iphdr->daddr = d_ip;
				// iphdr->check = 0;
    			// iphdr->check = checksum((unsigned short *)iphdr, sizeof(struct iphdr));
				action = bpf_redirect(ifindex, 0);
			}
		}
		if (ip_type == IPPROTO_TCP){		
			// tcphdr = iphdr + 1;
    		// if (tcphdr + 1 > data_end)
			// 	return XDP_DROP;	
			// bpf_trace_printk("this is tcp\\n");
			// iphdr->ttl = 1;
            // memcpy(eth->h_source, src, ETH_ALEN);
			// memcpy(eth->h_dest, dst, ETH_ALEN);
			// iphdr->saddr = s_ip;
			// iphdr->daddr = d_ip;
			// iphdr->check = 0;
    		// iphdr->check = checksum((unsigned short *)iphdr, sizeof(struct iphdr));
			// iphdr->check = 0;
			// iphdr->check = ipv4_checksum((void *) iphdr, (void *) tcphdr);
			// tcphdr->check = 0;
			// tcphdr->check = l4_checksum(iphdr, tcphdr, data_end);
			// action = bpf_redirect(ifindex, 0);
			goto out;
		} else if (ip_type == IPPROTO_UDP){	
			// 	udphdr = iphdr + 1;
			// 	if (udphdr + 1 > data_end)
			// 		return XDP_DROP;	
			// 	bpf_trace_printk("this is udp\\n");
			// 	// iphdr->ttl = 1;
			//     memcpy(eth->h_source, src, ETH_ALEN);
			// 	memcpy(eth->h_dest, dst, ETH_ALEN);
			// 	iphdr->saddr = s_ip;
			// 	iphdr->daddr = d_ip;
			// 	// iphdr->check = 0;
			// 	// iphdr->check = checksum((unsigned short *)iphdr, sizeof(struct iphdr));
			// 	iphdr->check = 0;
			// 	iphdr->check = ipv4_checksum((void *) iphdr, udphdr);
			// 	udphdr->check = 0;
			// 	udphdr->check = l4_checksum(iphdr, udphdr, data_end);	
			// action = bpf_redirect(ifindex, 0);		
			goto out;
		}else{
			// memcpy(eth->h_source, src, ETH_ALEN);
			memcpy(eth->h_dest, dst, ETH_ALEN);
			// iphdr->saddr = s_ip;
			// iphdr->daddr = d_ip;
			// iphdr->check = 0;
			// iphdr->check = checksum((unsigned short *)iphdr, sizeof(struct iphdr));
			action = bpf_redirect(ifindex, 0);
		}
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		// ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		goto out;
	} else {
		goto out;
	}

	out:
		return action;
}

int xdp_redirect_to_container_func(struct xdp_md *ctx)
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
	// src: 02:42:ac:12:00:03 
	src[0] = 2;
	src[1] = 66;
	src[2] = 172;
	src[3] = 18;
	src[4] = 0;
	src[5] = 3;
	// dst: 02:42:ac:13:00:02
	dst[0] = 2;
	dst[1] = 66;
	dst[2] = 172;
	dst[3] = 19;
	dst[4] = 0;
	dst[5] = 2;

	unsigned ifindex = 22 /* TODO: put your values here */;
	// 172.18.0.3
	u_int32_t s_ip = 50336428;
	// 172.19.0.2
	u_int32_t d_ip = 33559468;
    bpf_trace_printk("from edge\\n");

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
		if (ip_type == IPPROTO_ICMP){
			bpf_trace_printk("this is icmp\\n");
			icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
			if (icmp_type == ICMP_ECHOREPLY){
				bpf_trace_printk("this is icmp reply\\n");
				// memcpy(eth->h_source, src, ETH_ALEN);
				memcpy(eth->h_dest, dst, ETH_ALEN);
				// iphdr->saddr = s_ip;
				iphdr->daddr = d_ip;
				iphdr->check = 0;
    			iphdr->check = checksum((unsigned short *)iphdr, sizeof(struct iphdr));
				action = bpf_redirect(ifindex, 0);
			}
			if (icmp_type == ICMP_ECHO){
				bpf_trace_printk("this is icmp request\\n");
				// memcpy(eth->h_source, src, ETH_ALEN);
				memcpy(eth->h_dest, dst, ETH_ALEN);
				// iphdr->saddr = s_ip;
				iphdr->daddr = d_ip;
				iphdr->check = 0;
    			iphdr->check = checksum((unsigned short *)iphdr, sizeof(struct iphdr));
				action = bpf_redirect(ifindex, 0);
			}
		}
		if (ip_type == IPPROTO_TCP){	
			tcphdr = iphdr + 1;
    		if (tcphdr + 1 > data_end)
				return XDP_DROP;	
			unsigned long sum = SWAP_ORDER_16(tcphdr->check) + iphdr->saddr + ((~s_ip & 0xffff) + 1);
			tcphdr->check = SWAP_ORDER_16(sum & 0xffff);
			sum = SWAP_ORDER_16(tcphdr->check) + iphdr->daddr + ((~d_ip & 0xffff) + 1);
			tcphdr->check = SWAP_ORDER_16(sum & 0xffff);
			// unsigned long sum = iphdr->saddr + (~ntohs(*(unsigned short *)&s_ip) & 0xffff) ;
			// sum += ntohs(tcphdr->check);
			// sum = (sum & 0xffff) + (sum>>16);
			// tcphdr->check = htons(sum + (sum>>16) + 1);
			// sum = iphdr->daddr + (~ntohs(*(unsigned short *)&d_ip) & 0xffff);
			// sum += ntohs(tcphdr->check);
			// sum = (sum & 0xffff) + (sum>>16);
			// tcphdr->check = htons(sum + (sum>>16) + 1);
            bpf_trace_printk("this is udp\\n");
            memcpy(eth->h_source, src, ETH_ALEN);
			memcpy(eth->h_dest, dst, ETH_ALEN);
			iphdr->saddr = s_ip;
			iphdr->daddr = d_ip;
			iphdr->check = 0;
			iphdr->check = checksum((unsigned short *)iphdr, sizeof(struct iphdr));
			action = bpf_redirect(ifindex, 0);
		}else{
			if (ip_type == -1){
				goto out;
			}
			// memcpy(eth->h_source, src, ETH_ALEN);
			memcpy(eth->h_dest, dst, ETH_ALEN);
			// iphdr->saddr = s_ip;
			iphdr->daddr = d_ip;
			iphdr->check = 0;
			iphdr->check = checksum((unsigned short *)iphdr, sizeof(struct iphdr));
			action = bpf_redirect(ifindex, 0);
		}
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}

out:
	return action;
}