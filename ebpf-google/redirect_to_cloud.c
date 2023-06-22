#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
BPF_DEVMAP(tx_port, 1);
BPF_PERCPU_ARRAY(rxcnt, long, 1);
static inline void swap_src_dst_mac(void *data)
{
    unsigned short *p = data;
    unsigned short dst[3];
    dst[0] = p[0];
    dst[1] = p[1];
    dst[2] = p[2];
    p[0] = p[3];
    p[1] = p[4];
    p[2] = p[5];
    p[3] = dst[0];
    p[4] = dst[1];
    p[5] = dst[2];
}
int xdp_redirect_map(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iphdr;
    struct hdr_cursor nh;
    int eth_type, ip_type;
    uint32_t key = 0;
    long *value;
    uint64_t nh_off;

	// 172.16.1.11
	u_int32_t s_ip = 184619180;
	// 172.16.1.12
	u_int32_t d_ip = 201396396;
    bpf_trace_printk("from edge\\n");

    nh_off = sizeof(*eth);
    if (data + nh_off  > data_end)
        return XDP_DROP;
    value = rxcnt.lookup(&key);
    if (value)
        *value += 1;
    swap_src_dst_mac(data);
    // eth_type = parse_ethhdr(&nh, data_end, &eth);
	// if (eth_type == -1){
	// 	return XDP_PASS;
	// }
    // if (eth_type == bpf_htons(ETH_P_IP)) {
	// 	ip_type = parse_iphdr(&nh, data_end, &iphdr);	
    //     if (ip_type == -1){
	// 	    return XDP_PASS;
	//     }
    //     iphdr->saddr = s_ip;
    //     iphdr->daddr = d_ip;
	// } 
    return tx_port.redirect_map(0, 0);
}
int xdp_dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}