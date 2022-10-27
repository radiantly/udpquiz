#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <stddef.h>
#include <string.h>

#include "bpf/bpf_helpers.h"

SEC("classifier")
int cls_main(struct __sk_buff *skb) {
    return -1;
}

SEC("action")
int act_main(struct __sk_buff *skb) {
    /* packet data is stored in skb->data */
    void *data = (void *)(long)skb->data;

    /* first we check that the packet has enough data to contain the eth, ip and udp headers */
    if (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + skb->data > skb->data_end)
        return TC_ACT_UNSPEC;

    struct ethhdr *eth = data;
    struct iphdr *ip = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    /* Check if ip packet */
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    /* Check if udp packet */
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_UNSPEC;

    /* We'll store the mac addresses (L2) */
    __u8 src_mac[ETH_ALEN];
    __u8 dst_mac[ETH_ALEN];

    memcpy(src_mac, eth->h_source, ETH_ALEN);
    memcpy(dst_mac, eth->h_dest, ETH_ALEN);

    /* ip addresses (L3) */
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    /* and source/destination ports (L4) */
    __be16 dest_port = udp->dest;
    __be16 src_port = udp->source;

    /* and then swap them all */

    /* Swap the mac addresses */
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, ETH_ALEN, 0);
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, ETH_ALEN, 0);

    /* Swap the ip addresses
     * swapping the ips does not require checksum recalculation,
     * but we might want to reduce the TTL to prevent packets infinitely looping between us and another device that does not reduce the TTL */
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, saddr), &dst_ip, sizeof(dst_ip), 0);
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), &src_ip, sizeof(src_ip), 0);

    /* Swap the source and destination ports in the udp packet */
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, source), &dest_port, sizeof(dest_port), 0);
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, dest), &src_port, sizeof(src_port), 0);

    /* And then send it back from wherever it's come from */
    bpf_clone_redirect(skb, skb->ifindex, 0);

    /* Since we've handled the packet, drop it */
    return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";
