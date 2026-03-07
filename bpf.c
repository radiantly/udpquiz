// There are different types of ebpf program types
// When it comes to ebpf programs that operate on packets,
// we have two options
// 1. xdp
//    sits in the very beginning of packet processing. gives us
//    raw packet bytes and we don't have __sk_buff populated
// 2. classifier (or tc - traffic control)
//    by default packets can't be dropped or rejected
//    ref: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/
//    but in direct action mode we can do that
//    TC_ACT_UNSPEC - unspecified by this classifier, perform default action
//    TC_ACT_SHOT   - drop packet
//
// xdp is faster, but classifier is nicer to use due to available helper functions

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>

#include "bpf/bpf_helpers.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

#ifdef DEBUG
#define trace_printk(fmt, ...)                               \
    do                                                       \
    {                                                        \
        char _fmt[] = fmt;                                   \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
    } while (0)
#else
#define trace_printk(fmt, ...)
#endif

#define IP_OFFSET 0x1FFF

SEC("classifier")
int cls_main(struct __sk_buff *skb)
{
    // sk_buff is a linux kernel struct that represents a network packet
    // __sk_buff is a stable interface to this struct for bpf programs

    // first we check that the packet has enough data to contain the eth, ip and udp headers
    if (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + skb->data > skb->data_end)
        return TC_ACT_UNSPEC;

    // packet data is stored in skb->data
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    // check if ip packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    // check if udp packet
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_UNSPEC;

    // large udp packets are going to be sent as fragmented ip packets
    // just drop these. we don't expect fragmented packets from quic either
    if (ip->frag_off & __constant_htons(IP_OFFSET))
        return TC_ACT_SHOT;

    // check ip addresses (L3)
    __be32 src_ip = ip->saddr;
    __be32 dst_ip = ip->daddr;

    trace_printk("FROM: %d...%d", src_ip & 0xff, src_ip >> 24);

    // check if both ips are the same (not sure if handled earlier in the chain)
    if (src_ip == dst_ip)
        return TC_ACT_UNSPEC;

    // ignore private ip ranges 10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if ((src_ip & 0xff) == 10 || ((src_ip & 0xff) == 127) || (src_ip & 0xf0ff) == 0x10ac || (src_ip & 0xffff) == 0xa8c0 ||
        (dst_ip & 0xff) == 10 || ((dst_ip & 0xff) == 127) || (dst_ip & 0xf0ff) == 0x10ac || (dst_ip & 0xffff) == 0xa8c0)
        return TC_ACT_UNSPEC;

    __be16 dest_port = udp->dest;
    __be16 src_port = udp->source;

    // do not respond on 443 (caddy handles this)
    if (dest_port == __constant_htons(443))
        return TC_ACT_UNSPEC;

    // let dns responses pass through (check QR bit in dns flags)
    if (src_port == __constant_htons(53))
    {
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|    Z   |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        __u8 *dns_flags = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 2;
        if ((void *)dns_flags < (void *)(long)skb->data_end && (*dns_flags & 0x80))
            return TC_ACT_UNSPEC;
    }

    __u8 current_ttl = ip->ttl;
    if (current_ttl <= 1)
        return TC_ACT_SHOT;

    __u8 new_ttl = current_ttl - 1;

    // swap the mac addresses (L2)
    __u8 src_mac[ETH_ALEN];
    __u8 dst_mac[ETH_ALEN];

    __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);

    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, ETH_ALEN, 0);
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, ETH_ALEN, 0);

    // swap the ip addresses (L3)
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, saddr), &dst_ip, sizeof(dst_ip), 0);
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), &src_ip, sizeof(src_ip), 0);

    // update ttl
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, ttl), &new_ttl, sizeof(new_ttl), 0);
    bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), current_ttl, new_ttl, 2);

    // swap source/destination ports (L4)
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, source), &dest_port, sizeof(dest_port), 0);
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, dest), &src_port, sizeof(src_port), 0);

    // increment per-cpu packet counter
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&packet_count, &key);
    if (count)
        (*count)++;

    // send it back to wherever it's come from
    bpf_clone_redirect(skb, skb->ifindex, 0);

    // we've handled the packet, drop it
    return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";
