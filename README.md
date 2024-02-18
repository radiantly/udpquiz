# UDPQuiz ![Site status](https://github.com/radiantly/udpquiz/actions/workflows/site.yml/badge.svg)

UDPQuiz is an eBPF program that runs on Linux to send back all udp packets as is. This makes it a perfect tool to test which udp ports have been firewalled on your network.

Visit https://udpquiz.com/ to try it out!

## Running locally

```sh
# Replace eth0 with your interface name
export DEVICE=eth0

# Compile and load
make

# Once complete, the filter and qdisc can be removed
make clean
```

## References

- [Send ICMP Echo Replies using eBPF](https://fnordig.de/2017/03/04/send-icmp-echo-replies-using-ebpf/)
- [Bypassing Captive Portals](https://blog.chebro.dev/posts/bypassing-captive-portals)
- [tc direct action mode for BPF](https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/)
