# UDPQuiz ![Site status](https://github.com/radiantly/udpquiz/actions/workflows/site.yml/badge.svg)

UDPQuiz is an eBPF program that runs on Linux to send back all udp packets as is. This makes it a perfect tool to test which udp ports have been firewalled on your network.

Visiting the site requires your browser to support HTTP/3 and HTTP DNS records. A static copy is available at https://static.udpquiz.com/

## Running locally

Take a look at the Makefile.

## References

- [Send ICMP Echo Replies using eBPF](https://fnordig.de/2017/03/04/send-icmp-echo-replies-using-ebpf/)
- [tc direct action mode for BPF](https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/)
