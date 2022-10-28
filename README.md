# UDPQuiz

UDPQuiz is an eBPF program that runs on Linux to send back all udp packets as is. This makes it a perfect tool to test which udp ports have been firewalled on your network.

Visit https://udpquiz.com/ to try it out!

## Running locally

```sh
# Replace eth0 with your interface name
export DEVICE=eth0

# Compile and load
make -e

# Once complete, the filter and qdisc can be removed
make -e clean
```

## References

- [Send ICMP Echo Replies using eBPF](https://fnordig.de/2017/03/04/send-icmp-echo-replies-using-ebpf/)
- [Bypassing Captive Portals](https://blog.chebro.dev/posts/bypassing-captive-portals)
