# UDPQuiz ![Site status](https://github.com/radiantly/udpquiz/actions/workflows/site.yml/badge.svg)

UDPQuiz is an eBPF program that runs on Linux to send back all udp packets as is. This makes it a perfect tool to test which udp ports have been firewalled on your network.

Visit https://udpquiz.com/ to try it out!

## Running locally

```sh
# Build udpquiz
make

# Add to /usr/local/bin and create service
make install

# Add CF token
echo "CLOUDFLARE_API_TOKEN=<your token>" > /etc/udpquiz/env
chmod 600 /etc/udpquiz/env

# Enable service
systemctl enable --now udpquiz
```

## References

- [Send ICMP Echo Replies using eBPF](https://fnordig.de/2017/03/04/send-icmp-echo-replies-using-ebpf/)
- [tc direct action mode for BPF](https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/)
