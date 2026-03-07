# If the DEVICE env variable is not set, choose first non-loopback/non-virt interface
DEVICE ?= $(shell ip -br l | awk '$$1 !~ "lo|vir" { print $$1; exit }')

all: udpquiz

bpf.o: bpf.c
	clang $(DEBUG) -O2 -target bpf $< -c -o $@

debug: DEBUG = -DDEBUG

debug: qdisc
	-sudo tc exec bpf dbg

qdisc-del:
	-sudo tc qdisc del dev $(DEVICE) clsact

qdisc: qdisc-del bpf.o
	sudo tc qdisc add dev $(DEVICE) clsact && \
	sudo tc filter add dev $(DEVICE) ingress bpf direct-action obj bpf.o

clean: qdisc-del
	-rm bpf.o

bpfstatus/udpquizbpf_bpfel.o: bpf.c
	cd bpfstatus && go generate

udpquiz: bpfstatus/udpquizbpf_bpfel.o
	cd bpfstatus && \
	xcaddy build --output ../udpquiz \
				 --with github.com/caddy-dns/cloudflare \
		         --with github.com/radiantly/udpquiz/bpfstatus=.

install: udpquiz
	install -m 755 udpquiz /usr/local/bin/udpquiz
	install -m 644 udpquiz.service /etc/systemd/system/
	install -Dm 644 Caddyfile /etc/udpquiz/Caddyfile
	install -Dm 644 index.html /usr/share/udpquiz/index.html
	systemctl daemon-reload

.PHONY: all debug qdisc qdisc-del clean install
