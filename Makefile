# If the DEVICE env variable is not set, choose first non-loopback/non-virt interface
DEVICE ?= $(shell ip -br l | awk '$$1 !~ "lo|vir" { print $$1; exit }')

all: qdisc

bpf.o: bpf.c
	clang $(DEBUG) -O2 -target bpf $< -c -o $@

debug: DEBUG = -DDEBUG

debug: all
	-sudo tc exec bpf dbg

qdisc-del:
	-sudo tc qdisc del dev $(DEVICE) clsact

qdisc: qdisc-del bpf.o
	sudo tc qdisc add dev $(DEVICE) clsact && \
	sudo tc filter add dev $(DEVICE) ingress bpf direct-action obj bpf.o

clean: qdisc-del
	-rm bpf.o

.PHONY: all debug qdisc qdisc-del clean
