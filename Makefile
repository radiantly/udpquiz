DEVICE=eth0

all: qdisc

bpf.o: bpf.c
	clang -O2 -target bpf $< -c -o $@

qdisc-del:
	-sudo tc qdisc del dev $(DEVICE) ingress handle ffff:

qdisc: qdisc-del bpf.o
	sudo tc qdisc add dev $(DEVICE) ingress handle ffff: && \
	sudo tc filter add dev $(DEVICE) parent ffff: bpf obj bpf.o sec classifier flowid ffff:1 action bpf obj bpf.o sec action ok

clean: qdisc-del
	-rm bpf.o

.PHONY: all qdisc qdisc-del clean
