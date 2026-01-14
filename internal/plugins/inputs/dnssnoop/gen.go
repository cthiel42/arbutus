package dnssnoop

//go:generate go tool bpf2go -tags linux -cflags "-I../../../bpf/include" dnssnoop dnssnoop.bpf.c
