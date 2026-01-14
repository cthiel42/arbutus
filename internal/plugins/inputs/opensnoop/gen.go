package opensnoop

//go:generate go tool bpf2go -tags linux -cflags "-I../../../bpf/include" opensnoop opensnoop.bpf.c
