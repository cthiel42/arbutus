package memleak

//go:generate go tool bpf2go -tags linux -cflags "-I../../../bpf/include" memleak memleak.bpf.c
