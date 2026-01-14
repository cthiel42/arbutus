package template

//go:generate go tool bpf2go -tags linux -cflags "-I../../../bpf/include" template template.bpf.c
