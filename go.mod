module github.com/cthiel42/arbutus

go 1.25.1

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/cilium/ebpf v0.21.0
)

require golang.org/x/sys v0.37.0 // indirect

tool github.com/cilium/ebpf/cmd/bpf2go
