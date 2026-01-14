# DNSSnoop Input Plugin

The DNSSnoop input plugin monitors DNS queries made by processes on the system using eBPF. It captures DNS query information including the process ID, command name, destination IP, and the queried domain name.

Uses eBPF fentry tracing to attach to the kernel's DNS send function.

## Configuration

```toml
[inputs.dnssnoop]
```

No configuration options are currently needed. Simply include the dnssnoop input in your configuration to enable DNS query monitoring.

### Example Configuration

```toml
[inputs.dnssnoop]

[outputs.console]
```

This will monitor all DNS queries on the system and output them to the console.

## Requirements

- Linux kernel with eBPF support
- CAP_BPF capability or root privileges
- Kernel compiled with fentry/fexit support (kernel 5.5+)

## Generate

Run `go generate` in this directory to compile the eBPF program:

```bash
go generate
```
