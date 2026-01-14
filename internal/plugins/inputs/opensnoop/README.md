# Opensnoop Input Plugin

The Opensnoop input plugin monitors file open operations on the system using eBPF. It captures information about which processes are opening which files, providing visibility into file access patterns.

Attaches to the `sys_enter_openat` tracepoint to track all file open system calls.

## Configuration

```toml
[inputs.opensnoop]
```

No configuration options are currently needed. You only need to include the opensnoop input in your configuration to enable file open monitoring.

### Example Configuration

```toml
[inputs.opensnoop]

[outputs.console]
```

This will monitor all file open operations on the system and output them to the console.

## Use Cases

- Monitor which applications are accessing sensitive files
- Debug file access issues
- Audit file system access patterns
- Security monitoring and intrusion detection
- Performance analysis of file I/O

## Requirements

- Linux kernel with eBPF support
- CAP_BPF capability or root privileges
- Kernel with tracepoint support (most modern kernels)

## Generate

Run `go generate` in this directory to compile the eBPF program:

```bash
go generate
```
