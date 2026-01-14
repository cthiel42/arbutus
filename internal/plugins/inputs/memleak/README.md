# Memleak Input Plugin

Memory leak detection plugin using eBPF to track memory allocations and identify potential memory leaks.

This plugin can trace memory allocations in both kernel and userspace, tracking allocation/deallocation patterns to identify outstanding allocations that may indicate memory leaks. THis plugin is meant to be run for an extended period of time and only emit logs when there are leaks found.

## Features

- Kernel memory allocation tracking (kmalloc, kmem_cache_alloc, etc.)
- Stack trace collection for allocation sites
- Periodic reporting of outstanding allocations
- Configurable sampling rate and size filters

## Requirements

- CAP_BPF capability or root privileges
- Kernel with tracepoint support for kmem subsystem
- BTF (BPF Type Format) support for stack trace symbolization
- Access to `/proc/kallsyms` for kernel symbol resolution

## Usage

Add the memleak input plugin to your config:

```toml
[[inputs.memleak]]
  # Track kernel allocations (default: true)
  kernel_trace = true

  # Minimum allocation size to track (default: 0)
  min_size = 0

  # Maximum allocation size to track (default: unlimited)
  max_size = 18446744073709551615

  # Sample every N allocations (default: 1 = all allocations)
  sample_rate = 1

  # Quick check interval in seconds - checks for large new leaks (default: 5)
  interval = 5

  # Detailed report interval in seconds - reports top leaking stacks (default: 60)
  detailed_interval = 60

  # Minimum bytes to consider a leak worth reporting (default: 1048576 = 1MB)
  min_leak_threshold = 1048576

  # Maximum number of detailed reports before stopping (default: -1 = unlimited)
  max_reports = -1

  # Print trace messages for each alloc/free (default: false, can be noisy)
  trace_all = false
```

## Generate

Run `go generate` in this directory to compile the eBPF program:

```bash
cd internal/plugins/inputs/memleak
go generate
```

## Implementation Details

The plugin tracks memory allocations by:
1. Attaching to kernel tracepoints (kmem subsystem) or userspace malloc/free functions
2. Recording allocation sizes and stack traces in the `allocs` BPF map
3. Removing allocations from the map when they're freed
4. Tracking stack sizes over time to detect growing leaks
5. Reporting only new or growing leaks that exceed the threshold

The plugin uses two reporting intervals:
- **Quick checks** (default 5s): Only alerts on critical leaks (>10MB) with CRITICAL level
- **Detailed reports** (default 60s): Shows top 10 leaking stacks (>1MB by default) with WARNING level

This approach reduces log noise while still detecting actual memory leaks:
- Small leaks (1-10MB) are reported every 60 seconds on detailed checks
- Large leaks (>10MB) trigger immediate alerts on quick checks
- Only new or growing leaks are reported to avoid spam
- Allocations that remain unfreed and exceed the minimum threshold are tracked

## Understanding the Output

Each leak report includes:
- **process_name**: The name of the process causing the leak (e.g., "python3", "nginx")
- **pid**: Process ID that allocated the memory
- **bytes**: Total bytes leaked from this process at this stack trace
- **count**: Number of outstanding allocations
- **stack_trace**: The kernel call stack showing where the allocation occurred

Example output:
```
Memory leak in process 'Cache2 I/O' (PID 5522): 1178320 bytes in 11330 allocations Stack: kmem_cache_alloc_noprof+0x271 <- kmem_cache_alloc_noprof+0x271 <- alloc_buffer_head+0x1e <- folio_alloc_buffers+0x94 <- create_empty_buffers+0x1e <- ext4_block_write_begin+0x4d7 <- ext4_da_write_be...
```

Based on the memleak tool from BCC/libbpf-tools.
