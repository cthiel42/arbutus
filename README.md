# Arbutus

Arbutus is a lightweight telemetry tool for Linux systems that uses eBPF to monitor system behavior and collect observability data. It provides real time insights into DNS queries, file operations, memory leaks, and more without requiring kernel modules or code changes.

## Features

- **eBPF-based monitoring**: Low-overhead system observability using kernel tracing
- **Pluggable architecture**: Extensible input and output plugin system
- **Multiple outputs**: Send telemetry to Loki, files, console, or custom destinations
- **Real-time monitoring**: Capture system events as they happen
- **Multiple inputs**: Built in plugins include DNS, file operation, and memory leak monitoring

## Requirements

Arbutus is targeted for 6.x Linux kernels, but most simpler input plugins will work with older kernel versions. If you run into a compatability issue that you would like addressed, please open a GitHub issue.

### System Requirements
- Linux kernel 4.18+ with eBPF support
- CAP_BPF capability or root privileges
- BTF (BPF Type Format) support

## Configuration

Arbutus uses TOML for configuration. All configuration options can be found in the [example config](configs/arbutus.toml)

### Configuration Sections

- **inputs**: Input plugins that collect telemetry data
- **outputs**: Output plugins that receive and forward telemetry

```toml
# Input plugins - collect telemetry
[inputs.memleak]
  kernel_trace = true
  min_leak_threshold = 1048576

[inputs.dnssnoop]

[inputs.opensnoop]

# Output plugins - send telemetry
[outputs.console]

[outputs.file]
  filepath = "/var/log/arbutus/output.log"

[outputs.loki]
  domain = "http://localhost:3100"
  username = "user"
  password = "pass"
```

## Running Arbutus

Run with default config file:
```bash
sudo ./bin/arbutus
```

Run with custom config:
```bash
sudo ./bin/arbutus -config /path/to/config.toml
```

Arbutus requires root or CAP_BPF capability to load eBPF programs.

## Project Structure

```
arbutus/
├── cmd/arbutus/          # Main application entry point
├── internal/
│   ├── bpf/              # Directory used during builds for shared eBPF headers and utilities
│   ├── config/           # Configuration loading
│   ├── models/           # Core data types (telemetry, plugins)
│   ├── pipeline/         # Telemetry processing pipeline
│   └── plugins/
│       ├── inputs/       # Input plugins (data collection)
│       └── outputs/      # Output plugins (data forwarding)
├── configs/              # Example configuration files
├── Makefile              # Build automation
└── go.mod                # Go module definition
```

## Available Plugins

Each plugin has its own README with detailed configuration options and usage examples.

### Input Plugins

Input plugins collect telemetry data from the system:

- **memleak**: Kernel memory leak detection using eBPF tracepoints
  - [Documentation](internal/plugins/inputs/memleak/README.md)
- **dnssnoop**: DNS query monitoring via eBPF fentry hooks
  - [Documentation](internal/plugins/inputs/dnssnoop/README.md)
- **opensnoop**: File open operation tracking
  - [Documentation](internal/plugins/inputs/opensnoop/README.md)

### Output Plugins

Output plugins send telemetry to various destinations:

- **console**: Write logs and metrics to standard output
  - [Documentation](internal/plugins/outputs/console/README.md)
- **file**: Write logs and metrics to a file
  - [Documentation](internal/plugins/outputs/file/README.md)
- **loki**: Send logs to Grafana Loki
  - [Documentation](internal/plugins/outputs/loki/README.md)

## Development
### Architecture

Arbutus follows a simple pipeline architecture:

1. **Input plugins** collect telemetry from the system using eBPF
2. **Accumulator** buffers telemetry in memory
3. **Pipeline** periodically flushes telemetry to outputs
4. **Output plugins** forward telemetry to external systems

The pipeline automatically flushes on:
- Configured flush interval (default: 60s)
- Input plugin requests (via accumulator)
- Graceful shutdown

### Telemetry Types

Arbutus supports three telemetry types:

- **Logs**: Timestamped messages with levels and attributes
- **Metrics**: Timestamped numerical measurements with tags and fields
- **Traces**: Distributed tracing spans (planned, nothing currently implements this type)

Each input plugin can produce one or more telemetry types, and output plugins specify which types they support.

### Dependencies For Local Development
- Go 1.25.1 or later
- libbpf-dev
- llvm
- clang
- linux-headers

### Build Arbutus From Source

Clone the repository and build:

```bash
git clone https://github.com/cthiel42/arbutus.git
cd arbutus
make clean && make
```

The build process will:
1. Generate `vmlinux.h` from your kernel's BTF data
2. Compile eBPF programs for each input plugin
3. Build the `arbutus` binary to `bin/arbutus`

### Creating a New Plugin

Use the template plugin as a starting point:
```bash
cp -r internal/plugins/inputs/template internal/plugins/inputs/myplugin
```

Input plugins must implement the `models.Input` interface. Output plugins must implement the `models.Output` interface.

### Regenerating eBPF Code

If you modify eBPF C code, regenerate the Go bindings:

```bash
# Regenerate all plugins
make generate

# Or regenerate a specific plugin
cd internal/plugins/inputs/myplugin
go generate
```

### Cleaning Build Artifacts

```bash
make clean
```

This removes:
- Binary artifacts from `bin/`
- Generated `vmlinux.h`
- Generated eBPF Go files (`*_bpfel.go`, `*_bpfeb.go`)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with tests
