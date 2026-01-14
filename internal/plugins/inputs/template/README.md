# Template Input Plugin

Template input plugin for building new eBPF-based input plugins.

Attaches to the `sys_enter_openat` tracepoint and emits "hello world" logs on file opens.

## Usage

Use this as a starting point for new input plugins. Copy the directory and modify the eBPF program and Go code as needed.
You will need to import your plugin in the `inputs.go` file for it to be callable from the config. 

## Generate

Run `go generate` in this directory to compile the eBPF program:

```bash
go generate
```
