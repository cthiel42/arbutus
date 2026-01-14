.PHONY: all clean vmlinux generate build test

VMLINUX_H := internal/bpf/include/vmlinux.h
INPUT_PLUGINS_DIR := internal/plugins/inputs
# Dynamically find all input plugin directories that contain gen.go
INPUT_PLUGINS := $(shell find $(INPUT_PLUGINS_DIR) -mindepth 1 -maxdepth 1 -type d -exec test -f {}/gen.go \; -print)
BIN_DIR := bin
BINARY := $(BIN_DIR)/arbutus

all: build

$(VMLINUX_H):
	@echo "Generating vmlinux.h..."
	@mkdir -p internal/bpf/include
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

vmlinux: $(VMLINUX_H)

generate: $(VMLINUX_H)
	@echo "Running go generate for input plugins..."
	@for dir in $(INPUT_PLUGINS); do \
		echo "  Generating $$dir..."; \
		(cd $$dir && go generate); \
	done

build: generate
	@echo "Building arbutus..."
	@mkdir -p $(BIN_DIR)
	@go build -o $(BINARY) ./cmd/arbutus

test:
	@echo "Running tests..."
	@go test ./...

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@rm -f $(VMLINUX_H)
	@find internal/plugins/inputs -name "*_bpfe*.go" -delete
	@find internal/plugins/inputs -name "*_bpfe*.o" -delete
