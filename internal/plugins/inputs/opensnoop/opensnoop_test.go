package opensnoop

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cthiel42/arbutus/internal/models"
)

func TestCstring(t *testing.T) {
	// Test null-terminated string
	b := []byte{'h', 'e', 'l', 'l', 'o', 0, 'x', 'x', 'x'}
	result := cstring(b)
	if result != "hello" {
		t.Errorf("Expected 'hello', got %q", result)
	}

	// Test string without null terminator
	b2 := []byte{'w', 'o', 'r', 'l', 'd'}
	result2 := cstring(b2)
	if result2 != "world" {
		t.Errorf("Expected 'world', got %q", result2)
	}

	// Test empty string
	b3 := []byte{0, 'x', 'x'}
	result3 := cstring(b3)
	if result3 != "" {
		t.Errorf("Expected empty string, got %q", result3)
	}
}

func TestOpensnoopEventParsing(t *testing.T) {
	// Create a mock opensnoopEvent as raw bytes
	var buf bytes.Buffer

	// Write fields in order matching the C struct
	binary.Write(&buf, binary.LittleEndian, uint32(1234))  // Pid
	binary.Write(&buf, binary.LittleEndian, uint32(1000))  // Uid
	binary.Write(&buf, binary.LittleEndian, int32(3))      // Ret (file descriptor)

	// Write Comm (process name) - 16 bytes
	comm := make([]byte, 16)
	copy(comm, []byte("test_process\x00"))
	buf.Write(comm)

	// Write Fname (filename) - 256 bytes
	fname := make([]byte, 256)
	copy(fname, []byte("/etc/passwd\x00"))
	buf.Write(fname)

	// Parse the raw bytes into an opensnoopEvent
	var event opensnoopEvent
	err := binary.Read(&buf, binary.LittleEndian, &event)
	if err != nil {
		t.Fatalf("Failed to parse event: %v", err)
	}

	// Verify the parsed values
	if event.Pid != 1234 {
		t.Errorf("Expected Pid 1234, got %d", event.Pid)
	}
	if event.Uid != 1000 {
		t.Errorf("Expected Uid 1000, got %d", event.Uid)
	}
	if event.Ret != 3 {
		t.Errorf("Expected Ret 3, got %d", event.Ret)
	}

	// Test cstring conversion on the parsed data
	commStr := cstring(event.Comm[:])
	if commStr != "test_process" {
		t.Errorf("Expected Comm 'test_process', got %q", commStr)
	}

	fnameStr := cstring(event.Fname[:])
	if fnameStr != "/etc/passwd" {
		t.Errorf("Expected Fname '/etc/passwd', got %q", fnameStr)
	}
}

// Mock accumulator to test log generation without actual eBPF
type mockAccumulator struct {
	logs []models.Log
}

func (m *mockAccumulator) AddLog(log models.Log) {
	m.logs = append(m.logs, log)
}

func (m *mockAccumulator) AddMetric(metric models.Metric) {
	// Not used in this test
}

func TestEventToLogConversion(t *testing.T) {
	// Create a mock event
	event := opensnoopEvent{
		Pid: 5678,
		Uid: 1000,
		Ret: 5,
	}
	copy(event.Comm[:], []byte("nginx\x00"))
	copy(event.Fname[:], []byte("/var/log/access.log\x00"))

	// Convert to strings like the actual code does
	comm := cstring(event.Comm[:])
	fname := cstring(event.Fname[:])

	if comm != "nginx" {
		t.Errorf("Expected comm 'nginx', got %q", comm)
	}
	if fname != "/var/log/access.log" {
		t.Errorf("Expected fname '/var/log/access.log', got %q", fname)
	}

	// Test that we can create a log entry (simulating what Run() does)
	acc := &mockAccumulator{}
	logEntry := models.Log{
		Level:   "info",
		Message: "Process " + comm + " opened file: " + fname,
		Attributes: map[string]interface{}{
			"input": "opensnoop",
			"pid":   event.Pid,
		},
	}
	acc.AddLog(logEntry)

	if len(acc.logs) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(acc.logs))
	}
	if acc.logs[0].Level != "info" {
		t.Errorf("Expected level 'info', got %q", acc.logs[0].Level)
	}
}
