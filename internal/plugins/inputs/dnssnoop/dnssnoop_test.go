package dnssnoop

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cthiel42/arbutus/internal/models"
)

func TestCstring(t *testing.T) {
	// Test null-terminated string
	b := []byte{'c', 'u', 'r', 'l', 0, 'x', 'x'}
	result := cstring(b)
	if result != "curl" {
		t.Errorf("Expected 'curl', got %q", result)
	}

	// Test string without null terminator
	b2 := []byte{'d', 'i', 'g'}
	result2 := cstring(b2)
	if result2 != "dig" {
		t.Errorf("Expected 'dig', got %q", result2)
	}

	// Test empty string
	b3 := []byte{0}
	result3 := cstring(b3)
	if result3 != "" {
		t.Errorf("Expected empty string, got %q", result3)
	}
}

func TestParseDNSQuery(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected string
	}{
		{
			name: "google.com",
			payload: []byte{
				// DNS Header (12 bytes) - simplified
				0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				// Question: google.com
				0x06, 'g', 'o', 'o', 'g', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00, // null terminator
			},
			expected: "google.com",
		},
		{
			name: "example.org",
			payload: []byte{
				// DNS Header (12 bytes)
				0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				// Question: example.org
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'o', 'r', 'g',
				0x00,
			},
			expected: "example.org",
		},
		{
			name: "subdomain.test.local",
			payload: []byte{
				// DNS Header (12 bytes)
				0x00, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				// Question: subdomain.test.local
				0x09, 's', 'u', 'b', 'd', 'o', 'm', 'a', 'i', 'n',
				0x04, 't', 'e', 's', 't',
				0x05, 'l', 'o', 'c', 'a', 'l',
				0x00,
			},
			expected: "subdomain.test.local",
		},
		{
			name:     "empty payload",
			payload:  []byte{},
			expected: "",
		},
		{
			name: "too short payload",
			payload: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDNSQuery(tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestDnssnoopEventParsing(t *testing.T) {
	// Create a mock dnssnoopEvent as raw bytes
	var buf bytes.Buffer

	// Write fields in order matching the C struct
	binary.Write(&buf, binary.LittleEndian, uint32(9876))  // Pid

	// Write Comm (process name) - 16 bytes
	comm := make([]byte, 16)
	copy(comm, []byte("firefox\x00"))
	buf.Write(comm)

	// Write DstIP - 8.8.8.8 encoded as uint32
	// IP 8.8.8.8 = 0x08080808 in little endian
	binary.Write(&buf, binary.LittleEndian, uint32(0x08080808))

	// Write PayloadLen
	binary.Write(&buf, binary.LittleEndian, uint32(28))

	// Write Payload - 256 bytes
	payload := make([]byte, 256)
	// Create a simple DNS query for "test.com"
	dnsQuery := []byte{
		// DNS Header (12 bytes)
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		// Question: test.com
		0x04, 't', 'e', 's', 't',
		0x03, 'c', 'o', 'm',
		0x00,
	}
	copy(payload, dnsQuery)
	buf.Write(payload)

	// Parse the raw bytes into a dnssnoopEvent
	var event dnssnoopEvent
	err := binary.Read(&buf, binary.LittleEndian, &event)
	if err != nil {
		t.Fatalf("Failed to parse event: %v", err)
	}

	// Verify the parsed values
	if event.Pid != 9876 {
		t.Errorf("Expected Pid 9876, got %d", event.Pid)
	}

	commStr := cstring(event.Comm[:])
	if commStr != "firefox" {
		t.Errorf("Expected Comm 'firefox', got %q", commStr)
	}

	// Test IP address formatting
	dstIP := []byte{
		byte(event.DstIP),
		byte(event.DstIP >> 8),
		byte(event.DstIP >> 16),
		byte(event.DstIP >> 24),
	}
	expectedIP := []byte{8, 8, 8, 8}
	if !bytes.Equal(dstIP, expectedIP) {
		t.Errorf("Expected IP bytes %v, got %v", expectedIP, dstIP)
	}

	if event.PayloadLen != 28 {
		t.Errorf("Expected PayloadLen 28, got %d", event.PayloadLen)
	}

	// Test DNS query parsing
	dnsQueryStr := parseDNSQuery(event.Payload[:event.PayloadLen])
	if dnsQueryStr != "test.com" {
		t.Errorf("Expected DNS query 'test.com', got %q", dnsQueryStr)
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
	event := dnssnoopEvent{
		Pid:        1234,
		DstIP:      0x01010101, // 1.1.1.1
		PayloadLen: 25,
	}
	copy(event.Comm[:], []byte("curl\x00"))

	// Create DNS query payload for "example.com"
	dnsPayload := []byte{
		// DNS Header (12 bytes)
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		// Question: example.com
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}
	copy(event.Payload[:], dnsPayload)

	// Convert to strings like the actual code does
	comm := cstring(event.Comm[:])
	dstIP := []byte{
		byte(event.DstIP),
		byte(event.DstIP >> 8),
		byte(event.DstIP >> 16),
		byte(event.DstIP >> 24),
	}
	dnsQuery := parseDNSQuery(event.Payload[:event.PayloadLen])

	if comm != "curl" {
		t.Errorf("Expected comm 'curl', got %q", comm)
	}
	if !bytes.Equal(dstIP, []byte{1, 1, 1, 1}) {
		t.Errorf("Expected IP 1.1.1.1, got %v", dstIP)
	}
	if dnsQuery != "example.com" {
		t.Errorf("Expected DNS query 'example.com', got %q", dnsQuery)
	}

	// Test that we can create a log entry
	acc := &mockAccumulator{}
	logEntry := models.Log{
		Level:   "info",
		Message: "DNS Query: pid=" + string(rune(event.Pid)) + " query=" + dnsQuery,
		Attributes: map[string]interface{}{
			"input": "dnssnoop",
			"pid":   event.Pid,
		},
	}
	acc.AddLog(logEntry)

	if len(acc.logs) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(acc.logs))
	}
}
