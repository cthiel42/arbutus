package memleak

import (
	"testing"
)

func TestCombinedAllocInfo(t *testing.T) {
	tests := []struct {
		name           string
		bits           uint64
		expectedSize   uint64
		expectedAllocs uint64
	}{
		{
			name:           "small allocation",
			bits:           0x0000000000001000, // 4096 bytes, 0 allocs
			expectedSize:   4096,
			expectedAllocs: 0,
		},
		{
			name:           "single allocation of 1MB",
			bits:           0x0000010000100000, // 1MB size, 1 alloc
			expectedSize:   1048576,
			expectedAllocs: 1,
		},
		{
			name:           "multiple allocations",
			bits:           0x0000050000002000, // 8192 bytes, 5 allocs
			expectedSize:   8192,
			expectedAllocs: 5,
		},
		{
			name: "large allocation count",
			// 1000 allocs (0x3E8) in upper 24 bits, 10MB in lower 40 bits
			bits:           0x0003E80000989680,
			expectedSize:   10000000,
			expectedAllocs: 1000,
		},
		{
			name:           "zero values",
			bits:           0x0,
			expectedSize:   0,
			expectedAllocs: 0,
		},
		{
			name: "max lower 40 bits (size)",
			// All lower 40 bits set, 1 alloc in upper bits
			bits:           0x000001FFFFFFFFFF,
			expectedSize:   0xFFFFFFFFFF, // max 40-bit value
			expectedAllocs: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := combinedAllocInfo{Bits: tt.bits}

			size := info.TotalSize()
			if size != tt.expectedSize {
				t.Errorf("TotalSize() = %d, expected %d", size, tt.expectedSize)
			}

			allocs := info.NumberOfAllocs()
			if allocs != tt.expectedAllocs {
				t.Errorf("NumberOfAllocs() = %d, expected %d", allocs, tt.expectedAllocs)
			}
		})
	}
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]interface{}
		check  func(*testing.T, *Memleak)
	}{
		{
			name: "kernel_trace config",
			config: map[string]interface{}{
				"kernel_trace": false,
			},
			check: func(t *testing.T, m *Memleak) {
				if m.kernelTrace != false {
					t.Errorf("Expected kernelTrace false, got %v", m.kernelTrace)
				}
			},
		},
		{
			name: "pid config",
			config: map[string]interface{}{
				"pid": 1234,
			},
			check: func(t *testing.T, m *Memleak) {
				if m.pid != 1234 {
					t.Errorf("Expected pid 1234, got %d", m.pid)
				}
				if m.kernelTrace != false {
					t.Errorf("Expected kernelTrace false when pid is set, got %v", m.kernelTrace)
				}
			},
		},
		{
			name: "object config",
			config: map[string]interface{}{
				"object": "libc.so.6",
			},
			check: func(t *testing.T, m *Memleak) {
				if m.object != "libc.so.6" {
					t.Errorf("Expected object 'libc.so.6', got %q", m.object)
				}
			},
		},
		{
			name: "size and rate configs",
			config: map[string]interface{}{
				"min_size":    1024,
				"max_size":    1048576,
				"sample_rate": 100,
			},
			check: func(t *testing.T, m *Memleak) {
				if m.minSize != 1024 {
					t.Errorf("Expected minSize 1024, got %d", m.minSize)
				}
				if m.maxSize != 1048576 {
					t.Errorf("Expected maxSize 1048576, got %d", m.maxSize)
				}
				if m.sampleRate != 100 {
					t.Errorf("Expected sampleRate 100, got %d", m.sampleRate)
				}
			},
		},
		{
			name: "trace_all and max_reports",
			config: map[string]interface{}{
				"trace_all":   true,
				"max_reports": 10,
			},
			check: func(t *testing.T, m *Memleak) {
				if m.traceAll != true {
					t.Errorf("Expected traceAll true, got %v", m.traceAll)
				}
				if m.maxReports != 10 {
					t.Errorf("Expected maxReports 10, got %d", m.maxReports)
				}
			},
		},
		{
			name: "min_leak_threshold",
			config: map[string]interface{}{
				"min_leak_threshold": 5242880, // 5MB
			},
			check: func(t *testing.T, m *Memleak) {
				if m.minLeakThreshold != 5242880 {
					t.Errorf("Expected minLeakThreshold 5242880, got %d", m.minLeakThreshold)
				}
			},
		},
		{
			name:   "empty config uses defaults",
			config: map[string]interface{}{},
			check: func(t *testing.T, m *Memleak) {
				if m.kernelTrace != true {
					t.Errorf("Expected default kernelTrace true, got %v", m.kernelTrace)
				}
				if m.pid != -1 {
					t.Errorf("Expected default pid -1, got %d", m.pid)
				}
				if m.object != "libc.so.6" {
					t.Errorf("Expected default object 'libc.so.6', got %q", m.object)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New().(*Memleak)
			err := m.parseConfig(tt.config)
			if err != nil {
				t.Fatalf("parseConfig() failed: %v", err)
			}
			tt.check(t, m)
		})
	}
}

func TestFindSymbol(t *testing.T) {
	// Create mock kallsyms data
	syms := []kallsym{
		{addr: 0x1000, name: "function_a"},
		{addr: 0x2000, name: "function_b"},
		{addr: 0x3000, name: "function_c"},
		{addr: 0x5000, name: "function_d"},
	}

	tests := []struct {
		name     string
		addr     uint64
		expected string
	}{
		{
			name:     "exact match",
			addr:     0x1000,
			expected: "function_a+0x0",
		},
		{
			name:     "offset from symbol",
			addr:     0x1050,
			expected: "function_a+0x50",
		},
		{
			name:     "middle of function",
			addr:     0x2100,
			expected: "function_b+0x100",
		},
		{
			name:     "between symbols",
			addr:     0x4500,
			expected: "function_c+0x1500",
		},
		{
			name:     "after last symbol",
			addr:     0x6000,
			expected: "function_d+0x1000",
		},
		{
			name:     "before first symbol",
			addr:     0x500,
			expected: "0x500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findSymbol(syms, tt.addr)
			if result != tt.expected {
				t.Errorf("findSymbol(0x%x) = %q, expected %q", tt.addr, result, tt.expected)
			}
		})
	}
}

func TestFindSymbolEmptyList(t *testing.T) {
	syms := []kallsym{}
	result := findSymbol(syms, 0x1234)
	expected := "0x1234"
	if result != expected {
		t.Errorf("findSymbol() with empty list = %q, expected %q", result, expected)
	}
}
