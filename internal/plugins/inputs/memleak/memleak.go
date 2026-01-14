package memleak

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cthiel42/arbutus/internal/models"
)

type Memleak struct {
	running          bool
	objs             *memleakObjects
	links            []link.Link
	reportTicker     *time.Ticker
	detailedTicker   *time.Ticker
	reportCount      int
	maxReports       int
	kernelTrace      bool
	pid              int
	object           string
	minSize          uint64
	maxSize          uint64
	sampleRate       uint64
	traceAll         bool
	previousStacks   map[leakKey]uint64 // track previous sizes to detect growing leaks
	minLeakThreshold uint64             // minimum bytes to consider a leak worth reporting
}

// combinedAllocInfo matches the C union combined_alloc_info from memleak.h
type combinedAllocInfo struct {
	Bits uint64
}

func (c *combinedAllocInfo) TotalSize() uint64 {
	// use lower 40 bits for total size
	return c.Bits & 0xFFFFFFFFFF
}

func (c *combinedAllocInfo) NumberOfAllocs() uint64 {
	// use upper 24 bits for number of allocs
	return (c.Bits >> 40) & 0xFFFFFF
}

func init() {
	models.RegisterInputPlugin("memleak", New)
}

func New() models.Input {
	return &Memleak{
		running:          false,
		maxReports:       -1,
		kernelTrace:      true,
		pid:              -1,
		object:           "libc.so.6",
		minSize:          0,
		maxSize:          ^uint64(0),
		sampleRate:       1,
		traceAll:         false,
		previousStacks:   make(map[leakKey]uint64),
		minLeakThreshold: 1024 * 1024, // 1MB minimum to report
	}
}

func (m *Memleak) Run(ctx context.Context, acc models.Accumulator, config map[string]interface{}) error {
	log.Println("Memleak: Run called")

	m.parseConfig(config)
	m.objs = &memleakObjects{}

	spec, err := loadMemleak()
	if err != nil {
		return fmt.Errorf("loading eBPF spec: %w", err)
	}

	constantValues := map[string]interface{}{
		"min_size":        m.minSize,
		"max_size":        m.maxSize,
		"sample_rate":     m.sampleRate,
		"trace_all":       m.traceAll,
		"stack_flags":     uint64(0), // kernel trace uses 0, userspace uses BPF_F_USER_STACK
		"wa_missing_free": false,
		"page_size":       uint64(4096),
	}
	for name, value := range constantValues {
		if err := spec.Variables[name].Set(value); err != nil {
			return fmt.Errorf("setting variable %s: %w", name, err)
		}
	}

	if err := spec.LoadAndAssign(m.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	defer m.objs.Close()

	if m.kernelTrace {
		if err := m.attachKernelTracepoints(); err != nil {
			return fmt.Errorf("attaching kernel tracepoints: %w", err)
		}
	} else {
		if err := m.attachUprobes(); err != nil {
			return fmt.Errorf("attaching uprobes: %w", err)
		}
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	m.running = true
	log.Println("Memleak: Started successfully, tracking allocations...")

	// Quick check interval (default 5 seconds)
	quickInterval := 5 * time.Second
	if v, ok := config["interval"]; ok {
		if d, ok := v.(int); ok {
			quickInterval = time.Duration(d) * time.Second
		}
	}

	// Top 10 report interval (default 60 seconds)
	detailedInterval := 60 * time.Second
	if v, ok := config["detailed_interval"]; ok {
		if d, ok := v.(int); ok {
			detailedInterval = time.Duration(d) * time.Second
		}
	}

	m.reportTicker = time.NewTicker(quickInterval)
	defer m.reportTicker.Stop()

	m.detailedTicker = time.NewTicker(detailedInterval)
	defer m.detailedTicker.Stop()

	m.reportCount = 0

	for m.running {
		select {
		case <-ctx.Done():
			log.Println("Memleak: Context cancelled, stopping")
			return ctx.Err()

		case <-m.detailedTicker.C:
			if m.maxReports >= 0 && m.reportCount >= m.maxReports {
				log.Println("Memleak: Max reports reached, stopping")
				m.running = false
				continue
			}

			// Detailed report - show top leaking stacks
			if err := m.checkForNewLeaks(acc, hostname, true); err != nil {
				log.Printf("Memleak: Error reporting allocations: %v", err)
			}
			m.reportCount++

		case <-m.reportTicker.C:
			// Quick check - only report significant new leaks
			if err := m.checkForNewLeaks(acc, hostname, false); err != nil {
				log.Printf("Memleak: Error checking for leaks: %v", err)
			}
		}
	}

	log.Println("Memleak: Stopped by Stop() call")
	return nil
}

func (m *Memleak) parseConfig(config map[string]interface{}) {
	if v, ok := config["kernel_trace"]; ok {
		if b, ok := v.(bool); ok {
			m.kernelTrace = b
		}
	}

	if v, ok := config["pid"]; ok {
		if i, ok := v.(int); ok {
			m.pid = i
			m.kernelTrace = false
		}
	}

	if v, ok := config["object"]; ok {
		if s, ok := v.(string); ok {
			m.object = s
		}
	}

	if v, ok := config["min_size"]; ok {
		if i, ok := v.(int); ok {
			m.minSize = uint64(i)
		}
	}

	if v, ok := config["max_size"]; ok {
		if i, ok := v.(int); ok {
			m.maxSize = uint64(i)
		}
	}

	if v, ok := config["sample_rate"]; ok {
		if i, ok := v.(int); ok {
			m.sampleRate = uint64(i)
		}
	}

	if v, ok := config["trace_all"]; ok {
		if b, ok := v.(bool); ok {
			m.traceAll = b
		}
	}

	if v, ok := config["max_reports"]; ok {
		if i, ok := v.(int); ok {
			m.maxReports = i
		}
	}

	if v, ok := config["min_leak_threshold"]; ok {
		if i, ok := v.(int); ok {
			m.minLeakThreshold = uint64(i)
		}
	}
}

func (m *Memleak) attachKernelTracepoints() error {
	// kmalloc
	tp, err := link.Tracepoint("kmem", "kmalloc", m.objs.MemleakKmalloc, nil)
	if err != nil {
		return fmt.Errorf("attaching kmalloc tracepoint: %w", err)
	}
	m.links = append(m.links, tp)

	// kfree
	tp, err = link.Tracepoint("kmem", "kfree", m.objs.MemleakKfree, nil)
	if err != nil {
		return fmt.Errorf("attaching kfree tracepoint: %w", err)
	}
	m.links = append(m.links, tp)

	// kmem_cache_alloc
	tp, err = link.Tracepoint("kmem", "kmem_cache_alloc", m.objs.MemleakKmemCacheAlloc, nil)
	if err != nil {
		return fmt.Errorf("attaching kmem_cache_alloc tracepoint: %w", err)
	}
	m.links = append(m.links, tp)

	// kmem_cache_free
	tp, err = link.Tracepoint("kmem", "kmem_cache_free", m.objs.MemleakKmemCacheFree, nil)
	if err != nil {
		return fmt.Errorf("attaching kmem_cache_free tracepoint: %w", err)
	}
	m.links = append(m.links, tp)

	log.Println("Memleak: Attached kernel tracepoints")
	return nil
}

func (m *Memleak) attachUprobes() error {
	// For now, just log that uprobe attachment is not yet implemented
	// Full uprobe implementation would require attaching to malloc, free, etc.
	log.Println("Memleak: Userspace tracing not yet fully implemented in plugin")
	return fmt.Errorf("userspace tracing not yet implemented")
}

type stackAllocs struct {
	StackID int32
	Size    uint64
	Count   uint64
	PID     uint32
	Comm    string
}

type kallsym struct {
	addr uint64
	name string
}

// load kernel symbols from /proc/kallsyms
func loadKallsyms() ([]kallsym, error) {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var syms []kallsym
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}
		syms = append(syms, kallsym{addr: addr, name: parts[2]})
	}

	return syms, scanner.Err()
}

// Find the symbol for a given address. Binary search for closest symbol
func findSymbol(syms []kallsym, addr uint64) string {
	best := ""
	bestAddr := uint64(0)

	for _, sym := range syms {
		if sym.addr <= addr && sym.addr > bestAddr {
			bestAddr = sym.addr
			best = sym.name
		}
	}

	if best != "" {
		offset := addr - bestAddr
		return fmt.Sprintf("%s+0x%x", best, offset)
	}
	return fmt.Sprintf("0x%x", addr)
}

func (m *Memleak) getStackTrace(stackID int32, syms []kallsym) []string {
	// Stack traces are stored as arrays of u64 addresses
	stackSize := 127
	stack := make([]uint64, stackSize)

	if err := m.objs.StackTraces.Lookup(uint32(stackID), &stack); err != nil {
		return []string{fmt.Sprintf("[failed to lookup stack: %v]", err)}
	}

	// convert addresses to symbols
	var trace []string
	for _, addr := range stack {
		if addr == 0 {
			break
		}
		trace = append(trace, findSymbol(syms, addr))
	}

	return trace
}

type leakKey struct {
	PID     uint32
	StackID int32
}

func (m *Memleak) checkForNewLeaks(acc models.Accumulator, hostname string, detailed bool) error {
	// load kernel symbols for symbolization
	var syms []kallsym
	if m.kernelTrace {
		var err error
		syms, err = loadKallsyms()
		if err != nil {
			log.Printf("Memleak: Warning - failed to load kallsyms: %v", err)
		}
	}

	// group outstanding allocations by (PID, stack_id)
	leakMap := make(map[leakKey]*stackAllocs)

	// iterate through everything that hasn't been freed
	var addr uint64
	var info memleakAllocInfo
	iter := m.objs.Allocs.Iterate()
	for iter.Next(&addr, &info) {
		stackID := info.StackId
		if stackID < 0 {
			continue
		}

		key := leakKey{PID: info.Pid, StackID: stackID}

		if _, exists := leakMap[key]; !exists {
			// Convert comm to string
			commBytes := make([]byte, 0, len(info.Comm))
			for _, b := range info.Comm {
				if b == 0 {
					break
				}
				commBytes = append(commBytes, byte(b))
			}
			comm := string(commBytes)

			leakMap[key] = &stackAllocs{
				StackID: stackID,
				Size:    0,
				Count:   0,
				PID:     info.Pid,
				Comm:    comm,
			}
		}

		leakMap[key].Size += info.Size
		leakMap[key].Count++
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterating allocs: %w", err)
	}

	var leaksToReport []*stackAllocs
	if detailed {
		// top 10 report
		for key, current := range leakMap {
			if current.Size >= m.minLeakThreshold {
				leaksToReport = append(leaksToReport, current)
			}
			// update previous stacks to maintain current state
			m.previousStacks[key] = current.Size
		}
	} else {
		// quick check
		for key, current := range leakMap {
			previous, existed := m.previousStacks[key]
			if current.Size > 10*1024*1024 && (!existed || current.Size > previous) {
				leaksToReport = append(leaksToReport, current)
				m.previousStacks[key] = current.Size
			}
		}
	}

	// sort descending by size
	sort.Slice(leaksToReport, func(i, j int) bool {
		return leaksToReport[i].Size > leaksToReport[j].Size
	})

	if detailed && len(leaksToReport) > 0 {
		// top 10 report
		maxStacks := min(10, len(leaksToReport))

		for i := 0; i < maxStacks; i++ {
			s := leaksToReport[i]

			stackTrace := m.getStackTrace(s.StackID, syms)
			stackTraceStr := strings.Join(stackTrace, " <- ")

			logEntry := models.Log{
				Time:  time.Now(),
				Level: "warning",
				Message: fmt.Sprintf("Memory leak in process '%s' (PID %d): %d bytes in %d allocations\nStack: %s",
					s.Comm, s.PID, s.Size, s.Count, stackTraceStr),
				Attributes: map[string]interface{}{
					"input":    "memleak",
					"hostname": hostname,
				},
			}
			acc.AddLog(logEntry)
		}
	} else if !detailed && len(leaksToReport) > 0 {
		// quick check
		for _, s := range leaksToReport {
			stackTrace := m.getStackTrace(s.StackID, syms)
			stackTraceStr := strings.Join(stackTrace, " <- ")

			logEntry := models.Log{
				Time:  time.Now(),
				Level: "critical",
				Message: fmt.Sprintf("Large memory leak in process '%s' (PID %d): %d bytes in %d allocations\nStack: %s",
					s.Comm, s.PID, s.Size, s.Count, stackTraceStr),
				Attributes: map[string]interface{}{
					"input":    "memleak",
					"hostname": hostname,
				},
			}
			acc.AddLog(logEntry)
		}
	}

	return nil
}

func (m *Memleak) Stop() error {
	log.Println("Memleak: Stop called")
	m.running = false

	for _, l := range m.links {
		if l != nil {
			l.Close()
		}
	}
	m.links = nil

	return nil
}

func (m *Memleak) Description() string {
	return "Memleak input plugin using eBPF. Tracks memory allocations and leaks in kernel or userspace."
}
