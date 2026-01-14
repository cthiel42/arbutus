package opensnoop

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cthiel42/arbutus/internal/models"
)

// opensnoopEvent matches the C struct event from opensnoop.bpf.c
type opensnoopEvent struct {
	Pid   uint32
	Uid   uint32
	Ret   int32
	Comm  [16]byte
	Fname [256]byte
}

type OpenSnoop struct {
	running bool
}

func init() {
	models.RegisterInputPlugin("opensnoop", New)
}

func New() models.Input {
	return &OpenSnoop{
		running: false,
	}
}

func (o *OpenSnoop) Run(ctx context.Context, acc models.Accumulator, config map[string]interface{}) error {
	log.Println("OpenSnoop: Run called")

	// load eBPF objects
	var objs opensnoopObjects
	if err := loadOpensnoopObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	o.running = true
	log.Println("OpenSnoop: Started successfully, waiting for events...")

	// Channel to decouple reading from ring buffer and processing events.
	eventChan := make(chan opensnoopEvent, 10000)
	errChan := make(chan error, 1)

	// start goroutine to read from ring buffer
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				errChan <- fmt.Errorf("reading from ringbuf: %w", err)
				return
			}

			var event opensnoopEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("OpenSnoop: Error parsing event: %v", err)
				continue
			}

			select {
			case eventChan <- event:
			default:
				log.Println("OpenSnoop: Event channel full, dropping event")
			}
		}
	}()

	// process events
	for o.running {
		select {
		case <-ctx.Done():
			log.Println("OpenSnoop: Context cancelled, stopping")
			return ctx.Err()

		case err := <-errChan:
			log.Printf("OpenSnoop: Ring buffer error: %v", err)
			return err

		case event := <-eventChan:
			// convert null-terminated byte arrays to strings
			comm := cstring(event.Comm[:])
			fname := cstring(event.Fname[:])

			logEntry := models.Log{
				Time:    time.Now(),
				Level:   "info",
				Message: fmt.Sprintf("Process %s (PID %d) opened file: %s", comm, event.Pid, fname),
				Attributes: map[string]interface{}{
					"input":    "opensnoop",
					"hostname": hostname,
				},
			}
			acc.AddLog(logEntry)
		}
	}

	log.Println("OpenSnoop: Stopped by Stop() call")
	return nil
}

func (o *OpenSnoop) Stop() error {
	log.Println("OpenSnoop: Stop called")
	o.running = false
	return nil
}

func (o *OpenSnoop) Description() string {
	return "Monitors file open operations using eBPF"
}

// cstring converts a null-terminated byte array to a Go string
// It finds the first null byte and returns everything before it
func cstring(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}
