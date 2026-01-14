package template

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

// templateEvent matches the C struct event from template.bpf.c
type templateEvent struct {
	Msg [256]byte
}

type Template struct {
	running bool
}

func init() {
	models.RegisterInputPlugin("template", New)
}

func New() models.Input {
	return &Template{
		running: false,
	}
}

func (o *Template) Run(ctx context.Context, acc models.Accumulator, config map[string]interface{}) error {
	log.Println("Template: Run called")

	// load eBPF objects
	var objs templateObjects
	if err := loadTemplateObjects(&objs, nil); err != nil {
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
	log.Println("Template: Started successfully, waiting for events...")

	// Channel to decouple reading from ring buffer and processing events.
	// You may be wondering why there's a ring buffer, this channel, and a buffer in
	// the accumulator. This channel allows us to keep the smaller ring buffer clear
	// while processing events to put in the accumulator. It also allows us to shutdown
	// cleaner by putting the blocking read operation in a goroutine.
	eventChan := make(chan templateEvent, 10000)
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

			var event templateEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Template: Error parsing event: %v", err)
				continue
			}

			select {
			case eventChan <- event:
			default:
				log.Println("Template: Event channel full, dropping event")
			}
		}
	}()

	// process events
	for o.running {
		select {
		case <-ctx.Done():
			log.Println("Template: Context cancelled, stopping")
			return ctx.Err()

		case err := <-errChan:
			log.Printf("Template: Ring buffer error: %v", err)
			return err

		case event := <-eventChan:
			// convert null-terminated byte arrays to strings
			msg := cstring(event.Msg[:])

			logEntry := models.Log{
				Time:    time.Now(),
				Level:   "info",
				Message: fmt.Sprintf("Template msg: %s", msg),
				Attributes: map[string]interface{}{
					"input":    "template",
					"hostname": hostname,
				},
			}
			acc.AddLog(logEntry)
		}
	}

	log.Println("Template: Stopped by Stop() call")
	return nil
}

func (o *Template) Stop() error {
	log.Println("Template: Stop called")
	o.running = false
	return nil
}

func (o *Template) Description() string {
	return "Template input plugin using eBPF. Attaches to sys_enter_openat tracepoint and emits a hello world log for each event."
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
