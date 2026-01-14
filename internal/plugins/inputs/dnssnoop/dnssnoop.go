package dnssnoop

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

// dnssnoopEvent matches the C struct event from dnssnoop.bpf.c
type dnssnoopEvent struct {
	Pid        uint32
	Comm       [16]byte
	DstIP      uint32
	PayloadLen uint32
	Payload    [256]byte
}

type Dnssnoop struct {
	running bool
}

func init() {
	models.RegisterInputPlugin("dnssnoop", New)
}

func New() models.Input {
	return &Dnssnoop{
		running: false,
	}
}

func (o *Dnssnoop) Run(ctx context.Context, acc models.Accumulator, config map[string]interface{}) error {
	log.Println("Dnssnoop: Run called")

	// load eBPF objects
	var objs dnssnoopObjects
	if err := loadDnssnoopObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	defer objs.Close()

	lnk, err := link.AttachTracing(link.TracingOptions{
		Program: objs.DnsSend,
	})
	if err != nil {
		return fmt.Errorf("attaching fentry: %w", err)
	}
	defer lnk.Close()

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
	log.Println("Dnssnoop: Started successfully, waiting for events...")

	// Channel to decouple reading from ring buffer and processing events.
	eventChan := make(chan dnssnoopEvent, 10000)
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

			var event dnssnoopEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Dnssnoop: Error parsing event: %v", err)
				continue
			}

			select {
			case eventChan <- event:
			default:
				log.Println("Dnssnoop: Event channel full, dropping event")
			}
		}
	}()

	// process events
	for o.running {
		select {
		case <-ctx.Done():
			log.Println("Dnssnoop: Context cancelled, stopping")
			return ctx.Err()

		case err := <-errChan:
			log.Printf("Dnssnoop: Ring buffer error: %v", err)
			return err

		case event := <-eventChan:
			dstIP := fmt.Sprintf("%d.%d.%d.%d",
				byte(event.DstIP),
				byte(event.DstIP>>8),
				byte(event.DstIP>>16),
				byte(event.DstIP>>24))

			// Parse DNS query to extract domain name
			dnsQuery := ""
			if event.PayloadLen > 12 {
				// DNS header is 12 bytes, query name starts after that
				dnsQuery = parseDNSQuery(event.Payload[:event.PayloadLen])
			}

			// end debug logging
			logEntry := models.Log{
				Time:    time.Now(),
				Level:   "info",
				Message: fmt.Sprintf("DNS Query: pid=%d comm=%s dst_ip=%s query=%s", event.Pid, cstring(event.Comm[:]), dstIP, dnsQuery),
				Attributes: map[string]interface{}{
					"input":    "dnssnoop",
					"hostname": hostname,
				},
			}
			acc.AddLog(logEntry)
		}
	}

	log.Println("Dnssnoop: Stopped by Stop() call")
	return nil
}

func (o *Dnssnoop) Stop() error {
	log.Println("Dnssnoop: Stop called")
	o.running = false
	return nil
}

func (o *Dnssnoop) Description() string {
	return "Dnssnoop input plugin using eBPF. Returns DNS query logs."
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

// parseDNSQuery extracts the domain name from a DNS query packet
// DNS packet format:
// - Header (12 bytes): ID, flags, question count, answer count, authority count, additional count
// - Question section: domain name (variable length), query type (2 bytes), query class (2 bytes)
// Domain names are encoded as length-prefixed labels: \x06google\x03com\x00
func parseDNSQuery(payload []byte) string {
	if len(payload) < 13 {
		return ""
	}

	// skip DNS header
	offset := 12
	var domain []byte

	for offset < len(payload) {
		// read len of next label
		labelLen := int(payload[offset])
		offset++

		if labelLen == 0 {
			break
		}

		// Check for DNS pointer/compression
		// if the top 2 bits are set (value >= 192) its a pointer
		if labelLen >= 192 {
			// dont handle this case for now, just skip
			break
		}

		// make sure theres enough data left in the payload
		if offset+labelLen > len(payload) {
			break
		}

		// Add a dot separator if this isn't the first label
		if len(domain) > 0 {
			domain = append(domain, '.')
		}

		domain = append(domain, payload[offset:offset+labelLen]...)
		offset += labelLen
	}

	return string(domain)
}
