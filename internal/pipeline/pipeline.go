package pipeline

import (
	"log"
	"sync"

	"github.com/cthiel42/arbutus/internal/models"
)

// Routes telemetry data from inputs to outputs
type Pipeline struct {
	outputs []models.Output
	buffer  []models.Telemetry
	mu      sync.Mutex
	flush   chan struct{}
}

func NewPipeline(outputs []models.Output) *Pipeline {
	return &Pipeline{
		outputs: outputs,
		buffer:  make([]models.Telemetry, 0, 10000),
		flush:   make(chan struct{}, 1),
	}
}

func (p *Pipeline) AddLog(l models.Log) {
	p.add(l)
}

func (p *Pipeline) AddSpan(s models.Span) {
	p.add(s)
}

func (p *Pipeline) AddMetric(m models.Metric) {
	p.add(m)
}

func (p *Pipeline) add(t models.Telemetry) {
	p.mu.Lock()
	p.buffer = append(p.buffer, t)
	shouldFlush := len(p.buffer) >= 100
	p.mu.Unlock()

	if shouldFlush {
		select {
		case p.flush <- struct{}{}:
		default:
		}
	}
}

// Send all buffered telemetry to outputs
// TODO: a lot of performance improvements possible here
// especially around minimizing copies and cycles spent filtering
func (p *Pipeline) Flush() {
	p.mu.Lock()
	if len(p.buffer) == 0 {
		p.mu.Unlock()
		return
	}

	toFlush := make([]models.Telemetry, len(p.buffer))
	copy(toFlush, p.buffer)
	p.buffer = p.buffer[:0]
	p.mu.Unlock()
	log.Printf("Pipeline: Flushing %d telemetry items", len(toFlush))

	// group telemetry by type for each output
	for _, output := range p.outputs {
		supportedTypes := output.SupportedTypes()

		var filtered []models.Telemetry
		for _, t := range toFlush {
			if supportedTypes[t.Type()] {
				filtered = append(filtered, t)
			}
		}

		if len(filtered) > 0 {
			if err := output.Write(filtered); err != nil {
				log.Printf("Error writing to output %T: %v", output, err)
			}
		}
	}
}

// returns the channel used to signal flush requests
func (p *Pipeline) FlushChannel() <-chan struct{} {
	return p.flush
}
