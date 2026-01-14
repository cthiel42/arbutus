package models

import "context"

// Plugin and accumulator interfaces
type Input interface {
	Run(ctx context.Context, acc Accumulator, config map[string]interface{}) error
	Stop() error
	Description() string
}

type Output interface {
	Connect(config map[string]any) error
	Write(telemetry []Telemetry) error
	Close() error
	Description() string
	SupportedTypes() map[TelemetryType]bool
}

type Accumulator interface {
	AddLog(log Log)
	AddSpan(span Span)
	AddMetric(metric Metric)
	Flush()
	FlushChannel() <-chan struct{}
}

// Registry for input plugins
var inputPluginRegistry = make(map[string]func() Input)

func RegisterInputPlugin(name string, constructor func() Input) {
	inputPluginRegistry[name] = constructor
}

func GetInputPluginConstructor(name string) (func() Input, bool) {
	constructor, exists := inputPluginRegistry[name]
	return constructor, exists
}

// Registry for output plugins
var outputPluginRegistry = make(map[string]func() Output)

func RegisterOutputPlugin(name string, constructor func() Output) {
	outputPluginRegistry[name] = constructor
}

func GetOutputPluginConstructor(name string) (func() Output, bool) {
	constructor, exists := outputPluginRegistry[name]
	return constructor, exists
}
