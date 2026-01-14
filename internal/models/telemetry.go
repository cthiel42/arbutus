package models

import "time"

// Shared telemetry types for passing data from inputs to outputs
type TelemetryType string

const (
	TelemetryTypeLog    TelemetryType = "log"
	TelemetryTypeTrace  TelemetryType = "trace"
	TelemetryTypeMetric TelemetryType = "metric"
)

type Telemetry interface {
	Type() TelemetryType
	Timestamp() time.Time
}

type Log struct {
	Time       time.Time
	Level      string
	Message    string
	Attributes map[string]interface{}
}

func (l Log) Type() TelemetryType  { return TelemetryTypeLog }
func (l Log) Timestamp() time.Time { return l.Time }

type Span struct {
	TraceID    string
	SpanID     string
	ParentID   string
	Name       string
	StartTime  time.Time
	EndTime    time.Time
	Attributes map[string]interface{}
}

func (s Span) Type() TelemetryType  { return TelemetryTypeTrace }
func (s Span) Timestamp() time.Time { return s.StartTime }

type Metric struct {
	Time   time.Time
	Name   string
	Value  float64
	Tags   map[string]string
	Fields map[string]interface{}
}

func (m Metric) Type() TelemetryType  { return TelemetryTypeMetric }
func (m Metric) Timestamp() time.Time { return m.Time }
