package loki

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cthiel42/arbutus/internal/models"
)

const (
	defaultEndpoint      = "/loki/api/v1/push"
	defaultClientTimeout = "10s"
)

type LokiLog [2]string // [timestamp, line]

type Stream struct {
	Stream map[string]string `json:"stream"`
	Values []LokiLog         `json:"values"`
}

type Streams struct {
	Streams []Stream `json:"streams"`
}

type Loki struct {
	// Configuration fields
	Domain   string
	Endpoint string
	Timeout  string
	Username string
	Password string
	Headers  map[string]string

	// Internal state
	url    string
	client *http.Client
}

func init() {
	models.RegisterOutputPlugin("loki", New)
}

func New() models.Output {
	return &Loki{}
}

func (l *Loki) Configure(config map[string]any) error {
	// marshall config into struct fields using json
	// TODO: This is disgusting, find a better way
	jsonData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	err = json.Unmarshal(jsonData, l)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// validation and defaults
	if l.Domain == "" {
		return errors.New("domain is required")
	}

	if l.Endpoint == "" {
		l.Endpoint = defaultEndpoint
	}

	l.url = fmt.Sprintf("%s%s", l.Domain, l.Endpoint)

	if l.Timeout == "" {
		l.Timeout = defaultClientTimeout
	}

	return nil
}

func (l *Loki) Connect(config map[string]any) error {
	log.Println("Loki: Connect called")

	if err := l.Configure(config); err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	ctx := context.Background()
	client, err := l.createClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}
	l.client = client

	log.Printf("Loki: Connected successfully to %s", l.url)
	return nil
}

func (l *Loki) Write(telemetry []models.Telemetry) error {
	if len(telemetry) == 0 {
		return nil
	}
	streams := Streams{}

	for _, t := range telemetry {
		switch t.Type() {
		case models.TelemetryTypeLog:
			logEntry := t.(models.Log)
			labels := make(map[string]string)

			// Loki has strict label requirements and occasionally log attributes may contain non UTF-8 data
			// so we sanitize all attribute values to valid UTF-8
			labels["level"] = sanitizeUTF8(logEntry.Level, "level")
			for key, value := range logEntry.Attributes {
				valueStr := fmt.Sprintf("%v", value)
				labels[key] = sanitizeUTF8(valueStr, fmt.Sprintf("attribute[%s]", key))
			}
			line := sanitizeUTF8(logEntry.Message, "message")
			lokiLog := LokiLog{
				strconv.FormatInt(logEntry.Time.UnixNano(), 10),
				line,
			}

			streams.insertLog(labels, lokiLog)

		case models.TelemetryTypeTrace:
			log.Printf("Loki: Skipping trace (not supported)")
		case models.TelemetryTypeMetric:
			log.Printf("Loki: Skipping metric (not supported)")
		}
	}

	return l.sendToLoki(streams)
}

func (l *Loki) Close() error {
	log.Println("Loki: Close called")

	if l.client != nil {
		l.client.CloseIdleConnections()
	}

	log.Println("Loki: Closed successfully")
	return nil
}

func (l *Loki) Description() string {
	return "Sends logs to Grafana Loki"
}

func sanitizeUTF8(s string, fieldName string) string {
	if utf8.ValidString(s) {
		return s
	}

	log.Printf("Loki: Found invalid UTF-8 in %s, sanitizing. Original: %q", fieldName, s)
	return strings.ToValidUTF8(s, "�")
}

func (l *Loki) SupportedTypes() map[models.TelemetryType]bool {
	return map[models.TelemetryType]bool{
		models.TelemetryTypeLog: true,
	}
}

func (l *Loki) sendToLoki(streams Streams) error {
	payload, err := json.Marshal(streams)
	if err != nil {
		return fmt.Errorf("failed to marshal streams: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, l.url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	for k, v := range l.Headers {
		if strings.EqualFold(k, "host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}

	if l.Username != "" && l.Password != "" {
		req.SetBasicAuth(l.Username, l.Password)
	}

	resp, err := l.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("loki returned status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Loki: Successfully sent %d streams", len(streams.Streams))
	return nil
}

func (l *Loki) createClient(ctx context.Context) (*http.Client, error) {
	duration, err := time.ParseDuration(l.Timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout duration: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
		Timeout: duration,
	}

	return client, nil
}

// adds a log entry to the appropriate stream based on labels
func (s *Streams) insertLog(labels map[string]string, log LokiLog) {
	for i, stream := range s.Streams {
		if mapsEqual(stream.Stream, labels) {
			s.Streams[i].Values = append(s.Streams[i].Values, log)
			return
		}
	}

	s.Streams = append(s.Streams, Stream{
		Stream: labels,
		Values: []LokiLog{log},
	})
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
