package file

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/cthiel42/arbutus/internal/models"
)

type File struct {
	FilePath string // config field
	file     *os.File
	mutex    sync.Mutex
}

func init() {
	models.RegisterOutputPlugin("file", New)
}

func New() models.Output {
	return &File{}
}

func (f *File) Connect(config map[string]any) error {
	log.Println("File: Connect called")

	jsonData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	err = json.Unmarshal(jsonData, f)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if f.FilePath == "" {
		return fmt.Errorf("filepath is required")
	}

	file, err := os.OpenFile(f.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	f.file = file

	log.Printf("File: Connected successfully to %s", f.FilePath)
	return nil
}

func (f *File) Write(telemetry []models.Telemetry) error {
	if len(telemetry) == 0 {
		return nil
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()

	for _, t := range telemetry {
		switch t.Type() {
		case models.TelemetryTypeLog:
			if err := f.writeLog(t.(models.Log)); err != nil { //nolint:forcetypeassert
				return err
			}
		case models.TelemetryTypeMetric:
			if err := f.writeMetric(t.(models.Metric)); err != nil { //nolint:forcetypeassert
				return err
			}
		case models.TelemetryTypeTrace:
			log.Printf("File: Skipping trace (not supported)")
		}
	}

	return nil
}

func (f *File) writeLog(logEntry models.Log) error {
	var line string
	attrs := ""
	if len(logEntry.Attributes) > 0 {
		attrData, _ := json.Marshal(logEntry.Attributes)
		attrs = " " + string(attrData)
	}
	line = fmt.Sprintf("%s [%s] %s%s\n",
		logEntry.Time.Format(time.RFC3339),
		logEntry.Level,
		logEntry.Message,
		attrs,
	)

	_, err := f.file.WriteString(line)
	if err != nil {
		return fmt.Errorf("failed to write log: %w", err)
	}

	return nil
}

// write metric in influx line protocol
func (f *File) writeMetric(metric models.Metric) error {
	var line string
	tags := ""
	if len(metric.Tags) > 0 {
		for k, v := range metric.Tags {
			tags += fmt.Sprintf(",%s=%s", k, v)
		}
	}

	fields := fmt.Sprintf("value=%v", metric.Value)
	if len(metric.Fields) > 0 {
		for k, v := range metric.Fields {
			fields += fmt.Sprintf(",%s=%v", k, v)
		}
	}

	line = fmt.Sprintf("%s%s %s %d\n",
		metric.Name,
		tags,
		fields,
		metric.Time.UnixNano(),
	)

	_, err := f.file.WriteString(line)
	if err != nil {
		return fmt.Errorf("failed to write metric: %w", err)
	}

	return nil
}

func (f *File) Close() error {
	log.Println("File: Close called")

	f.mutex.Lock()
	defer f.mutex.Unlock()

	if f.file != nil {
		if err := f.file.Sync(); err != nil {
			log.Printf("File: Warning - failed to sync file: %v", err)
		}
		if err := f.file.Close(); err != nil {
			return fmt.Errorf("failed to close file: %w", err)
		}
		f.file = nil
	}

	log.Println("File: Closed successfully")
	return nil
}

func (f *File) Description() string {
	return "Writes logs and metrics to a file in line format"
}

func (f *File) SupportedTypes() map[models.TelemetryType]bool {
	return map[models.TelemetryType]bool{
		models.TelemetryTypeLog:    true,
		models.TelemetryTypeMetric: true,
	}
}
