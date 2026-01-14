package console

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cthiel42/arbutus/internal/models"
)

type Console struct {
	mutex sync.Mutex
}

func init() {
	models.RegisterOutputPlugin("console", New)
}

func New() models.Output {
	return &Console{}
}

func (c *Console) Connect(config map[string]any) error {
	log.Println("Console: Connected successfully")
	return nil
}

func (c *Console) Write(telemetry []models.Telemetry) error {
	if len(telemetry) == 0 {
		return nil
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, t := range telemetry {
		switch t.Type() {
		case models.TelemetryTypeLog:
			c.writeLog(t.(models.Log))
		case models.TelemetryTypeMetric:
			c.writeMetric(t.(models.Metric))
		case models.TelemetryTypeTrace:
			log.Printf("Console: Skipping trace (not supported)")
		}
	}

	return nil
}

func (c *Console) writeLog(logEntry models.Log) {
	attrs := ""
	if len(logEntry.Attributes) > 0 {
		attrData, _ := json.Marshal(logEntry.Attributes)
		attrs = " " + string(attrData)
	}
	line := fmt.Sprintf("%s [%s] %s%s",
		logEntry.Time.Format(time.RFC3339),
		logEntry.Level,
		logEntry.Message,
		attrs,
	)

	fmt.Println(line)
}

func (c *Console) writeMetric(metric models.Metric) {
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

	line := fmt.Sprintf("%s%s %s %d",
		metric.Name,
		tags,
		fields,
		metric.Time.UnixNano(),
	)

	fmt.Println(line)
}

func (c *Console) Close() error {
	log.Println("Console: Closed successfully")
	return nil
}

func (c *Console) Description() string {
	return "Writes logs and metrics to console output in line format"
}

func (c *Console) SupportedTypes() map[models.TelemetryType]bool {
	return map[models.TelemetryType]bool{
		models.TelemetryTypeLog:    true,
		models.TelemetryTypeMetric: true,
	}
}