package console

import (
	"testing"
	"time"

	"github.com/cthiel42/arbutus/internal/models"
)

func TestWriteLog(t *testing.T) {
	c := New()

	log := models.Log{
		Time:    time.Now(),
		Level:   "INFO",
		Message: "test message",
		Attributes: map[string]interface{}{
			"key": "value",
		},
	}

	err := c.Write([]models.Telemetry{log})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestWriteMetric(t *testing.T) {
	c := New()

	metric := models.Metric{
		Time:  time.Now(),
		Name:  "test_metric",
		Value: 42.5,
		Tags: map[string]string{
			"env": "test",
		},
		Fields: map[string]interface{}{
			"count": 10,
		},
	}

	err := c.Write([]models.Telemetry{metric})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}
