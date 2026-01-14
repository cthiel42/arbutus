package file

import (
	"os"
	"testing"
	"time"

	"github.com/cthiel42/arbutus/internal/models"
)

func TestWriteLog(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "arbutus-test-*.log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	f, ok := New().(*File)
	if !ok {
		t.Fatalf("expected *File")
	}
	config := map[string]any{
		"filepath": tmpFile.Name(),
	}

	err = f.Connect(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer f.Close()

	log := models.Log{
		Time:    time.Now(),
		Level:   "INFO",
		Message: "test message",
		Attributes: map[string]interface{}{
			"key": "value",
		},
	}

	err = f.Write([]models.Telemetry{log})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestWriteMetric(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "arbutus-test-*.log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	f, ok := New().(*File)
	if !ok {
		t.Fatalf("expected *File")
	}
	config := map[string]any{
		"filepath": tmpFile.Name(),
	}

	err = f.Connect(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer f.Close()

	metric := models.Metric{
		Time:  time.Now(),
		Name:  "test_metric",
		Value: 42.5,
		Tags: map[string]string{
			"env": "test",
		},
	}

	err = f.Write([]models.Telemetry{metric})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}
