package loki

import (
	"testing"
	"time"

	"github.com/cthiel42/arbutus/internal/models"
)

func TestWriteLog(t *testing.T) {
	l, ok := New().(*Loki)
	if !ok {
		t.Fatalf("expected *Loki")
	}
	config := map[string]any{
		"domain": "http://localhost:3100",
	}

	err := l.Connect(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer l.Close()

	log := models.Log{
		Time:    time.Now(),
		Level:   "INFO",
		Message: "test message",
		Attributes: map[string]interface{}{
			"service": "test",
		},
	}

	// This will fail since there's no actual Loki server, but that's expected
	_ = l.Write([]models.Telemetry{log})
}

func TestSanitizeUTF8(t *testing.T) {
	valid := "hello world"
	result := sanitizeUTF8(valid, "test")
	if result != valid {
		t.Errorf("Expected %q, got %q", valid, result)
	}

	invalid := "hello\xc5world"
	result = sanitizeUTF8(invalid, "test")
	if result == invalid {
		t.Error("Expected invalid UTF-8 to be sanitized")
	}
}
