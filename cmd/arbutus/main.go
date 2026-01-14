package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cthiel42/arbutus/internal/config"
	"github.com/cthiel42/arbutus/internal/pipeline"
	"github.com/cthiel42/arbutus/internal/plugins/inputs"
	"github.com/cthiel42/arbutus/internal/plugins/outputs"
)

func main() {
	configPath := flag.String("config", "arbutus.toml", "path to configuration file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Starting Arbutus")
	log.Printf("Config: %+v", cfg)

	outputs := outputs.InitializeOutputs(cfg.Outputs)
	pipe := pipeline.NewPipeline(outputs)
	inputs := inputs.InitializeInputs(cfg.Inputs, pipe)

	log.Printf("Loaded %d inputs and %d outputs", len(inputs), len(outputs))

	// setup context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	flushTicker := time.NewTicker(10 * time.Second)
	defer flushTicker.Stop()

	log.Println("Arbutus started successfully")

	// main loop
	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			pipe.Flush()
			return
		case <-sigCh:
			log.Println("Received shutdown signal")
			cancel()
		case <-flushTicker.C:
			pipe.Flush()
		case <-pipe.FlushChannel():
			pipe.Flush()
		}
	}
}
