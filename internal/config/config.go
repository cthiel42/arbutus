package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Agent   AgentConfig               `toml:"agent"`
	Inputs  map[string]map[string]any `toml:"inputs"`
	Outputs map[string]map[string]any `toml:"outputs"`
}

type AgentConfig struct {
	FlushInterval string `toml:"flush_interval"` // todo: implement
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}
