package inputs

import (
	"context"
	"log"

	"github.com/cthiel42/arbutus/internal/models"
	"github.com/cthiel42/arbutus/internal/pipeline"

	_ "github.com/cthiel42/arbutus/internal/plugins/inputs/dnssnoop"
	_ "github.com/cthiel42/arbutus/internal/plugins/inputs/memleak"
	_ "github.com/cthiel42/arbutus/internal/plugins/inputs/opensnoop"
)

// Creates and starts input plugins based on config
func InitializeInputs(inputConfigs map[string]map[string]any, pipe *pipeline.Pipeline) []models.Input {
	var inputs []models.Input
	ctx := context.Background()

	for name, config := range inputConfigs {
		log.Printf("Initializing input: %s with config: %+v", name, config)

		if constructor, exists := models.GetInputPluginConstructor(name); exists {
			input := constructor()

			// Start plugin in a goroutine since Run() blocks
			go func(pluginName string, plugin models.Input) {
				if err := plugin.Run(ctx, pipe, config); err != nil {
					log.Printf("Input plugin %s stopped with error: %v", pluginName, err)
				} else {
					log.Printf("Input plugin %s stopped cleanly", pluginName)
				}
			}(name, input)

			inputs = append(inputs, input)
			log.Printf("Started input: %s", name)
		} else {
			log.Printf("Input plugin not found: %s", name)
		}
	}

	return inputs
}
