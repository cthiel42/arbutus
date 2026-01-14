package outputs

import (
	"log"

	"github.com/cthiel42/arbutus/internal/models"

	_ "github.com/cthiel42/arbutus/internal/plugins/outputs/console"
	_ "github.com/cthiel42/arbutus/internal/plugins/outputs/file"
	_ "github.com/cthiel42/arbutus/internal/plugins/outputs/loki"
)

// InitializeOutputs creates and connects output plugins based on configuration
func InitializeOutputs(outputConfigs map[string]map[string]any) []models.Output {
	var outputs []models.Output

	for name, config := range outputConfigs {
		log.Printf("Initializing output: %s with config: %+v", name, config)

		if constructor, exists := models.GetOutputPluginConstructor(name); exists {
			output := constructor()

			// Connect in a goroutine to allow concurrent initialization
			go func(pluginName string, plugin models.Output, cfg map[string]any) {
				if err := plugin.Connect(cfg); err != nil {
					log.Printf("Failed to connect output %s: %v", pluginName, err)
				} else {
					log.Printf("Output %s connected successfully", pluginName)
				}
			}(name, output, config)

			outputs = append(outputs, output)
			log.Printf("Started output: %s", name)
		} else {
			log.Printf("Output plugin not found: %s", name)
		}
	}

	return outputs
}
