package server

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/k8shell-io/identity/pkg/backend"
	"github.com/k8shell-io/identity/pkg/providers/file"
	"github.com/k8shell-io/identity/pkg/providers/github"
	"github.com/k8shell-io/identity/pkg/providers/usermap"
	"gopkg.in/yaml.v3"
)

var envVarRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

type Config struct {
	Http              HttpConfig          `yaml:"http"`
	Cache             backend.CacheConfig `yaml:"cache"`
	DB                backend.DBConfig    `yaml:"db"`
	IdentityProviders []yaml.Node         `yaml:"identityProviders"`

	// ConfigDir is the directory where the configuration file is located.
	configDir string
}

func LoadConfig(configFile string) (*Config, error) {
	root, err := loadYaml(configFile)
	if err != nil {
		return nil, fmt.Errorf("load YAML config '%s': %w", configFile, err)
	}
	var config Config
	if err := root.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	absPath, err := filepath.Abs(configFile)
	if err != nil {
		return nil, fmt.Errorf("resolve config file path: %w", err)
	}
	config.configDir = filepath.Dir(absPath)

	// validate identity providers
	for _, node := range config.IdentityProviders {
		var raw map[string]any
		if err := node.Decode(&raw); err != nil {
			return nil, fmt.Errorf("decode raw provider map: %w", err)
		}

		id, ok := raw["id"].(string)
		if !ok {
			return nil, fmt.Errorf("missing or invalid provider 'id' field")
		}

		switch id {
		case "file":
			var fileProvCfg file.FileUserProviderConfig
			if err := node.Decode(&fileProvCfg); err != nil {
				return nil, fmt.Errorf("file provider config decode: %w", err)
			}

		case "usermap":
			var usermapProvCfg usermap.UserMapProviderConfig
			if err := node.Decode(&usermapProvCfg); err != nil {
				return nil, fmt.Errorf("usermap provider config decode: %w", err)
			}

		case "github":
			var githubProvCfg github.GitHubProviderConfig
			if err := node.Decode(&githubProvCfg); err != nil {
				return nil, fmt.Errorf("github provider config decode: %w", err)
			}

		default:
			return nil, fmt.Errorf("unknown identity provider id: %s", id)
		}

	}
	return &config, nil
}

func loadYaml(path string) (*yaml.Node, error) {
	rawYAML, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read YAML file '%s': %w", path, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(rawYAML, &root); err != nil {
		return nil, fmt.Errorf("unmarshal YAML file '%s': %w", path, err)
	}

	if len(root.Content) == 0 {
		return nil, fmt.Errorf("YAML file '%s' is empty", path)
	}

	if err := processNode(root.Content[0]); err != nil {
		return nil, fmt.Errorf("process YAML nodes: %w", err)
	}

	if len(root.Content) == 0 {
		return nil, fmt.Errorf("YAML file '%s' is empty", path)
	}

	return &root, nil
}

func processNode(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		// ENV substitution
		val, err := expandEnvVars(node.Value)
		if err != nil {
			return fmt.Errorf("expand env vars in '%s': %w", node.Value, err)
		}
		node.Value = val

		// Custom !file tag
		if node.Tag == "!file" {
			path := node.Value
			content, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				return fmt.Errorf("read !file '%s': %w", path, err)
			}
			node.Tag = "!!str"
			node.Value = strings.TrimSpace(string(content))
		}

	case yaml.SequenceNode, yaml.MappingNode:
		for _, n := range node.Content {
			if err := processNode(n); err != nil {
				return err
			}
		}
	}
	return nil
}

func expandEnvVars(input string) (string, error) {
	result := envVarRegex.ReplaceAllStringFunc(input, func(match string) string {
		return match
	})

	matches := envVarRegex.FindAllStringSubmatch(result, -1)

	for _, match := range matches {
		placeholder := match[0]
		varName := match[1]
		val, exists := os.LookupEnv(varName)
		if !exists {
			return "", fmt.Errorf("environment variable '%s' not set", varName)
		}
		result = strings.ReplaceAll(result, placeholder, val)
	}

	return result, nil
}
