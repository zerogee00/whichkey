// Package config handles configuration loading and management.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config represents the complete application configuration
type Config struct {
	DefaultEnvironment string                       `json:"default_environment"`
	Environments       map[string]EnvironmentConfig `json:"environments"`
	AWSProfiles        AWSProfileConfig             `json:"aws_profiles"`
	KubectlContexts    map[string][]string          `json:"kubectl_contexts"`
	FallbackUtilityIDs []string                     `json:"fallback_utility_clip_ids"`
}

// EnvironmentConfig holds environment-specific configuration
type EnvironmentConfig struct {
	Name          string   `json:"name"`
	Aliases       []string `json:"aliases"`
	Namespace     string   `json:"namespace"`
	ConfigMapName string   `json:"configmap_name"`
	SecretName    string   `json:"secret_name"`
	KMSEndpoint   string   `json:"kms_endpoint"`
	KMSToken      string   `json:"kms_token"`
	VaultPath     string   `json:"vault_path"`
	VaultServer   string   `json:"vault_server"`
	VaultKey      string   `json:"vault_key"`
}

// AWSProfileConfig holds AWS profile mappings
type AWSProfileConfig struct {
	BucketPatterns map[string]string `json:"bucket_patterns"`
	DefaultProfile string            `json:"default_profile"`
}

// global config instance
var globalConfig *Config

// configSearchPaths returns paths to search for config file
func configSearchPaths() []string {
	var paths []string

	// 1. Current directory
	paths = append(paths, "whichkey.json")
	paths = append(paths, ".whichkey.json")

	// 2. Home directory
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".whichkey.json"))
		paths = append(paths, filepath.Join(home, ".config", "whichkey", "config.json"))
	}

	// 3. XDG config directory
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		paths = append(paths, filepath.Join(xdgConfig, "whichkey", "config.json"))
	}

	// 4. Executable directory
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		paths = append(paths, filepath.Join(exeDir, "whichkey.json"))
		paths = append(paths, filepath.Join(exeDir, "config.json"))
	}

	return paths
}

// LoadConfig loads configuration from file or returns defaults
func LoadConfig() (*Config, error) {
	// Return cached config if already loaded
	if globalConfig != nil {
		return globalConfig, nil
	}

	// Try to find and load config file
	for _, path := range configSearchPaths() {
		if data, err := os.ReadFile(path); err == nil {
			cfg := &Config{}
			if err := json.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
			}
			globalConfig = cfg
			return globalConfig, nil
		}
	}

	// No config file found, use embedded defaults
	globalConfig = getDefaultConfig()
	return globalConfig, nil
}

// LoadConfigFromFile loads configuration from a specific file
func LoadConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	globalConfig = cfg
	return globalConfig, nil
}

// GetConfig returns the loaded config or loads it if not already loaded
func GetConfig() *Config {
	if globalConfig == nil {
		cfg, _ := LoadConfig()
		return cfg
	}
	return globalConfig
}

// GetEnvironment returns the environment config for a given name (handling aliases)
func (c *Config) GetEnvironment(name string) (EnvironmentConfig, bool) {
	nameLower := strings.ToLower(name)

	// Direct match
	if env, exists := c.Environments[nameLower]; exists {
		return env, true
	}

	// Check aliases
	for _, env := range c.Environments {
		for _, alias := range env.Aliases {
			if strings.ToLower(alias) == nameLower {
				return env, true
			}
		}
	}

	return EnvironmentConfig{}, false
}

// GetAWSProfile returns the AWS profile for a bucket name
func (c *Config) GetAWSProfile(bucket string) string {
	bucketLower := strings.ToLower(bucket)

	// Sort patterns by length (longest first) to ensure more specific patterns match first
	// e.g., "nonprd" should match before "prd"
	type patternProfile struct {
		pattern string
		profile string
	}
	var patterns []patternProfile
	for pattern, profile := range c.AWSProfiles.BucketPatterns {
		patterns = append(patterns, patternProfile{pattern, profile})
	}
	// Sort by pattern length descending
	for i := 0; i < len(patterns)-1; i++ {
		for j := i + 1; j < len(patterns); j++ {
			if len(patterns[i].pattern) < len(patterns[j].pattern) {
				patterns[i], patterns[j] = patterns[j], patterns[i]
			}
		}
	}

	// Check patterns in order (longest first)
	for _, pp := range patterns {
		if strings.Contains(bucketLower, strings.ToLower(pp.pattern)) {
			return pp.profile
		}
	}

	return c.AWSProfiles.DefaultProfile
}

// GetKubectlContexts returns possible kubectl contexts for an environment
func (c *Config) GetKubectlContexts(env string) []string {
	if contexts, exists := c.KubectlContexts[strings.ToLower(env)]; exists {
		return contexts
	}
	return nil
}

// getDefaultConfig returns the embedded default configuration
func getDefaultConfig() *Config {
	return &Config{
		DefaultEnvironment: "nonprd",
		Environments: map[string]EnvironmentConfig{
			"nonprd": {
				Name:          "nonprd",
				Aliases:       []string{"dev", "development", "sandbox", "sbox"},
				Namespace:     "nonprd-service-media-center",
				ConfigMapName: "configmap.service-media-center-utility-clip-ids",
				SecretName:    "secret.service-media-center",
				KMSEndpoint:   "https://service-video-kms-use1-1.nonprd.pluto.tv/v1",
				VaultPath:     "app/common/shared-encryption/nonprd",
				VaultServer:   "https://vault-nonprd.devops.pluto.tv",
				VaultKey:      "STATIC_ENCRYPTION_KEYS",
			},
			"preprd": {
				Name:          "preprd",
				Aliases:       []string{"preprod"},
				Namespace:     "preprd-service-media-center",
				ConfigMapName: "configmap.service-media-center-utility-clip-ids",
				SecretName:    "secret.service-media-center",
				KMSEndpoint:   "https://service-video-kms-use1-1.preprd.pluto.tv/v1",
				VaultPath:     "app/common/shared-encryption/preprd",
				VaultServer:   "https://vault-ent-preprod.devops.pluto.tv:8200",
				VaultKey:      "STATIC_ENCRYPTION_KEYS",
			},
			"prd": {
				Name:          "prd",
				Aliases:       []string{"prod", "production"},
				Namespace:     "prd-service-media-center",
				ConfigMapName: "configmap.service-media-center-utility-clip-ids",
				SecretName:    "secret.service-media-center",
				KMSEndpoint:   "https://service-video-kms-use1-1.prd.pluto.tv/v1",
				VaultPath:     "app/common/shared-encryption/prd",
				VaultServer:   "https://vault-ent-prod.devops.pluto.tv:8200",
				VaultKey:      "STATIC_ENCRYPTION_KEYS",
			},
		},
		AWSProfiles: AWSProfileConfig{
			BucketPatterns: map[string]string{
				"slio":   "main-tier4",
				"nonprd": "nonprod-tier3",
				"dev":    "nonprod-tier3",
				"preprd": "preprod-tier3",
				"prd":    "main-tier4",
			},
			DefaultProfile: "",
		},
		KubectlContexts: map[string][]string{
			"nonprd": {"nonprd", "pluto-nonprd", "aws-nonprd"},
			"preprd": {"preprd", "pluto-preprd", "aws-preprd"},
			"prd":    {"prd", "pluto-prd", "pluto-prod", "production", "prod", "aws-prd", "aws-prod"},
		},
		FallbackUtilityIDs: []string{
			"622721e908d75d0007f44311",
			"56244db86ffa1d5f58b77376",
			"56c2dcd6222d7c7767c715dd",
		},
	}
}

// WriteDefaultConfig writes the default config to a file
func WriteDefaultConfig(path string) error {
	cfg := getDefaultConfig()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// ToTypesEnvironmentConfig converts to the types.EnvironmentConfig
func (e EnvironmentConfig) ToTypesEnvironmentConfig() map[string]string {
	return map[string]string{
		"name":           e.Name,
		"namespace":      e.Namespace,
		"configmap_name": e.ConfigMapName,
		"secret_name":    e.SecretName,
		"kms_endpoint":   e.KMSEndpoint,
		"vault_path":     e.VaultPath,
		"vault_server":   e.VaultServer,
	}
}
