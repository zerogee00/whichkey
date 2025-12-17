package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGetDefaultConfig(t *testing.T) {
	cfg := getDefaultConfig()

	if cfg.DefaultEnvironment != "nonprd" {
		t.Errorf("expected default environment 'nonprd', got %q", cfg.DefaultEnvironment)
	}

	if len(cfg.Environments) != 3 {
		t.Errorf("expected 3 environments, got %d", len(cfg.Environments))
	}

	// Check nonprd environment
	nonprd, exists := cfg.Environments["nonprd"]
	if !exists {
		t.Fatal("expected 'nonprd' environment to exist")
	}
	if nonprd.Name != "nonprd" {
		t.Errorf("expected nonprd name 'nonprd', got %q", nonprd.Name)
	}
	if nonprd.VaultKey != "STATIC_ENCRYPTION_KEYS" {
		t.Errorf("expected vault_key 'STATIC_ENCRYPTION_KEYS', got %q", nonprd.VaultKey)
	}
}

func TestGetEnvironment(t *testing.T) {
	cfg := getDefaultConfig()

	tests := []struct {
		name     string
		input    string
		expected string
		exists   bool
	}{
		{"direct match nonprd", "nonprd", "nonprd", true},
		{"direct match preprd", "preprd", "preprd", true},
		{"direct match prd", "prd", "prd", true},
		{"alias dev", "dev", "nonprd", true},
		{"alias development", "development", "nonprd", true},
		{"alias prod", "prod", "prd", true},
		{"alias production", "production", "prd", true},
		{"alias preprod", "preprod", "preprd", true},
		{"case insensitive", "NONPRD", "nonprd", true},
		{"unknown environment", "unknown", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, exists := cfg.GetEnvironment(tt.input)
			if exists != tt.exists {
				t.Errorf("GetEnvironment(%q) exists = %v, want %v", tt.input, exists, tt.exists)
			}
			if exists && env.Name != tt.expected {
				t.Errorf("GetEnvironment(%q) name = %q, want %q", tt.input, env.Name, tt.expected)
			}
		})
	}
}

func TestGetAWSProfile(t *testing.T) {
	cfg := getDefaultConfig()

	tests := []struct {
		name     string
		bucket   string
		expected string
	}{
		{"slio bucket", "slio-media-bucket", "main-tier4"},
		{"nonprd bucket", "nonprd-hybrik-output", "nonprod-tier3"},
		{"dev bucket", "dev-media-bucket", "nonprod-tier3"},
		{"preprd bucket", "preprd-hybrik-output", "preprod-tier3"},
		{"prd bucket", "prd-hybrik-output", "main-tier4"},
		{"unknown bucket", "random-bucket", ""},
		{"case insensitive", "NONPRD-BUCKET", "nonprod-tier3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := cfg.GetAWSProfile(tt.bucket)
			if profile != tt.expected {
				t.Errorf("GetAWSProfile(%q) = %q, want %q", tt.bucket, profile, tt.expected)
			}
		})
	}
}

func TestGetKubectlContexts(t *testing.T) {
	cfg := getDefaultConfig()

	tests := []struct {
		name        string
		env         string
		minContexts int
	}{
		{"nonprd contexts", "nonprd", 3},
		{"preprd contexts", "preprd", 3},
		{"prd contexts", "prd", 7},
		{"unknown env", "unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contexts := cfg.GetKubectlContexts(tt.env)
			if len(contexts) < tt.minContexts {
				t.Errorf("GetKubectlContexts(%q) returned %d contexts, want at least %d",
					tt.env, len(contexts), tt.minContexts)
			}
		})
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.json")

	testConfig := &Config{
		DefaultEnvironment: "test",
		Environments: map[string]EnvironmentConfig{
			"test": {
				Name:        "test",
				Namespace:   "test-namespace",
				VaultServer: "https://test-vault.example.com",
				VaultKey:    "TEST_KEYS",
			},
		},
		AWSProfiles: AWSProfileConfig{
			BucketPatterns: map[string]string{
				"test": "test-profile",
			},
		},
	}

	data, err := json.MarshalIndent(testConfig, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal test config: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	// Reset global config
	globalConfig = nil

	// Load the config
	cfg, err := LoadConfigFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFromFile() error = %v", err)
	}

	if cfg.DefaultEnvironment != "test" {
		t.Errorf("expected default environment 'test', got %q", cfg.DefaultEnvironment)
	}

	env, exists := cfg.GetEnvironment("test")
	if !exists {
		t.Fatal("expected 'test' environment to exist")
	}
	if env.VaultKey != "TEST_KEYS" {
		t.Errorf("expected vault_key 'TEST_KEYS', got %q", env.VaultKey)
	}

	// Reset global config for other tests
	globalConfig = nil
}

func TestWriteDefaultConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "output-config.json")

	err := WriteDefaultConfig(configPath)
	if err != nil {
		t.Fatalf("WriteDefaultConfig() error = %v", err)
	}

	// Verify the file was created and is valid JSON
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read output config: %v", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("output config is not valid JSON: %v", err)
	}

	if cfg.DefaultEnvironment != "nonprd" {
		t.Errorf("expected default environment 'nonprd', got %q", cfg.DefaultEnvironment)
	}
}

func TestLoadConfigCaching(t *testing.T) {
	// Reset global config
	globalConfig = nil

	// First call should load defaults
	cfg1, _ := LoadConfig()

	// Second call should return cached config
	cfg2, _ := LoadConfig()

	// Should be the same instance
	if cfg1 != cfg2 {
		t.Error("expected LoadConfig to return cached config")
	}

	// Reset for other tests
	globalConfig = nil
}
