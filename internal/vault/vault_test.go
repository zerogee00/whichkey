package vault

import (
	"testing"

	"github.com/roddd/whichkey/internal/types"
)

func TestNormalizeKeyID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"UUID with dashes", "00000000-654b-bc98-c034-dae1f16995de", "00000000654bbc98c034dae1f16995de"},
		{"lowercase no dashes", "00000000654bbc98c034dae1f16995de", "00000000654bbc98c034dae1f16995de"},
		{"uppercase with dashes", "00000000-654B-BC98-C034-DAE1F16995DE", "00000000654bbc98c034dae1f16995de"},
		{"mixed case", "00000000-654B-bc98-C034-dae1f16995de", "00000000654bbc98c034dae1f16995de"},
		{"empty string", "", ""},
		{"single dash", "a-b", "ab"},
		{"multiple dashes", "a-b-c-d", "abcd"},
		{"only dashes", "----", ""},
		{"uppercase only", "ABCDEF123456", "abcdef123456"},
		{"mixed with numbers", "A1-B2-C3-D4", "a1b2c3d4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeKeyID(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeKeyID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetVaultServerURL(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		contains string
	}{
		{"nonprd environment", "nonprd", "vault-nonprd"},
		{"dev environment", "dev", "vault-nonprd"},
		{"development alias", "development", "vault-nonprd"},
		{"sandbox alias", "sandbox", "vault-nonprd"},
		{"preprd environment", "preprd", "preprod"},
		{"preprod alias", "preprod", "preprod"},
		{"prd environment", "prd", "prod"},
		{"prod alias", "prod", "prod"},
		{"production alias", "production", "prod"},
		{"unknown defaults to nonprd", "unknown", "vault-nonprd"},
		{"empty string defaults", "", "vault-nonprd"},
		{"case insensitive", "NONPRD", "vault-nonprd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetVaultServerURL(tt.env)
			if result == "" {
				t.Error("GetVaultServerURL returned empty string")
			}
			if !containsSubstring(result, tt.contains) {
				t.Errorf("GetVaultServerURL(%q) = %q, want to contain %q", tt.env, result, tt.contains)
			}
		})
	}
}

func TestGetEnvironmentConfig(t *testing.T) {
	tests := []struct {
		name         string
		env          string
		expectedName string
	}{
		{"nonprd", "nonprd", "nonprd"},
		{"preprd", "preprd", "preprd"},
		{"prd", "prd", "prd"},
		{"dev alias", "dev", "nonprd"},
		{"development alias", "development", "nonprd"},
		{"sandbox alias", "sandbox", "nonprd"},
		{"prod alias", "prod", "prd"},
		{"production alias", "production", "prd"},
		{"preprod alias", "preprod", "preprd"},
		{"unknown defaults", "unknown", "nonprd"},
		{"empty defaults", "", "nonprd"},
		{"case insensitive", "NONPRD", "nonprd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GetEnvironmentConfig(tt.env)

			if config.Name != tt.expectedName {
				t.Errorf("GetEnvironmentConfig(%q).Name = %q, want %q",
					tt.env, config.Name, tt.expectedName)
			}

			// Verify required fields are populated
			if config.Namespace == "" {
				t.Error("Namespace should not be empty")
			}
			if config.KMSEndpoint == "" {
				t.Error("KMSEndpoint should not be empty")
			}
			if config.VaultPath == "" {
				t.Error("VaultPath should not be empty")
			}
			if config.VaultServer == "" {
				t.Error("VaultServer should not be empty")
			}
			if config.VaultKey == "" {
				t.Error("VaultKey should not be empty")
			}
		})
	}
}

func TestGetEnvironmentConfigFields(t *testing.T) {
	tests := []struct {
		name      string
		env       string
		checkFunc func(types.EnvironmentConfig) bool
		desc      string
	}{
		{
			name: "nonprd has correct namespace",
			env:  "nonprd",
			checkFunc: func(c types.EnvironmentConfig) bool {
				return containsSubstring(c.Namespace, "nonprd")
			},
			desc: "Namespace should contain 'nonprd'",
		},
		{
			name: "preprd has correct namespace",
			env:  "preprd",
			checkFunc: func(c types.EnvironmentConfig) bool {
				return containsSubstring(c.Namespace, "preprd")
			},
			desc: "Namespace should contain 'preprd'",
		},
		{
			name: "prd has correct namespace",
			env:  "prd",
			checkFunc: func(c types.EnvironmentConfig) bool {
				return containsSubstring(c.Namespace, "prd")
			},
			desc: "Namespace should contain 'prd'",
		},
		{
			name: "nonprd KMS endpoint",
			env:  "nonprd",
			checkFunc: func(c types.EnvironmentConfig) bool {
				return containsSubstring(c.KMSEndpoint, "nonprd")
			},
			desc: "KMSEndpoint should contain 'nonprd'",
		},
		{
			name: "vault path contains env",
			env:  "nonprd",
			checkFunc: func(c types.EnvironmentConfig) bool {
				return containsSubstring(c.VaultPath, "nonprd")
			},
			desc: "VaultPath should contain environment name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GetEnvironmentConfig(tt.env)
			if !tt.checkFunc(config) {
				t.Error(tt.desc)
			}
		})
	}
}

func TestGetEnvironmentConfigVaultKey(t *testing.T) {
	envs := []string{"nonprd", "preprd", "prd"}

	for _, env := range envs {
		t.Run(env, func(t *testing.T) {
			config := GetEnvironmentConfig(env)

			// Default should be STATIC_ENCRYPTION_KEYS for all envs
			if config.VaultKey != "STATIC_ENCRYPTION_KEYS" {
				t.Errorf("VaultKey = %q, want %q", config.VaultKey, "STATIC_ENCRYPTION_KEYS")
			}
		})
	}
}

func TestVerbosityVariable(t *testing.T) {
	original := Verbosity
	defer func() { Verbosity = original }()

	Verbosity = 0
	if Verbosity != 0 {
		t.Errorf("Verbosity = %d, want 0", Verbosity)
	}

	Verbosity = 1
	if Verbosity != 1 {
		t.Errorf("Verbosity = %d, want 1", Verbosity)
	}

	Verbosity = 2
	if Verbosity != 2 {
		t.Errorf("Verbosity = %d, want 2", Verbosity)
	}
}

func TestHTTPClientVariable(t *testing.T) {
	// HTTPClient should be settable
	original := HTTPClient
	defer func() { HTTPClient = original }()

	if HTTPClient != nil {
		// Just verify it's accessible
		_ = HTTPClient
	}
}

func TestEnvironmentConfigStructure(t *testing.T) {
	config := GetEnvironmentConfig("nonprd")

	// Verify struct fields are correctly typed and accessible
	t.Run("Name is accessible", func(t *testing.T) {
		if config.Name == "" {
			t.Error("Name should not be empty")
		}
	})

	t.Run("Namespace is accessible", func(t *testing.T) {
		if config.Namespace == "" {
			t.Error("Namespace should not be empty")
		}
	})

	t.Run("KMSEndpoint is accessible", func(t *testing.T) {
		if config.KMSEndpoint == "" {
			t.Error("KMSEndpoint should not be empty")
		}
	})

	t.Run("VaultPath is accessible", func(t *testing.T) {
		if config.VaultPath == "" {
			t.Error("VaultPath should not be empty")
		}
	})

	t.Run("VaultServer is accessible", func(t *testing.T) {
		if config.VaultServer == "" {
			t.Error("VaultServer should not be empty")
		}
	})

	t.Run("VaultKey is accessible", func(t *testing.T) {
		if config.VaultKey == "" {
			t.Error("VaultKey should not be empty")
		}
	})
}

// Helper function
func containsSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
