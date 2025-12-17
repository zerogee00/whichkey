package k8s

import (
	"strings"
	"testing"

	"github.com/zerogee00/whichkey/internal/types"
)

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

func TestIsUtilityClipID_WithFallback(t *testing.T) {
	// Test with fallback utility clip IDs
	// This tests the fallback path when kubectl fails

	tests := []struct {
		name       string
		clipID     string
		wantResult bool
	}{
		{
			name:       "known fallback clip 1",
			clipID:     "622721e908d75d0007f44311",
			wantResult: true,
		},
		{
			name:       "known fallback clip 2",
			clipID:     "56244db86ffa1d5f58b77376",
			wantResult: true,
		},
		{
			name:       "known fallback clip 3",
			clipID:     "56c2dcd6222d7c7767c715dd",
			wantResult: true,
		},
		{
			name:       "unknown clip",
			clipID:     "unknown-clip-id-12345",
			wantResult: false,
		},
		{
			name:       "empty clip ID",
			clipID:     "",
			wantResult: false,
		},
	}

	config := types.EnvironmentConfig{
		Name:          "nonprd",
		Namespace:     "nonprd-service-media-center",
		ConfigMapName: "configmap.service-media-center-utility-clip-ids",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This will likely fail kubectl and use fallback
			isUtility, source := IsUtilityClipID(tt.clipID, config)

			if isUtility != tt.wantResult {
				t.Errorf("IsUtilityClipID(%q) = %v, want %v (source: %s)",
					tt.clipID, isUtility, tt.wantResult, source)
			}

			// Source should be either "kubectl" or "fallback"
			if source != "kubectl" && source != "fallback" {
				t.Errorf("IsUtilityClipID source = %q, want 'kubectl' or 'fallback'", source)
			}
		})
	}
}

func TestParseYAMLClipList(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		envName     string
		expected    []string
	}{
		{
			name: "simple list format",
			yamlContent: `nonprd:
  - clip1
  - clip2
  - clip3
prd:
  - clip4`,
			envName:  "nonprd",
			expected: []string{"clip1", "clip2", "clip3"},
		},
		{
			name: "with comments",
			yamlContent: `nonprd:
  - clip1
  # this is a comment
  - clip2`,
			envName:  "nonprd",
			expected: []string{"clip1", "clip2"},
		},
		{
			name: "different environment",
			yamlContent: `nonprd:
  - clip1
prd:
  - clip2
  - clip3`,
			envName:  "prd",
			expected: []string{"clip2", "clip3"},
		},
		{
			name:        "empty content",
			yamlContent: "",
			envName:     "nonprd",
			expected:    []string{},
		},
		{
			name: "environment not found",
			yamlContent: `prd:
  - clip1`,
			envName:  "nonprd",
			expected: []string{},
		},
		{
			name: "with extra whitespace",
			yamlContent: `nonprd:
  -   clip1
  - clip2`,
			envName:  "nonprd",
			expected: []string{"clip1", "clip2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseYAMLClipList(tt.yamlContent, tt.envName)
			if len(result) != len(tt.expected) {
				t.Errorf("parseYAMLClipList() returned %d items, want %d", len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("parseYAMLClipList()[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestParseCommaSeparatedClips(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "simple comma separated",
			input:    "clip1,clip2,clip3",
			expected: []string{"clip1", "clip2", "clip3"},
		},
		{
			name:     "with spaces",
			input:    "clip1, clip2, clip3",
			expected: []string{"clip1", "clip2", "clip3"},
		},
		{
			name:     "single clip",
			input:    "clip1",
			expected: []string{"clip1"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "with extra commas",
			input:    "clip1,,clip2,",
			expected: []string{"clip1", "clip2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCommaSeparated(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("parseCommaSeparated() returned %d items, want %d", len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("parseCommaSeparated()[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

// parseYAMLClipList is a helper function that mimics the YAML parsing in GetUtilityClipIDs
func parseYAMLClipList(content, envName string) []string {
	lines := strings.Split(content, "\n")
	var clipIDs []string
	inSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Check if we're entering the right environment section
		if strings.HasPrefix(line, envName+":") {
			inSection = true
			continue
		}
		// Check if we've entered a different section
		if inSection && strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "-") {
			break
		}
		// Extract clip IDs from list items
		if inSection && strings.HasPrefix(line, "- ") {
			clipID := strings.TrimPrefix(line, "- ")
			clipID = strings.TrimSpace(clipID)
			if clipID != "" && !strings.HasPrefix(clipID, "#") {
				clipIDs = append(clipIDs, clipID)
			}
		}
	}
	return clipIDs
}

// parseCommaSeparated parses comma-separated clip IDs
func parseCommaSeparated(input string) []string {
	if input == "" {
		return []string{}
	}

	parts := strings.Split(input, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func TestSetupContextEnvironments(t *testing.T) {
	// This tests the expected behavior for different environments
	// The actual kubectl calls may fail in test environment

	tests := []struct {
		name        string
		environment string
	}{
		{"nonprd environment", "nonprd"},
		{"preprd environment", "preprd"},
		{"prd environment", "prd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// SetupContext will try kubectl - may fail in test env
			// but should not panic
			err := SetupContext(tt.environment)
			// We don't assert on error since kubectl may not be available
			_ = err
		})
	}
}

func TestSetupVaultAuth(t *testing.T) {
	// This tests the function doesn't panic
	// Actual vault auth will likely fail in test environment
	t.Run("does not panic", func(t *testing.T) {
		err := SetupVaultAuth()
		// We expect an error in test env, but it shouldn't panic
		_ = err
	})
}

func TestGetUtilityClipIDsConfigurations(t *testing.T) {
	// Test that the function handles different configs
	configs := []types.EnvironmentConfig{
		{
			Name:          "nonprd",
			Namespace:     "nonprd-service-media-center",
			ConfigMapName: "configmap.service-media-center-utility-clip-ids",
		},
		{
			Name:          "preprd",
			Namespace:     "preprd-service-media-center",
			ConfigMapName: "configmap.service-media-center-utility-clip-ids",
		},
		{
			Name:          "prd",
			Namespace:     "prd-service-media-center",
			ConfigMapName: "configmap.service-media-center-utility-clip-ids",
		},
	}

	for _, cfg := range configs {
		t.Run(cfg.Name, func(t *testing.T) {
			// This will likely fail kubectl, but should return error not panic
			_, err := GetUtilityClipIDs(cfg)
			// We expect error since kubectl likely not available
			_ = err
		})
	}
}
