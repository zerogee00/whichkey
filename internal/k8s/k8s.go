// Package k8s provides Kubernetes kubectl integration.
package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/roddd/whichkey/internal/config"
	"github.com/roddd/whichkey/internal/types"
)

// Verbosity level for logging
var Verbosity int

// SetupContext tries to set up kubectl context based on environment
func SetupContext(environment string) error {
	// Check if kubectl is available
	if _, err := exec.LookPath("kubectl"); err != nil {
		return fmt.Errorf("kubectl not found in PATH")
	}

	// Try to get current context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "config", "current-context")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get current kubectl context: %w", err)
	}

	currentContext := strings.TrimSpace(string(output))
	if Verbosity >= 1 {
		fmt.Printf("🔧 Current kubectl context: %s\n", currentContext)
	}

	// Check if current context matches the desired environment
	if strings.Contains(currentContext, environment) {
		if Verbosity >= 1 {
			fmt.Printf("✅ Already using correct context for %s environment\n", environment)
		}
		return nil
	}

	// Get possible contexts from config
	cfg := config.GetConfig()
	possibleContexts := cfg.GetKubectlContexts(environment)

	if len(possibleContexts) == 0 {
		return fmt.Errorf("no kubectl contexts configured for environment: %s", environment)
	}

	for _, contextName := range possibleContexts {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "kubectl", "config", "use-context", contextName)
		err := cmd.Run()
		cancel()
		if err == nil {
			fmt.Printf("✅ Switched to kubectl context: %s\n", contextName)
			return nil
		}
	}

	fmt.Printf("⚠️  Could not switch to %s context, using current context: %s\n", environment, currentContext)
	fmt.Printf("   Note: This may cause issues accessing %s resources\n", environment)
	return nil
}

// SetupVaultAuth tries to authenticate with Vault
func SetupVaultAuth() error {
	// Check if vault is available
	if _, err := exec.LookPath("vault"); err != nil {
		return fmt.Errorf("vault CLI not found in PATH")
	}

	// Check if already authenticated with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cmd := exec.CommandContext(ctx, "vault", "token", "lookup")
	err := cmd.Run()
	cancel()
	if err == nil {
		if Verbosity >= 1 {
			fmt.Printf("✅ Already authenticated with Vault\n")
		}
		return nil
	}

	fmt.Printf("🔐 Attempting Vault authentication...\n")

	// Try GitHub token from ~/.vaultToken first
	homeDir, err := os.UserHomeDir()
	if err == nil {
		vaultTokenPath := filepath.Join(homeDir, ".vaultToken")
		if tokenBytes, err := os.ReadFile(vaultTokenPath); err == nil {
			githubToken := strings.TrimSpace(string(tokenBytes))
			if githubToken != "" {
				cmd := exec.Command("vault", "login", "-method=github", "token="+githubToken)
				if err := cmd.Run(); err == nil {
					fmt.Printf("✅ Authenticated with Vault using GitHub\n")
					return nil
				}
			}
		}
	}

	// Try different authentication methods
	authMethods := []struct {
		name string
		cmd  []string
	}{
		{"GitHub", []string{"vault", "login", "-method=github"}},
		{"AWS IAM", []string{"vault", "auth", "-method=aws", "-path=aws"}},
		{"AWS IAM (default)", []string{"vault", "auth", "-method=aws"}},
		{"LDAP", []string{"vault", "auth", "-method=ldap"}},
		{"Userpass", []string{"vault", "auth", "-method=userpass"}},
		{"Token", []string{"vault", "auth", "-method=token"}},
	}

	for _, method := range authMethods {
		cmd = exec.Command(method.cmd[0], method.cmd[1:]...)
		if err := cmd.Run(); err == nil {
			fmt.Printf("✅ Authenticated with Vault using %s\n", method.name)
			return nil
		}
	}

	// Try environment variable authentication
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		cmd = exec.Command("vault", "auth", token)
		if err := cmd.Run(); err == nil {
			fmt.Printf("✅ Authenticated with Vault using VAULT_TOKEN environment variable\n")
			return nil
		}
	}

	return fmt.Errorf("could not authenticate with Vault using any available method")
}

// GetUtilityClipIDs fetches utility clip IDs from the deployed ConfigMap
func GetUtilityClipIDs(envConfig types.EnvironmentConfig) ([]string, error) {
	// Try to get utility-clip-ids.yaml format first (new format)
	cmd := exec.Command("kubectl", "get", "configmap", "config.utility-clip-ids", "-n", envConfig.Namespace, "-o", "jsonpath={.data.utility-clip-ids\\.yaml}")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		// Parse YAML to extract clip IDs for this environment
		var utilityClips map[string][]string
		if err := json.Unmarshal([]byte(output), &utilityClips); err == nil {
			if clips, ok := utilityClips[envConfig.Name]; ok && len(clips) > 0 {
				if Verbosity >= 2 {
					fmt.Printf("✅ Found utility clip IDs in namespace '%s', configmap 'config.utility-clip-ids' (YAML format)\n", envConfig.Namespace)
				}
				return clips, nil
			}
		}
		// Try parsing as YAML if JSON fails
		lines := strings.Split(string(output), "\n")
		var clipIDs []string
		inSection := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// Check if we're entering the right environment section
			if strings.HasPrefix(line, envConfig.Name+":") {
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
		if len(clipIDs) > 0 {
			if Verbosity >= 2 {
				fmt.Printf("✅ Found utility clip IDs in namespace '%s', configmap 'config.utility-clip-ids' (YAML format)\n", envConfig.Namespace)
			}
			return clipIDs, nil
		}
	}

	// Try old format: comma-separated UTILITY_CLIP_IDS
	possibleConfigs := []struct {
		namespace string
		configmap string
	}{
		{envConfig.Namespace, envConfig.ConfigMapName},
		{envConfig.Namespace, "config.utility-clip-ids"},
		{envConfig.Namespace, "config.utility-clip-ids-" + envConfig.Name},
		{"default", "service-media-center-utility-clip-ids"},
		{"pluto", "service-media-center-utility-clip-ids"},
		{"media-center", "service-media-center-utility-clip-ids"},
		{"default", "utility-clip-ids"},
	}

	for _, cfg := range possibleConfigs {
		cmd := exec.Command("kubectl", "get", "configmap", cfg.configmap, "-n", cfg.namespace, "-o", "jsonpath={.data.UTILITY_CLIP_IDS}")
		output, err := cmd.Output()
		if err == nil && len(output) > 0 {
			// Split by comma and clean up
			clipIDs := strings.Split(string(output), ",")
			var cleanIDs []string
			for _, id := range clipIDs {
				cleanID := strings.TrimSpace(id)
				if cleanID != "" {
					cleanIDs = append(cleanIDs, cleanID)
				}
			}
			if Verbosity >= 2 {
				fmt.Printf("✅ Found utility clip IDs in namespace '%s', configmap '%s'\n", cfg.namespace, cfg.configmap)
			}
			return cleanIDs, nil
		}
	}

	return nil, fmt.Errorf("could not find utility clip IDs in any known namespace/configmap")
}

// IsUtilityClipID checks if a clip ID is in the utility clip list
func IsUtilityClipID(clipID string, envConfig types.EnvironmentConfig) (bool, string) {
	// Try to get from kubectl first - use the correct namespace and configmap
	utilityClipIDs, err := GetUtilityClipIDs(envConfig)
	if err != nil {
		// Fallback to config file list if kubectl fails
		if Verbosity >= 1 {
			fmt.Printf("⚠️  Could not fetch utility clip IDs from kubectl: %v\n", err)
			fmt.Printf("   Using fallback method with known utility clips\n")
		}

		// Get fallback utility clips from config
		cfg := config.GetConfig()
		knownUtilityClips := cfg.FallbackUtilityIDs

		for _, utilityID := range knownUtilityClips {
			if utilityID == clipID {
				return true, "fallback"
			}
		}
		return false, "fallback"
	}

	for _, utilityID := range utilityClipIDs {
		if utilityID == clipID {
			return true, "kubectl"
		}
	}

	return false, "kubectl"
}
