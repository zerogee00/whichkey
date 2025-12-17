// Package vault provides Vault and KMS integration for key management.
package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/roddd/whichkey/internal/config"
	"github.com/roddd/whichkey/internal/types"
)

// HTTPClient is the HTTP client used for KMS requests
var HTTPClient *http.Client

// Verbosity level for logging
var Verbosity int

// GetVaultServerURL returns the appropriate Vault server URL based on the environment.
func GetVaultServerURL(env string) string {
	cfg := config.GetConfig()
	if envConfig, exists := cfg.GetEnvironment(env); exists {
		return envConfig.VaultServer
	}
	// Fallback to default environment
	if envConfig, exists := cfg.GetEnvironment(cfg.DefaultEnvironment); exists {
		return envConfig.VaultServer
	}
	return "https://vault-nonprd.devops.pluto.tv"
}

// GetEnvironmentConfig returns configuration for the specified environment
func GetEnvironmentConfig(env string) types.EnvironmentConfig {
	cfg := config.GetConfig()

	envConfig, exists := cfg.GetEnvironment(env)
	if !exists {
		// Fallback to default environment
		envConfig, _ = cfg.GetEnvironment(cfg.DefaultEnvironment)
	}

	// Default vault key if not specified
	vaultKey := envConfig.VaultKey
	if vaultKey == "" {
		vaultKey = "STATIC_ENCRYPTION_KEYS"
	}

	return types.EnvironmentConfig{
		Name:          envConfig.Name,
		Namespace:     envConfig.Namespace,
		ConfigMapName: envConfig.ConfigMapName,
		SecretName:    envConfig.SecretName,
		KMSEndpoint:   envConfig.KMSEndpoint,
		KMSToken:      "", // Will be fetched from secret
		VaultPath:     envConfig.VaultPath,
		VaultServer:   envConfig.VaultServer,
		VaultKey:      vaultKey,
	}
}

// GetKMSTokenFromSecret fetches the KMS token from the Kubernetes secret
func GetKMSTokenFromSecret(envConfig types.EnvironmentConfig) (string, error) {
	cmd := exec.Command("kubectl", "get", "secret", envConfig.SecretName, "-n", envConfig.Namespace, "-o", "jsonpath={.data.KMS_TOKEN}")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get KMS token from secret: %w", err)
	}

	// Decode the base64 token
	decodedToken, err := base64.StdEncoding.DecodeString(string(output))
	if err != nil {
		return "", fmt.Errorf("failed to decode KMS token: %w", err)
	}

	return string(decodedToken), nil
}

// CheckKeyInKMS checks if a key exists in the KMS service
func CheckKeyInKMS(keyID string, envConfig types.EnvironmentConfig) (bool, map[string]interface{}, error) {
	// Get KMS token from secret
	kmsToken, err := GetKMSTokenFromSecret(envConfig)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get KMS token: %w", err)
	}

	kmsURL := fmt.Sprintf("%s/key/%s", envConfig.KMSEndpoint, keyID)

	// Create request with KMS token
	req, err := http.NewRequest("GET", kmsURL, nil)
	if err != nil {
		return false, nil, fmt.Errorf("failed to create KMS request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", "Bearer "+kmsToken)
	req.Header.Set("Content-Type", "application/json")

	// Make the request using HTTP client
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("failed to call KMS service: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	switch resp.StatusCode {
	case http.StatusOK:
		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, nil, fmt.Errorf("failed to read KMS response: %w", err)
		}

		// Parse response
		result := make(map[string]interface{})
		result["raw_response"] = string(body)
		result["status_code"] = resp.StatusCode
		result["kms_url"] = kmsURL

		if Verbosity >= 1 {
			fmt.Printf("✅ Found key in KMS service: %s\n", kmsURL)
		}
		return true, result, nil
	case http.StatusNotFound:
		return false, nil, fmt.Errorf("key not found in KMS service (404)")
	default:
		body, _ := io.ReadAll(resp.Body)
		return false, nil, fmt.Errorf("KMS service error: %d - %s", resp.StatusCode, string(body))
	}
}

// GetDecryptionKeyFromKMS retrieves the actual key material from KMS for decryption
func GetDecryptionKeyFromKMS(keyID string, envConfig types.EnvironmentConfig) (string, string, error) {
	// Get KMS token from secret
	kmsToken, err := GetKMSTokenFromSecret(envConfig)
	if err != nil {
		return "", "", fmt.Errorf("failed to get KMS token: %w", err)
	}

	kmsURL := fmt.Sprintf("%s/key/%s", envConfig.KMSEndpoint, keyID)

	// Create request with KMS token
	req, err := http.NewRequest("GET", kmsURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create KMS request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", "Bearer "+kmsToken)
	req.Header.Set("Content-Type", "application/json")

	// Make the request using HTTP client
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to call KMS service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("KMS service error: %d - %s", resp.StatusCode, string(body))
	}

	// Read and parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read KMS response: %w", err)
	}

	// Parse KMS response structure
	type KMSKey struct {
		KID         string `json:"kid"`
		Key         string `json:"key"`
		IV          string `json:"iv"`
		CreatedAt   string `json:"createdAt"`
		LastUpdated string `json:"lastUpdated"`
	}

	type KMSResponse struct {
		ClipID string   `json:"clipID"`
		Keys   []KMSKey `json:"keys"`
	}

	var kmsResponse KMSResponse
	if err := json.Unmarshal(body, &kmsResponse); err != nil {
		return "", "", fmt.Errorf("failed to parse KMS response: %w", err)
	}

	// Check if we have any keys
	if len(kmsResponse.Keys) == 0 {
		return "", "", fmt.Errorf("no keys found in KMS response")
	}

	// Get the first key (or find matching KID)
	var matchedKey *KMSKey
	normalizedSearchKID := NormalizeKeyID(keyID)

	for i := range kmsResponse.Keys {
		if NormalizeKeyID(kmsResponse.Keys[i].KID) == normalizedSearchKID {
			matchedKey = &kmsResponse.Keys[i]
			break
		}
	}

	// If no exact match, use the first key
	if matchedKey == nil {
		matchedKey = &kmsResponse.Keys[0]
	}

	// Decode base64 key to hex
	keyBytes, err := base64.StdEncoding.DecodeString(matchedKey.Key)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode base64 key: %w", err)
	}

	// Convert to hex string
	keyHex := fmt.Sprintf("%x", keyBytes)

	// Decode base64 IV to hex
	var ivHex string
	if matchedKey.IV != "" {
		ivBytes, err := base64.StdEncoding.DecodeString(matchedKey.IV)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode base64 IV: %w", err)
		}
		ivHex = fmt.Sprintf("%x", ivBytes)
	}

	return keyHex, ivHex, nil
}

// GetKeyInfoFromVault gets detailed key information from Vault
func GetKeyInfoFromVault(keyID string, envConfig types.EnvironmentConfig) (map[string]interface{}, error) {
	// Determine vault key name (default to STATIC_ENCRYPTION_KEYS if not set)
	vaultKey := envConfig.VaultKey
	if vaultKey == "" {
		vaultKey = "STATIC_ENCRYPTION_KEYS"
	}

	// Get the encryption keys from vault using the secret mount
	cmd := exec.Command("vault", "kv", "get", "-format=json", "-mount=secret", envConfig.VaultPath)
	cmd.Env = append(os.Environ(), "VAULT_ADDR="+envConfig.VaultServer)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get vault data: %w", err)
	}

	// Parse JSON response
	var vaultResponse map[string]interface{}
	if err := json.Unmarshal(output, &vaultResponse); err != nil {
		return nil, fmt.Errorf("failed to parse vault response: %w", err)
	}

	// Extract data.data.<vault_key>
	data, ok := vaultResponse["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid vault response structure: missing data")
	}

	dataData, ok := data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid vault response structure: missing data.data")
	}

	// Vault key can be either a string (JSON) or already parsed array
	var staticKeys []map[string]interface{}
	staticKeysRaw, ok := dataData[vaultKey]
	if !ok {
		return nil, fmt.Errorf("%s not found in vault", vaultKey)
	}

	// Check if it's a string that needs parsing or already an array
	switch v := staticKeysRaw.(type) {
	case string:
		// It's a JSON string, parse it
		if err := json.Unmarshal([]byte(v), &staticKeys); err != nil {
			return nil, fmt.Errorf("failed to parse %s string: %w", vaultKey, err)
		}
	case []interface{}:
		// It's already an array, convert it
		for _, item := range v {
			if keyMap, ok := item.(map[string]interface{}); ok {
				staticKeys = append(staticKeys, keyMap)
			}
		}
	default:
		return nil, fmt.Errorf("%s has unexpected type: %T", vaultKey, v)
	}

	// Normalize the search key ID (remove dashes)
	normalizedSearchKeyID := NormalizeKeyID(keyID)

	// Find the key with matching key_id
	for _, key := range staticKeys {
		if keyIDVal, ok := key["key_id"].(string); ok {
			// Normalize both key IDs for comparison
			if NormalizeKeyID(keyIDVal) == normalizedSearchKeyID {
				// Found the key, return it with vault path info
				key["vault_path"] = envConfig.VaultPath
				return key, nil
			}
		}
	}

	return nil, fmt.Errorf("key %s not found in %s", keyID, vaultKey)
}

// NormalizeKeyID normalizes a key ID by removing dashes and converting to lowercase
func NormalizeKeyID(keyID string) string {
	return strings.ToLower(strings.ReplaceAll(keyID, "-", ""))
}

// SetupAuth tries to authenticate with Vault
func SetupAuth() error {
	// Check if vault is available
	if _, err := exec.LookPath("vault"); err != nil {
		return fmt.Errorf("vault not found in PATH")
	}

	// Check if already authenticated by trying to list
	cmd := exec.Command("vault", "token", "lookup")
	if err := cmd.Run(); err == nil {
		// Already authenticated
		return nil
	}

	// Try to auth using default method (ldap)
	cmd = exec.Command("vault", "login", "-method=ldap")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("vault authentication failed: %w", err)
	}

	return nil
}
