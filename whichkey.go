package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Global verbosity level
var globalVerbosity int

// Global flag to include subclips
var globalIncludeSubclips bool

// Global flag for markdown output
var globalMarkdownOutput bool

// Global variable for the manifest path (for markdown output)
var globalManifestPath string

// copyToClipboard copies text to the system clipboard (macOS)
func copyToClipboard(text string) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

// Global HTTP client with connection pooling for concurrent requests
var globalHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     90 * time.Second,
	},
}

// Global S3 client (initialized on first use)
var (
	globalS3Client *s3.Client
	s3ClientOnce   sync.Once
	s3ClientErr    error
)

// Spinner provides a simple progress indicator
type Spinner struct {
	frames  []string
	message string
	stop    chan bool
	done    chan bool
	mu      sync.Mutex
}

// NewSpinner creates a new spinner with a message
func NewSpinner(message string) *Spinner {
	return &Spinner{
		frames:  []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		message: message,
		stop:    make(chan bool),
		done:    make(chan bool),
	}
}

// Start begins the spinner animation
func (s *Spinner) Start() {
	go func() {
		i := 0
		for {
			select {
			case <-s.stop:
				// Clear the spinner line
				fmt.Printf("\r%s\r", strings.Repeat(" ", len(s.message)+5))
				s.done <- true
				return
			default:
				s.mu.Lock()
				fmt.Printf("\r%s %s", s.frames[i%len(s.frames)], s.message)
				s.mu.Unlock()
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

// Stop halts the spinner
func (s *Spinner) Stop() {
	s.stop <- true
	<-s.done
}

// Update changes the spinner message
func (s *Spinner) Update(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Clear old message
	fmt.Printf("\r%s\r", strings.Repeat(" ", len(s.message)+5))
	s.message = message
}

// normalizeKeyID removes dashes from a key ID for comparison
func normalizeKeyID(keyID string) string {
	return strings.ReplaceAll(keyID, "-", "")
}

// isSubclipPath checks if a path is a subclip folder (not 0-end)
// Subclip folders are like: 0-10/, 10-20/, 30-end/, etc.
func isSubclipPath(path string) bool {
	// Pattern matches: /digits-digits/ or /digits-end/ but NOT /0-end/
	subclipRegex := regexp.MustCompile(`/(\d+)-(\d+|end)/`)
	matches := subclipRegex.FindStringSubmatch(path)
	if len(matches) > 1 {
		// It's a subclip if the start isn't 0 or the end isn't "end"
		start := matches[1]
		end := matches[2]
		// 0-end is the full clip, anything else is a subclip
		if start == "0" && end == "end" {
			return false
		}
		return true
	}
	return false
}

// extractClipIDFromPath extracts clip ID from various path formats
func extractClipIDFromPath(manifestPath string) string {
	// Try multiple patterns to extract clip ID

	// Pattern 1: .../clip/CLIP_ID_description/...
	if strings.Contains(manifestPath, "/clip/") {
		parts := strings.Split(manifestPath, "/clip/")
		if len(parts) > 1 {
			clipPart := parts[1]
			clipIDParts := strings.Split(clipPart, "/")
			if len(clipIDParts) > 0 {
				fullClipID := clipIDParts[0]
				if strings.Contains(fullClipID, "_") {
					return strings.Split(fullClipID, "_")[0]
				}
				return fullClipID
			}
		}
	}

	// Pattern 2: Extract from path segment before /dash/ or /hls/
	// e.g., s3://bucket/path/CLIP_ID/dash/0-end/main.mpd
	for _, marker := range []string{"/dash/", "/hls/"} {
		if idx := strings.Index(manifestPath, marker); idx > 0 {
			// Get the path before the marker
			pathBefore := manifestPath[:idx]
			// Find the last path segment
			lastSlash := strings.LastIndex(pathBefore, "/")
			if lastSlash >= 0 && lastSlash < len(pathBefore)-1 {
				clipSegment := pathBefore[lastSlash+1:]
				// Clean up: remove common suffixes/prefixes, extract ID part
				if strings.Contains(clipSegment, "_") {
					return strings.Split(clipSegment, "_")[0]
				}
				if len(clipSegment) > 0 {
					return clipSegment
				}
			}
		}
	}

	// Pattern 3: Look for common clip ID patterns (24-25 char hex string)
	clipIDRegex := regexp.MustCompile(`/([a-f0-9]{24,25})[/_]`)
	if matches := clipIDRegex.FindStringSubmatch(manifestPath); len(matches) > 1 {
		return matches[1]
	}

	// Pattern 4: Look for UUID pattern in path
	uuidRegex := regexp.MustCompile(`/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})[/_]`)
	if matches := uuidRegex.FindStringSubmatch(manifestPath); len(matches) > 1 {
		return matches[1]
	}

	return "unknown"
}

// isURL checks if the given path is a URL
func isURL(path string) bool {
	return strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://")
}

// isS3URL checks if the given path is an S3 URL
func isS3URL(path string) bool {
	return strings.HasPrefix(path, "s3://")
}

// fetchURLContent fetches content from a URL and returns a reader
func fetchURLContent(url string) (io.Reader, error) {
	resp, err := globalHTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	return resp.Body, nil
}

// parseS3URL parses an S3 URL into bucket and key
func parseS3URL(s3URL string) (bucket, key string, err error) {
	if !strings.HasPrefix(s3URL, "s3://") {
		return "", "", fmt.Errorf("invalid S3 URL format: %s", s3URL)
	}

	// Remove s3:// prefix
	path := strings.TrimPrefix(s3URL, "s3://")

	// Split into bucket and key
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid S3 URL format: must be s3://bucket/key")
	}

	return parts[0], parts[1], nil
}

// Global AWS profile override (set via flag)
var awsProfileOverride string

// getAWSProfileForBucket determines the appropriate AWS profile based on bucket name
func getAWSProfileForBucket(bucket string) string {
	bucketLower := strings.ToLower(bucket)

	// Check for slio buckets first (use main-tier4)
	if strings.Contains(bucketLower, "slio") {
		return "main-tier4"
	}

	// Check for environment-specific buckets
	if strings.Contains(bucketLower, "nonprd") || strings.Contains(bucketLower, "dev") {
		return "nonprod-tier3"
	}
	if strings.Contains(bucketLower, "preprd") {
		return "preprod-tier3"
	}
	// Check for prd (but make sure it's not preprd or nonprd which we already handled)
	if strings.Contains(bucketLower, "prd") {
		return "main-tier4"
	}

	// Default - no automatic profile
	return ""
}

// autoSetAWSProfile sets the AWS profile based on the S3 URL if not already set
func autoSetAWSProfile(s3URL string) {
	// Don't override if user explicitly specified a profile via flag
	if awsProfileOverride != "" {
		return
	}

	// Parse bucket from URL
	bucket, _, err := parseS3URL(s3URL)
	if err != nil {
		return
	}

	// Get appropriate profile for this bucket
	profile := getAWSProfileForBucket(bucket)
	if profile != "" {
		if globalVerbosity >= 1 {
			fmt.Printf("🔐 Auto-detected AWS profile: %s (based on bucket: %s)\n", profile, bucket)
		}
		// Set the global override so getAWSConfig uses it
		awsProfileOverride = profile
		// Also set env var for any subprocesses
		os.Setenv("AWS_PROFILE", profile)
		// Reset the S3 client so it picks up the new profile
		s3ClientOnce = sync.Once{}
		globalS3Client = nil
		s3ClientErr = nil
	}
}

// getS3Client returns a shared S3 client (initialized once)
func getS3Client() (*s3.Client, error) {
	s3ClientOnce.Do(func() {
		cfg, err := getAWSConfig()
		if err != nil {
			s3ClientErr = err
			return
		}
		// Create S3 client with custom HTTP client for higher concurrency
		globalS3Client = s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.HTTPClient = globalHTTPClient
		})
	})
	return globalS3Client, s3ClientErr
}

// getAWSConfig loads AWS configuration respecting AWS_PROFILE and with shorter timeouts
func getAWSConfig() (aws.Config, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Load config with options to handle profiles correctly
	opts := []func(*config.LoadOptions) error{
		config.WithRegion("us-east-1"), // Default region
		config.WithSharedConfigFiles([]string{
			filepath.Join(os.Getenv("HOME"), ".aws", "config"),
		}),
		config.WithSharedCredentialsFiles([]string{
			filepath.Join(os.Getenv("HOME"), ".aws", "credentials"),
		}),
	}

	// Determine profile to use (flag override > env var)
	profile := awsProfileOverride
	if profile == "" {
		profile = os.Getenv("AWS_PROFILE")
	}
	if profile == "" {
		profile = os.Getenv("AWS_DEFAULT_PROFILE")
	}

	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
		if globalVerbosity >= 2 {
			fmt.Printf("🔐 Using AWS profile: %s\n", profile)
		}
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return cfg, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return cfg, nil
}

// fetchS3Content fetches content from an S3 URL using AWS SDK
func fetchS3Content(s3URL string) (io.Reader, error) {
	// Parse S3 URL
	bucket, key, err := parseS3URL(s3URL)
	if err != nil {
		return nil, err
	}

	// Get shared S3 client
	client, err := getS3Client()
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 client: %w (make sure AWS credentials are configured)", err)
	}

	ctx := context.Background()

	// Get object from S3
	result, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch S3 object s3://%s/%s: %w", bucket, key, err)
	}
	defer result.Body.Close()

	// Read the entire body into memory
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, result.Body); err != nil {
		return nil, fmt.Errorf("failed to read S3 object body: %w", err)
	}

	return bytes.NewReader(buf.Bytes()), nil
}

// setupKubectlContext tries to set up kubectl context based on environment
func setupKubectlContext(environment string) error {
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
	if globalVerbosity >= 1 {
		fmt.Printf("🔧 Current kubectl context: %s\n", currentContext)
	}

	// Check if current context matches the desired environment
	if strings.Contains(currentContext, environment) {
		if globalVerbosity >= 1 {
			fmt.Printf("✅ Already using correct context for %s environment\n", environment)
		}
		return nil
	}

	// Try to switch to the appropriate context for the environment
	var possibleContexts []string
	switch environment {
	case "preprd":
		possibleContexts = []string{
			"preprd",
			"pluto-preprd",
			"aws-preprd",
		}
	case "nonprd":
		possibleContexts = []string{
			"nonprd",
			"pluto-nonprd",
			"aws-nonprd",
		}
	case "prd":
		possibleContexts = []string{
			"prd",
			"pluto-prd",
			"pluto-prod",
			"production",
			"prod",
			"aws-prd",
			"aws-prod",
		}
	default:
		return fmt.Errorf("unknown environment: %s", environment)
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

// setupVaultAuth tries to authenticate with Vault
func setupVaultAuth() error {
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
		if globalVerbosity >= 1 {
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

// getUtilityClipIDsFromKubectl fetches utility clip IDs from the deployed ConfigMap
func getUtilityClipIDsFromKubectl(config EnvironmentConfig) ([]string, error) {
	// Try to get utility-clip-ids.yaml format first (new format)
	cmd := exec.Command("kubectl", "get", "configmap", "config.utility-clip-ids", "-n", config.Namespace, "-o", "jsonpath={.data.utility-clip-ids\\.yaml}")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		// Parse YAML to extract clip IDs for this environment
		var utilityClips map[string][]string
		if err := json.Unmarshal([]byte(output), &utilityClips); err == nil {
			if clips, ok := utilityClips[config.Name]; ok && len(clips) > 0 {
				if globalVerbosity >= 2 {
					fmt.Printf("✅ Found utility clip IDs in namespace '%s', configmap 'config.utility-clip-ids' (YAML format)\n", config.Namespace)
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
			if strings.HasPrefix(line, config.Name+":") {
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
			if globalVerbosity >= 2 {
				fmt.Printf("✅ Found utility clip IDs in namespace '%s', configmap 'config.utility-clip-ids' (YAML format)\n", config.Namespace)
			}
			return clipIDs, nil
		}
	}

	// Try old format: comma-separated UTILITY_CLIP_IDS
	possibleConfigs := []struct {
		namespace string
		configmap string
	}{
		{config.Namespace, config.ConfigMapName},
		{config.Namespace, "config.utility-clip-ids"},
		{config.Namespace, "config.utility-clip-ids-" + config.Name},
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
			if globalVerbosity >= 2 {
				fmt.Printf("✅ Found utility clip IDs in namespace '%s', configmap '%s'\n", cfg.namespace, cfg.configmap)
			}
			return cleanIDs, nil
		}
	}

	return nil, fmt.Errorf("could not find utility clip IDs in any known namespace/configmap")
}

// isUtilityClipID checks if a clip ID is in the utility clip list
func isUtilityClipID(clipID string, config EnvironmentConfig) (bool, string) {
	// Try to get from kubectl first - use the correct namespace and configmap
	utilityClipIDs, err := getUtilityClipIDsFromKubectl(config)
	if err != nil {
		// Fallback to hardcoded list if kubectl fails
		if globalVerbosity >= 1 {
			fmt.Printf("⚠️  Could not fetch utility clip IDs from kubectl: %v\n", err)
			fmt.Printf("   Using fallback method with known utility clips\n")
		}

		// Known utility clips (from the config file)
		knownUtilityClips := []string{
			"622721e908d75d0007f44311", // The clip we're testing
			"56244db86ffa1d5f58b77376",
			"56c2dcd6222d7c7767c715dd",
			// Add more as needed
		}

		for _, utilityID := range knownUtilityClips {
			if utilityID == clipID {
				return true, "hardcoded"
			}
		}

		// Final fallback to 25-character heuristic
		return len(clipID) == 25, "heuristic"
	}

	// Check if clipID is in the list
	for _, utilityID := range utilityClipIDs {
		if utilityID == clipID {
			return true, "kubectl"
		}
	}
	return false, "kubectl"
}

// EnvironmentConfig holds environment-specific configuration
type EnvironmentConfig struct {
	Name          string
	Namespace     string
	ConfigMapName string
	SecretName    string
	KMSEndpoint   string
	KMSToken      string
	VaultPath     string
	VaultServer   string
}

// getVaultServerURL returns the appropriate Vault server URL based on the environment.
func getVaultServerURL(env string) string {
	switch strings.ToLower(env) {
	case "dev", "development", "nonprd", "sandbox", "sbox":
		return "https://vault-nonprd.devops.pluto.tv"
	case "preprd", "preprod":
		return "https://vault-ent-preprod.devops.pluto.tv:8200"
	case "prd", "prod", "production":
		return "https://vault-ent-prod.devops.pluto.tv:8200"
	default:
		return "https://vault-nonprd.devops.pluto.tv"
	}
}

// getEnvironmentConfig returns configuration for the specified environment
func getEnvironmentConfig(env string) EnvironmentConfig {
	configs := map[string]EnvironmentConfig{
		"preprd": {
			Name:          "preprd",
			Namespace:     "preprd-service-media-center",
			ConfigMapName: "configmap.service-media-center-utility-clip-ids",
			SecretName:    "secret.service-media-center",
			KMSEndpoint:   "https://service-video-kms-use1-1.preprd.pluto.tv/v1",
			KMSToken:      "", // Will be fetched from secret
			VaultPath:     "app/common/shared-encryption/preprd",
			VaultServer:   getVaultServerURL("preprd"),
		},
		"nonprd": {
			Name:          "nonprd",
			Namespace:     "nonprd-service-media-center",
			ConfigMapName: "configmap.service-media-center-utility-clip-ids",
			SecretName:    "secret.service-media-center",
			KMSEndpoint:   "https://service-video-kms-use1-1.nonprd.pluto.tv/v1",
			KMSToken:      "", // Will be fetched from secret
			VaultPath:     "app/common/shared-encryption/nonprd",
			VaultServer:   getVaultServerURL("nonprd"),
		},
		"prd": {
			Name:          "prd",
			Namespace:     "prd-service-media-center",
			ConfigMapName: "configmap.service-media-center-utility-clip-ids",
			SecretName:    "secret.service-media-center",
			KMSEndpoint:   "https://service-video-kms-use1-1.prd.pluto.tv/v1",
			KMSToken:      "", // Will be fetched from secret
			VaultPath:     "app/common/shared-encryption/prd",
			VaultServer:   getVaultServerURL("prd"),
		},
	}

	if config, exists := configs[env]; exists {
		return config
	}

	// Default to nonprd if environment not found
	return configs["nonprd"]
}

// getKMSTokenFromSecret fetches the KMS token from the Kubernetes secret
func getKMSTokenFromSecret(config EnvironmentConfig) (string, error) {
	cmd := exec.Command("kubectl", "get", "secret", config.SecretName, "-n", config.Namespace, "-o", "jsonpath={.data.KMS_TOKEN}")
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

// checkKeyInKMS checks if a key exists in the KMS service
func checkKeyInKMS(keyID string, config EnvironmentConfig) (bool, map[string]interface{}, error) {
	// Get KMS token from secret
	kmsToken, err := getKMSTokenFromSecret(config)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get KMS token: %w", err)
	}

	kmsURL := fmt.Sprintf("%s/key/%s", config.KMSEndpoint, keyID)

	// Create request with KMS token
	req, err := http.NewRequest("GET", kmsURL, nil)
	if err != nil {
		return false, nil, fmt.Errorf("failed to create KMS request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", "Bearer "+kmsToken)
	req.Header.Set("Content-Type", "application/json")

	// Make the request using global HTTP client
	resp, err := globalHTTPClient.Do(req)
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

		// Parse response (simplified - in production you'd use proper JSON parsing)
		result := make(map[string]interface{})
		result["raw_response"] = string(body)
		result["status_code"] = resp.StatusCode
		result["kms_url"] = kmsURL

		if globalVerbosity >= 1 {
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

// getDecryptionKeyFromKMS retrieves the actual key material from KMS for decryption
func getDecryptionKeyFromKMS(keyID string, config EnvironmentConfig) (string, string, error) {
	// Get KMS token from secret
	kmsToken, err := getKMSTokenFromSecret(config)
	if err != nil {
		return "", "", fmt.Errorf("failed to get KMS token: %w", err)
	}

	kmsURL := fmt.Sprintf("%s/key/%s", config.KMSEndpoint, keyID)

	// Create request with KMS token
	req, err := http.NewRequest("GET", kmsURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create KMS request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", "Bearer "+kmsToken)
	req.Header.Set("Content-Type", "application/json")

	// Make the request using global HTTP client
	resp, err := globalHTTPClient.Do(req)
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
	normalizedSearchKID := normalizeKeyID(keyID)

	for i := range kmsResponse.Keys {
		if normalizeKeyID(kmsResponse.Keys[i].KID) == normalizedSearchKID {
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

// getKeyInfoFromVault gets detailed key information from Vault
func getKeyInfoFromVault(keyID string, config EnvironmentConfig) (map[string]interface{}, error) {
	// Get the STATIC_ENCRYPTION_KEYS from vault using the secret mount
	cmd := exec.Command("vault", "kv", "get", "-format=json", "-mount=secret", config.VaultPath)
	cmd.Env = append(os.Environ(), "VAULT_ADDR="+config.VaultServer)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get vault data: %w", err)
	}

	// Parse JSON response
	var vaultResponse map[string]interface{}
	if err := json.Unmarshal(output, &vaultResponse); err != nil {
		return nil, fmt.Errorf("failed to parse vault response: %w", err)
	}

	// Extract data.data.STATIC_ENCRYPTION_KEYS
	data, ok := vaultResponse["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid vault response structure: missing data")
	}

	dataData, ok := data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid vault response structure: missing data.data")
	}

	// STATIC_ENCRYPTION_KEYS can be either a string (JSON) or already parsed array
	var staticKeys []map[string]interface{}
	staticKeysRaw, ok := dataData["STATIC_ENCRYPTION_KEYS"]
	if !ok {
		return nil, fmt.Errorf("STATIC_ENCRYPTION_KEYS not found in vault")
	}

	// Check if it's a string that needs parsing or already an array
	switch v := staticKeysRaw.(type) {
	case string:
		// It's a JSON string, parse it
		if err := json.Unmarshal([]byte(v), &staticKeys); err != nil {
			return nil, fmt.Errorf("failed to parse STATIC_ENCRYPTION_KEYS string: %w", err)
		}
	case []interface{}:
		// It's already an array, convert it
		for _, item := range v {
			if keyMap, ok := item.(map[string]interface{}); ok {
				staticKeys = append(staticKeys, keyMap)
			}
		}
	default:
		return nil, fmt.Errorf("STATIC_ENCRYPTION_KEYS has unexpected type: %T", v)
	}

	// Normalize the search key ID (remove dashes)
	normalizedSearchKeyID := normalizeKeyID(keyID)

	// Find the key with matching key_id
	for _, key := range staticKeys {
		if keyIDVal, ok := key["key_id"].(string); ok {
			// Normalize both key IDs for comparison
			if normalizeKeyID(keyIDVal) == normalizedSearchKeyID {
				// Found the key, return it with vault path info
				key["vault_path"] = config.VaultPath
				return key, nil
			}
		}
	}

	return nil, fmt.Errorf("key %s not found in STATIC_ENCRYPTION_KEYS", keyID)
}

// MediaAnalysis represents the unified analysis results
type MediaAnalysis struct {
	MediaType           string // "HLS" or "DASH"
	KeyURI              string
	KeyID               string
	AllKeyIDs           []string // All unique key IDs (for DASH multi-key manifests)
	ClipID              string
	KeyFileSize         int64
	IVLength            int
	EncryptionMethod    string
	KeyType             string
	IsUtilityClip       bool
	ReferencedManifests []string
	HLSStreams          []HLSStreamInfo // HLS variant streams with resolution/bandwidth info
	Representations     []RepresentationInfo
	PSSHData            string
	ProData             string
	// Vault integration
	KeyExistsInVault  bool
	VaultKeyInfo      map[string]interface{}            // For single key (HLS)
	AllVaultKeyInfo   map[string]map[string]interface{} // For multiple keys (DASH): keyID -> vaultInfo
	UtilityClipSource string                            // "kubectl", "fallback", or "unknown"
	// KMS integration
	KeyExistsInKMS bool
	KMSKeyInfo     map[string]interface{}
}

type RepresentationInfo struct {
	ID        string
	Bandwidth int
	Codecs    string
	Width     int
	Height    int
	KeyID     string
}

// HLSStreamInfo holds information about an HLS variant stream
type HLSStreamInfo struct {
	Path      string
	Bandwidth int
	Width     int
	Height    int
	Codecs    string
}

// DASHManifest represents the DASH MPD structure
type DASHManifest struct {
	XMLName xml.Name `xml:"MPD"`
	Periods []Period `xml:"Period"`
}

type Period struct {
	ID             string          `xml:"id,attr"`
	AdaptationSets []AdaptationSet `xml:"AdaptationSet"`
}

type AdaptationSet struct {
	ID                string              `xml:"id,attr"`
	ContentType       string              `xml:"contentType,attr"`
	ContentProtection []ContentProtection `xml:"ContentProtection"`
	Representations   []Representation    `xml:"Representation"`
}

type ContentProtection struct {
	Value       string `xml:"value,attr"`
	SchemeIDURI string `xml:"schemeIdUri,attr"`
	DefaultKID  string `xml:"default_KID,attr"`
	PSSH        string `xml:"pssh"`
	Pro         string `xml:"pro"`
}

type Representation struct {
	ID        string `xml:"id,attr"`
	Bandwidth int    `xml:"bandwidth,attr"`
	Codecs    string `xml:"codecs,attr"`
	MimeType  string `xml:"mimeType,attr"`
	Width     int    `xml:"width,attr"`
	Height    int    `xml:"height,attr"`
}

// analyzeHLSManifest analyzes an HLS manifest file
func analyzeHLSManifest(manifestPath string, config EnvironmentConfig) (*MediaAnalysis, error) {
	var reader io.Reader
	var err error

	if isS3URL(manifestPath) {
		reader, err = fetchS3Content(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch manifest from S3: %w", err)
		}
	} else if isURL(manifestPath) {
		reader, err = fetchURLContent(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch manifest from URL: %w", err)
		}
	} else {
		file, err := os.Open(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open manifest: %w", err)
		}
		defer file.Close()
		reader = file
	}

	scanner := bufio.NewScanner(reader)
	var keyURI string
	var encryptionMethod string
	var isMasterManifest bool
	var referencedManifests []string
	var hlsStreams []HLSStreamInfo

	// Check if this is a master manifest and look for key info
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#EXT-X-STREAM-INF:") {
			isMasterManifest = true

			// Parse stream info attributes
			streamInfo := HLSStreamInfo{}

			// Parse BANDWIDTH
			if bwMatch := regexp.MustCompile(`BANDWIDTH=(\d+)`).FindStringSubmatch(line); len(bwMatch) > 1 {
				fmt.Sscanf(bwMatch[1], "%d", &streamInfo.Bandwidth)
			}

			// Parse RESOLUTION (WIDTHxHEIGHT)
			if resMatch := regexp.MustCompile(`RESOLUTION=(\d+)x(\d+)`).FindStringSubmatch(line); len(resMatch) > 2 {
				fmt.Sscanf(resMatch[1], "%d", &streamInfo.Width)
				fmt.Sscanf(resMatch[2], "%d", &streamInfo.Height)
			}

			// Parse CODECS
			if codecMatch := regexp.MustCompile(`CODECS="([^"]+)"`).FindStringSubmatch(line); len(codecMatch) > 1 {
				streamInfo.Codecs = codecMatch[1]
			}

			// Read the next line which should be the referenced manifest
			if scanner.Scan() {
				refManifest := strings.TrimSpace(scanner.Text())
				if !strings.HasPrefix(refManifest, "#") && refManifest != "" {
					referencedManifests = append(referencedManifests, refManifest)
					streamInfo.Path = refManifest
					hlsStreams = append(hlsStreams, streamInfo)
				}
			}
		} else if strings.HasPrefix(line, "#EXT-X-KEY:") {
			// Parse the key URI
			uriRegex := regexp.MustCompile(`URI="([^"]+)"`)
			matches := uriRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				keyURI = matches[1]
			}

			// Parse encryption method
			if strings.Contains(line, "METHOD=SAMPLE-AES") {
				encryptionMethod = "SAMPLE-AES (FairPlay)"
			} else if strings.Contains(line, "METHOD=AES-128") {
				// Check if it's a .key file (ClearKey) or URI (AES-128)
				if strings.Contains(keyURI, ".key") {
					encryptionMethod = "ClearKey"
				} else {
					encryptionMethod = "AES-128"
				}
			} else {
				encryptionMethod = "Unknown"
			}
			break
		}
	}

	// If this is a master manifest, return special analysis
	if isMasterManifest {
		return &MediaAnalysis{
			MediaType:           "HLS",
			KeyURI:              "MASTER_MANIFEST",
			KeyID:               "",
			ClipID:              "",
			EncryptionMethod:    "Master Manifest",
			IsUtilityClip:       false,
			ReferencedManifests: referencedManifests,
			HLSStreams:          hlsStreams,
		}, nil
	}

	if keyURI == "" {
		return nil, fmt.Errorf("no key URI found in manifest")
	}

	// Parse key URI to extract key ID and clip ID
	keyID, clipID := parseKeyURI(keyURI)

	// Only check utility clip status and key validation for DRM-protected content
	var isUtilityClip bool
	var utilitySource string
	var keyExistsInKMS bool
	var kmsKeyInfo map[string]interface{}

	var keyExistsInVault bool
	var vaultKeyInfo map[string]interface{}
	var ivLength int

	if encryptionMethod == "SAMPLE-AES (FairPlay)" || encryptionMethod == "Widevine (CENC)" || encryptionMethod == "PlayReady (CENC)" || encryptionMethod == "CENC (Common Encryption)" {
		// This is DRM-protected content - check utility clip status and key validation
		isUtilityClip, utilitySource = isUtilityClipID(clipID, config)

		// Check Vault first for key labels and metadata, then fallback to KMS
		if keyID != "" {
			// Check Vault to get key labels and metadata
			if globalVerbosity >= 2 {
				fmt.Printf("🔐 Checking Vault for key metadata...\n")
			}
			vaultInfo, vaultErr := getKeyInfoFromVault(keyID, config)
			if vaultErr != nil {
				if globalVerbosity >= 2 {
					fmt.Printf("⚠️  Key not found in Vault: %v\n", vaultErr)
					fmt.Printf("   Trying KMS service as fallback...\n")
				}

				// Try KMS service as fallback
				kmsExists, kmsInfo, kmsErr := checkKeyInKMS(keyID, config)
				if kmsErr != nil {
					if globalVerbosity >= 1 {
						fmt.Printf("⚠️  Key not found in KMS service: %v\n", kmsErr)
					}
				} else {
					keyExistsInKMS = kmsExists
					kmsKeyInfo = kmsInfo
					if globalVerbosity >= 2 {
						fmt.Printf("✅ Found key in KMS service\n")
					}
				}
			} else {
				keyExistsInVault = true
				vaultKeyInfo = vaultInfo
				if globalVerbosity >= 2 {
					fmt.Printf("✅ Found key metadata in Vault\n")
				}
			}
		}

		// Set standard IV length for DRM content based on encryption method
		switch encryptionMethod {
		case "SAMPLE-AES (FairPlay)":
			// FairPlay standard IV length is 16 bytes
			ivLength = 16
		case "Widevine (CENC)", "PlayReady (CENC)", "CENC (Common Encryption)":
			// CENC standard IV length is 8 bytes
			ivLength = 8
		}
	} else {
		// This is non-DRM content (ClearKey, AES-128) - skip utility clip and key validation
		isUtilityClip = false
		utilitySource = "not applicable (non-DRM)"
	}

	return &MediaAnalysis{
		MediaType:         "HLS",
		KeyURI:            keyURI,
		KeyID:             keyID,
		ClipID:            clipID,
		EncryptionMethod:  encryptionMethod,
		IsUtilityClip:     isUtilityClip,
		KeyExistsInVault:  keyExistsInVault,
		VaultKeyInfo:      vaultKeyInfo,
		UtilityClipSource: utilitySource,
		KeyExistsInKMS:    keyExistsInKMS,
		KMSKeyInfo:        kmsKeyInfo,
		IVLength:          ivLength,
	}, nil
}

// analyzeDASHManifest analyzes a DASH manifest file
func analyzeDASHManifest(manifestPath string, config EnvironmentConfig) (*MediaAnalysis, error) {
	var reader io.Reader
	var err error

	if isS3URL(manifestPath) {
		reader, err = fetchS3Content(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch manifest from S3: %w", err)
		}
	} else if isURL(manifestPath) {
		reader, err = fetchURLContent(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch manifest from URL: %w", err)
		}
	} else {
		file, err := os.Open(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open manifest: %w", err)
		}
		defer file.Close()
		reader = file
	}

	var manifest DASHManifest
	decoder := xml.NewDecoder(reader)
	err = decoder.Decode(&manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	var primaryKeyID string
	var clipID string
	var primaryEncryptionMethod string
	var psshData string
	var proData string
	var representations []RepresentationInfo
	allKeyIDs := make(map[string]bool) // Track all unique key IDs

	// Extract key information from ContentProtection for each adaptation set
	for _, period := range manifest.Periods {
		for _, adaptationSet := range period.AdaptationSets {
			// Extract key info for this specific adaptation set
			var adaptationSetKeyID string

			for _, contentProtection := range adaptationSet.ContentProtection {
				if contentProtection.DefaultKID != "" {
					adaptationSetKeyID = contentProtection.DefaultKID
					allKeyIDs[contentProtection.DefaultKID] = true
					// Set as primary if we don't have one yet
					if primaryKeyID == "" {
						primaryKeyID = contentProtection.DefaultKID
					}
				}

				if contentProtection.PSSH != "" {
					if psshData == "" {
						psshData = contentProtection.PSSH
					}
					// Try to extract key ID from PSSH if not found in default_KID
					if adaptationSetKeyID == "" {
						extractedKeyID, err := parseKeyIDFromPSSH(contentProtection.PSSH)
						if err == nil {
							adaptationSetKeyID = extractedKeyID
							allKeyIDs[extractedKeyID] = true
							if primaryKeyID == "" {
								primaryKeyID = extractedKeyID
							}
						}
					}
				}

				if contentProtection.Pro != "" && proData == "" {
					proData = contentProtection.Pro
				}

				// Determine encryption method for this adaptation set
				if strings.Contains(contentProtection.SchemeIDURI, "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed") {
					if primaryEncryptionMethod == "" {
						primaryEncryptionMethod = "Widevine (CENC)"
					}
				} else if strings.Contains(contentProtection.SchemeIDURI, "9a04f079-9840-4286-ab92-e65be0885f95") {
					if primaryEncryptionMethod == "" {
						primaryEncryptionMethod = "PlayReady (CENC)"
					}
				} else if contentProtection.Value == "cenc" {
					if primaryEncryptionMethod == "" {
						primaryEncryptionMethod = "CENC (Common Encryption)"
					}
				}
			}

			// Extract representation information for this adaptation set
			for _, representation := range adaptationSet.Representations {
				repInfo := RepresentationInfo{
					ID:        representation.ID,
					Bandwidth: representation.Bandwidth,
					Codecs:    representation.Codecs,
					Width:     representation.Width,
					Height:    representation.Height,
					KeyID:     adaptationSetKeyID, // Use the key ID for this specific adaptation set
				}
				representations = append(representations, repInfo)
			}
		}
	}

	// Extract clip ID from manifest path (for URLs and S3, it's in the path)
	clipID = extractClipIDFromPath(manifestPath)

	// Determine if it's a utility clip
	isUtilityClip := false
	utilitySource := ""
	if clipID != "unknown" && clipID != "" {
		isUtilityClip, utilitySource = isUtilityClipID(clipID, config)
	}

	// Determine key type based on encryption method
	var keyType string
	if primaryEncryptionMethod == "Widevine (CENC)" || primaryEncryptionMethod == "PlayReady (CENC)" || primaryEncryptionMethod == "CENC (Common Encryption)" {
		keyType = "HD Video Key (CENC)"
	} else {
		keyType = "Unknown Key Type"
	}

	// Check Vault and KMS for all unique DASH keys
	var keyExistsInVault bool
	var vaultKeyInfo map[string]interface{}
	var keyExistsInKMS bool
	var kmsKeyInfo map[string]interface{}
	allVaultKeyInfo := make(map[string]map[string]interface{})

	// Convert allKeyIDs map to slice
	var allKeyIDsSlice []string
	for keyID := range allKeyIDs {
		allKeyIDsSlice = append(allKeyIDsSlice, keyID)
	}

	// Determine IV length for CENC (8 bytes is standard)
	var ivLength int
	if primaryEncryptionMethod == "Widevine (CENC)" || primaryEncryptionMethod == "PlayReady (CENC)" || primaryEncryptionMethod == "CENC (Common Encryption)" {
		ivLength = 8 // CENC standard IV length
	}

	// Check vault/KMS for each unique key ID
	if len(allKeyIDs) > 0 && (primaryEncryptionMethod == "Widevine (CENC)" || primaryEncryptionMethod == "PlayReady (CENC)" || primaryEncryptionMethod == "CENC (Common Encryption)") {
		if globalVerbosity >= 2 {
			fmt.Printf("🔐 Found %d unique key ID(s) in manifest\n", len(allKeyIDs))
		}

		// Check each unique key
		for keyIDToCheck := range allKeyIDs {
			if globalVerbosity >= 2 {
				fmt.Printf("🔐 Checking Vault for key: %s\n", keyIDToCheck)
			}

			vaultInfo, vaultErr := getKeyInfoFromVault(keyIDToCheck, config)
			if vaultErr != nil {
				if globalVerbosity >= 2 {
					fmt.Printf("⚠️  Key %s not found in Vault: %v\n", keyIDToCheck, vaultErr)
					fmt.Printf("   Trying KMS service as fallback...\n")
				}

				// Try KMS service as fallback
				_, kmsInfo, kmsErr := checkKeyInKMS(keyIDToCheck, config)
				if kmsErr != nil {
					if globalVerbosity >= 1 {
						fmt.Printf("⚠️  Key %s not found in KMS service: %v\n", keyIDToCheck, kmsErr)
					}
				} else {
					keyExistsInKMS = true
					if kmsKeyInfo == nil {
						kmsKeyInfo = kmsInfo
					}
					if globalVerbosity >= 2 {
						fmt.Printf("✅ Found key %s in KMS service\n", keyIDToCheck)
					}
				}
			} else {
				keyExistsInVault = true
				// Store vault info for this specific key
				allVaultKeyInfo[keyIDToCheck] = vaultInfo
				if vaultKeyInfo == nil {
					vaultKeyInfo = vaultInfo // Keep first one for backward compatibility
				}
				if globalVerbosity >= 2 {
					fmt.Printf("✅ Found key %s metadata in Vault\n", keyIDToCheck)
				}
			}
		}
	}

	return &MediaAnalysis{
		MediaType:         "DASH",
		KeyID:             primaryKeyID,
		AllKeyIDs:         allKeyIDsSlice,
		ClipID:            clipID,
		EncryptionMethod:  primaryEncryptionMethod,
		KeyType:           keyType,
		IsUtilityClip:     isUtilityClip,
		UtilityClipSource: utilitySource,
		PSSHData:          psshData,
		ProData:           proData,
		Representations:   representations,
		KeyExistsInVault:  keyExistsInVault,
		VaultKeyInfo:      vaultKeyInfo,
		AllVaultKeyInfo:   allVaultKeyInfo,
		KeyExistsInKMS:    keyExistsInKMS,
		KMSKeyInfo:        kmsKeyInfo,
		IVLength:          ivLength,
	}, nil
}

// extractHLSRenditionDescription extracts a clean description from an HLS manifest filename
func extractHLSRenditionDescription(manifestPath string) string {
	// Get just the filename without path
	filename := filepath.Base(manifestPath)
	filename = strings.TrimSuffix(filename, ".m3u8")
	filename = strings.TrimSuffix(filename, ".M3U8")
	lowerFilename := strings.ToLower(filename)

	// Check for audio first
	if strings.Contains(lowerFilename, "audio") {
		return "Audio"
	}

	// Try to extract bitrate from patterns like "hls_1000", "hls_1600", "hls_4500", "hls_300"
	bitrateRegex := regexp.MustCompile(`[_-](\d{3,5})(?:[_.]|$)`)
	if matches := bitrateRegex.FindStringSubmatch(filename); len(matches) > 1 {
		bitrateStr := matches[1]
		bitrate := 0
		fmt.Sscanf(bitrateStr, "%d", &bitrate)
		quality := "SD"
		if bitrate >= 2000 {
			quality = "HD"
		}
		return fmt.Sprintf("%s %s kbps", quality, bitrateStr)
	}

	// Check for explicit resolution patterns with word boundaries (e.g., "720p", "1080p", "/720/", "_720_")
	resolutionRegex := regexp.MustCompile(`(?:^|[/_-])(\d{3,4})p?(?:[/_-]|$)`)
	if matches := resolutionRegex.FindStringSubmatch(lowerFilename); len(matches) > 1 {
		res := matches[1]
		resInt := 0
		fmt.Sscanf(res, "%d", &resInt)
		quality := "SD"
		if resInt >= 720 {
			quality = "HD"
		}
		// Only treat as resolution if it's a common video height
		switch res {
		case "2160", "1080", "720", "576", "540", "480", "360", "240", "144":
			return fmt.Sprintf("%s %sp", quality, res)
		}
	}

	// Check for 4K
	if strings.Contains(lowerFilename, "4k") || strings.Contains(lowerFilename, "2160") {
		return "HD 2160p (4K)"
	}

	// Try to extract any number - assume it's a bitrate
	numRegex := regexp.MustCompile(`(\d{3,5})`)
	if matches := numRegex.FindStringSubmatch(filename); len(matches) > 1 {
		bitrateStr := matches[1]
		bitrate := 0
		fmt.Sscanf(bitrateStr, "%d", &bitrate)
		quality := "SD"
		if bitrate >= 2000 {
			quality = "HD"
		}
		return fmt.Sprintf("%s %s kbps", quality, bitrateStr)
	}

	// Fallback: just use cleaned filename
	cleanName := strings.ReplaceAll(filename, "_", " ")
	cleanName = strings.ReplaceAll(cleanName, "-", " ")
	if cleanName != "" && cleanName != "index" && cleanName != "master" && cleanName != "playlist" {
		return cleanName
	}
	return "Video variant"
}

// parseKeyURI extracts key ID and clip ID from skd:// URI
func parseKeyURI(uri string) (string, string) {
	// Expected format: skd://{keyID}/clip/{clipID}
	// Remove skd:// prefix first
	if !strings.HasPrefix(uri, "skd://") {
		return "", ""
	}

	// Remove skd:// prefix and split by /
	cleanURI := strings.TrimPrefix(uri, "skd://")
	parts := strings.Split(cleanURI, "/")

	if len(parts) >= 3 && parts[1] == "clip" {
		return parts[0], parts[2]
	}
	return "", ""
}

// parseKeyIDFromPSSH extracts key ID from PSSH data
func parseKeyIDFromPSSH(psshBase64 string) (string, error) {
	// Decode base64
	psshData, err := base64.StdEncoding.DecodeString(psshBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode PSSH: %w", err)
	}

	// PSSH format: [4 bytes size][4 bytes type][16 bytes key ID][...]
	if len(psshData) < 24 {
		return "", fmt.Errorf("PSSH too short")
	}

	// Extract key ID (bytes 8-24)
	keyIDBytes := psshData[8:24]
	keyID := fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		keyIDBytes[0], keyIDBytes[1], keyIDBytes[2], keyIDBytes[3],
		keyIDBytes[4], keyIDBytes[5], keyIDBytes[6], keyIDBytes[7],
		keyIDBytes[8], keyIDBytes[9], keyIDBytes[10], keyIDBytes[11],
		keyIDBytes[12], keyIDBytes[13], keyIDBytes[14], keyIDBytes[15])

	return keyID, nil
}

// analyzeKeyFile analyzes a key file to determine IV length
func analyzeKeyFile(keyFilePath string) (int64, int, error) {
	file, err := os.Open(keyFilePath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to open key file: %w", err)
	}
	defer file.Close()

	// Get file size
	stat, err := file.Stat()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get file stats: %w", err)
	}

	fileSize := stat.Size()

	// Read first few bytes to analyze
	buffer := make([]byte, 32)
	_, err = file.Read(buffer)
	if err != nil && err != io.EOF {
		return fileSize, 0, fmt.Errorf("failed to read key file: %w", err)
	}

	// Determine IV length based on file size
	var ivLength int
	switch fileSize {
	case 16:
		ivLength = 16 // FairPlay standard
	case 8:
		ivLength = 8 // CENC standard
	default:
		ivLength = int(fileSize) // Use file size as IV length
	}

	return fileSize, ivLength, nil
}

// determineKeyType determines the type of key based on analysis
func determineKeyType(analysis *MediaAnalysis) string {
	switch analysis.MediaType {
	case "HLS":
		if analysis.EncryptionMethod == "SAMPLE-AES (FairPlay)" {
			// Use IV length to determine key type
			if analysis.IVLength == 16 {
				return "SD Video+Audio Key (FairPlay)"
			}
			return "Unknown FairPlay Key"
		}

		if analysis.EncryptionMethod == "ClearKey" {
			return "ClearKey (Local Key File)"
		}

		if analysis.EncryptionMethod == "AES-128" {
			return "AES-128 (URI-based)"
		}

		if analysis.IVLength == 8 {
			return "CENC Key (DASH Widevine)"
		}

		return "Unknown Key Type"
	case "DASH":
		if analysis.EncryptionMethod == "Widevine (CENC)" || analysis.EncryptionMethod == "PlayReady (CENC)" || analysis.EncryptionMethod == "CENC (Common Encryption)" {
			return "HD Video Key (CENC)"
		}
		return "Unknown Key Type"
	default:
		return "Unknown Key Type"
	}
}

// listS3Manifests lists all manifest files in an S3 prefix
func listS3Manifests(s3URL string) ([]string, error) {
	// Parse S3 URL
	bucket, prefix, err := parseS3URL(s3URL)
	if err != nil {
		return nil, err
	}

	// Get shared S3 client
	client, err := getS3Client()
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 client: %w", err)
	}

	var manifestFiles []string
	ctx := context.Background()

	// List objects with the given prefix
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: &bucket,
		Prefix: &prefix,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list S3 objects: %w", err)
		}

		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}

			key := *obj.Key
			// Check if it's a manifest file
			if strings.HasSuffix(key, ".m3u8") || strings.HasSuffix(key, ".mpd") {
				// By default, skip subclip folders (0-10, 10-20, etc.) - only process 0-end
				// Use --subclips flag to include them
				if !globalIncludeSubclips && isSubclipPath("/"+key) {
					continue
				}
				// Construct full S3 URL
				manifestURL := fmt.Sprintf("s3://%s/%s", bucket, key)
				manifestFiles = append(manifestFiles, manifestURL)
			}
		}
	}

	if len(manifestFiles) == 0 {
		return nil, fmt.Errorf("no manifest files (.m3u8 or .mpd) found in s3://%s/%s", bucket, prefix)
	}

	return manifestFiles, nil
}

// findMediaFiles finds all media manifest files in a directory or returns a single URL
func findMediaFiles(path string) ([]string, error) {
	// If it's an HTTP/HTTPS URL
	if isURL(path) {
		// If it ends with a manifest extension, treat it as a single file
		if strings.HasSuffix(path, ".m3u8") || strings.HasSuffix(path, ".mpd") {
			return []string{path}, nil
		}

		// If it's a directory URL (no extension), try standard manifest locations
		var manifestFiles []string

		baseURL := path
		if !strings.HasSuffix(baseURL, "/") {
			baseURL += "/"
		}

		// Try standard manifest locations
		commonLocations := []string{
			"hls/0-end/master.m3u8",
			"dash/0-end/main.mpd",
		}

		for _, location := range commonLocations {
			testURL := baseURL + location
			resp, err := globalHTTPClient.Head(testURL)
			if err == nil && resp.StatusCode == http.StatusOK {
				manifestFiles = append(manifestFiles, testURL)
			}
			if resp != nil {
				resp.Body.Close()
			}
		}

		if len(manifestFiles) == 0 {
			return nil, fmt.Errorf("no accessible manifest files found at %s (tried hls/0-end/master.m3u8 and dash/0-end/main.mpd)", path)
		}

		return manifestFiles, nil
	}

	// If it's an S3 URL, check if it's a single file or a prefix to list
	if isS3URL(path) {
		// If the path ends with a manifest extension, treat it as a single file
		if strings.HasSuffix(path, ".m3u8") || strings.HasSuffix(path, ".mpd") {
			return []string{path}, nil
		}
		// Otherwise, list all manifests in the S3 prefix
		return listS3Manifests(path)
	}

	// Local file system walk
	var manifestFiles []string

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Look for HLS and DASH manifest files
		if strings.HasSuffix(filePath, ".m3u8") || strings.HasSuffix(filePath, ".mpd") {
			manifestFiles = append(manifestFiles, filePath)
		}

		return nil
	})

	return manifestFiles, err
}

// findKeyFiles finds all key files in a directory
func findKeyFiles(dir string) ([]string, error) {
	var keyFiles []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Look for key files
		if strings.HasSuffix(path, ".key") || strings.Contains(path, "keyfile") {
			keyFiles = append(keyFiles, path)
		}

		return nil
	})

	return keyFiles, err
}

// printHexDump prints a hex dump of a file
func printHexDump(filePath string, maxBytes int) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	buffer := make([]byte, maxBytes)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read file: %w", err)
	}

	fmt.Printf("\n📄 Hex dump of %s (first %d bytes):\n", filePath, n)
	for i := 0; i < n; i += 16 {
		// Print offset
		fmt.Printf("%08x  ", i)

		// Print hex bytes
		for j := 0; j < 16; j++ {
			if i+j < n {
				fmt.Printf("%02x ", buffer[i+j])
			} else {
				fmt.Printf("   ")
			}
			if j == 7 {
				fmt.Printf(" ")
			}
		}

		// Print ASCII representation
		fmt.Printf(" |")
		for j := 0; j < 16 && i+j < n; j++ {
			b := buffer[i+j]
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Printf(".")
			}
		}
		fmt.Printf("|\n")
	}

	return nil
}

// playMediaFile attempts to play a media file using ffplay with optional DRM decryption
func playMediaFile(manifestPath string, analysis *MediaAnalysis, config EnvironmentConfig, verbosity int) {
	// Check if ffplay is available
	if _, err := exec.LookPath("ffplay"); err != nil {
		fmt.Printf("⚠️  ffplay not found in PATH. Please install FFmpeg to play media files.\n")
		fmt.Printf("   Install with: brew install ffmpeg (macOS) or apt-get install ffmpeg (Linux)\n")
		return
	}

	if verbosity >= 1 {
		fmt.Printf("📺 Playing: %s\n", manifestPath)
	}

	// Check if this is DRM content that needs decryption
	if analysis != nil && analysis.KeyID != "" &&
		(strings.Contains(analysis.EncryptionMethod, "CENC") ||
			strings.Contains(analysis.EncryptionMethod, "Widevine") ||
			strings.Contains(analysis.EncryptionMethod, "PlayReady")) {

		if verbosity >= 1 {
			fmt.Printf("🔐 Detected DRM encryption (%s)\n", analysis.EncryptionMethod)
			fmt.Printf("\n⚠️  Note: FFmpeg/ffplay cannot directly play CENC/DRM encrypted content.\n")
			fmt.Printf("\n📋 Options for playing DRM content:\n")
			fmt.Printf("   1. Use a browser with built-in DRM support:\n")
			fmt.Printf("      • Chrome/Edge (Widevine) or Safari (FairPlay)\n")
			fmt.Printf("      • Open: %s\n", manifestPath)
			fmt.Printf("\n   2. Use mp4decrypt (from Bento4) to decrypt first:\n")
			fmt.Printf("      • Install: brew install bento4\n")
		}

		// Try to retrieve key info for manual decryption
		if verbosity >= 1 {
			fmt.Printf("\n🔑 Retrieving decryption key from KMS...\n")
		}

		decryptionKey, _, err := getDecryptionKeyFromKMS(analysis.KeyID, config)
		if err != nil {
			fmt.Printf("⚠️  Failed to retrieve decryption key: %v\n", err)
		} else {
			if verbosity >= 1 {
				fmt.Printf("✅ Retrieved decryption key\n")
				fmt.Printf("\n📝 To decrypt manually, use:\n")
				fmt.Printf("   mp4decrypt --key %s:%s input.mp4 output.mp4\n", analysis.KeyID, decryptionKey)
				fmt.Printf("   ffplay output.mp4\n")
			}
		}

		if verbosity >= 1 {
			fmt.Printf("\n💬 Would you like to open this in a browser instead? (y/n): ")
		}
		return
	}

	// For non-DRM content, play directly with ffplay
	args := []string{
		"-autoexit",            // Exit when playback finishes
		"-loglevel", "warning", // Reduce log verbosity
	}

	// Add verbose logging if requested
	if verbosity >= 2 {
		args = []string{
			"-autoexit",
			"-loglevel", "info",
		}
	}

	if verbosity >= 1 {
		fmt.Printf("💡 Press 'q' to quit, 'p' to pause, space to toggle playback\n")
	}

	args = append(args, manifestPath)

	// Execute ffplay
	cmd := exec.Command("ffplay", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Check if user quit (exit code 255 or SIGINT)
			if exitErr.ExitCode() == 255 || exitErr.ExitCode() == 130 {
				if verbosity >= 1 {
					fmt.Printf("✅ Playback stopped by user\n")
				}
				return
			}
		}
		fmt.Printf("❌ Error playing media: %v\n", err)
		fmt.Printf("   This may be due to unsupported codec or corrupted file\n")
	} else if verbosity >= 1 {
		fmt.Printf("✅ Playback completed\n")
	}
}

// decodeBase64Data decodes and displays base64-encoded data
func decodeBase64Data(data string, label string) {
	if data == "" {
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		fmt.Printf("❌ Failed to decode %s: %v\n", label, err)
		return
	}

	fmt.Printf("📋 %s (decoded %d bytes):\n", label, len(decoded))
	for i := 0; i < len(decoded) && i < 64; i += 16 {
		fmt.Printf("  %08x  ", i)
		for j := 0; j < 16 && i+j < len(decoded); j++ {
			fmt.Printf("%02x ", decoded[i+j])
		}
		fmt.Printf("\n")
	}
}

// KeyDetail represents metadata about a single encryption key
type KeyDetail struct {
	KID              string
	Labels           []string
	IV               int
	EncryptionMethod string
	InVault          bool
	InKMS            bool
}

// RenditionSummary represents a rendition and its associated key
type RenditionSummary struct {
	Description string // e.g., "1080p video", "720p video", "audio"
	KeyID       string
	ClipID      string // Source clip ID for grouping
}

// ManifestResult holds the results from analyzing a single manifest
type ManifestResult struct {
	ManifestPath     string
	Analysis         *MediaAnalysis
	Error            error
	KeyDetails       map[string]KeyDetail
	Renditions       []RenditionSummary
	TotalAnalyzed    int
	TotalEncrypted   int
	TotalFairPlay    int
	TotalWidevine    int
	TotalInVault     int
	TotalInKMS       int
	TotalMismatches  int
	TotalMissingKeys int
}

// extractBitrateForSort extracts a numeric value from rendition description for sorting
func extractBitrateForSort(desc string) int {
	// Try to extract bitrate in kbps (e.g., "1000 kbps HLS", "254 kbps")
	bitrateRegex := regexp.MustCompile(`(\d+)\s*kbps`)
	if matches := bitrateRegex.FindStringSubmatch(desc); len(matches) > 1 {
		val := 0
		fmt.Sscanf(matches[1], "%d", &val)
		return val
	}

	// Try to extract resolution and convert to approximate bitrate for sorting
	// (higher resolution = higher in sort order)
	resRegex := regexp.MustCompile(`(\d+)p`)
	if matches := resRegex.FindStringSubmatch(desc); len(matches) > 1 {
		val := 0
		fmt.Sscanf(matches[1], "%d", &val)
		// Convert resolution to approximate bitrate equivalent for sorting
		switch val {
		case 2160:
			return 15000
		case 1080:
			return 5000
		case 720:
			return 2500
		case 576:
			return 1500
		case 480:
			return 1000
		case 360:
			return 600
		case 240:
			return 300
		case 144:
			return 150
		default:
			return val * 3 // rough estimate
		}
	}

	// Audio typically lower bitrate
	if strings.Contains(strings.ToLower(desc), "audio") || strings.Contains(desc, "mp4a") {
		return 100
	}

	// Subtitles/captions at the bottom
	if strings.Contains(strings.ToLower(desc), "wvtt") || strings.Contains(strings.ToLower(desc), "subtitle") {
		return 0
	}

	return 50000 // Unknown at the end
}

// sortRenditionsByBitrate sorts rendition descriptions by bitrate (lowest to highest)
func sortRenditionsByBitrate(rendList []string) {
	sort.Slice(rendList, func(i, j int) bool {
		return extractBitrateForSort(rendList[i]) < extractBitrateForSort(rendList[j])
	})
}

// simplifyCodecName returns a human-readable codec name
func simplifyCodecName(codecs string) string {
	codecLower := strings.ToLower(codecs)

	if strings.HasPrefix(codecLower, "avc1") || strings.HasPrefix(codecLower, "h264") {
		return "H.264"
	}
	if strings.HasPrefix(codecLower, "hvc1") || strings.HasPrefix(codecLower, "hev1") || strings.HasPrefix(codecLower, "h265") {
		return "HEVC"
	}
	if strings.HasPrefix(codecLower, "vp9") || strings.HasPrefix(codecLower, "vp09") {
		return "VP9"
	}
	if strings.HasPrefix(codecLower, "av01") || strings.HasPrefix(codecLower, "av1") {
		return "AV1"
	}
	if strings.HasPrefix(codecLower, "mp4a") {
		return "AAC"
	}
	if strings.HasPrefix(codecLower, "ac-3") {
		return "Dolby AC-3"
	}
	if strings.HasPrefix(codecLower, "ec-3") {
		return "Dolby E-AC-3"
	}
	if strings.Contains(codecLower, "opus") {
		return "Opus"
	}

	return codecs
}

// formatCodecDescription creates a human-readable description from codec and bitrate (no resolution)
func formatCodecDescription(codecs string, bandwidthKbps int) string {
	codecLower := strings.ToLower(codecs)

	// Audio codecs
	if strings.HasPrefix(codecLower, "mp4a") {
		return fmt.Sprintf("Audio AAC (%d kbps)", bandwidthKbps)
	}
	if strings.HasPrefix(codecLower, "ac-3") || strings.HasPrefix(codecLower, "ec-3") {
		return fmt.Sprintf("Audio Dolby (%d kbps)", bandwidthKbps)
	}
	if strings.Contains(codecLower, "opus") {
		return fmt.Sprintf("Audio Opus (%d kbps)", bandwidthKbps)
	}

	// Video codecs - estimate quality from bitrate when no resolution available
	codecName := simplifyCodecName(codecs)
	if strings.HasPrefix(codecLower, "avc1") || strings.HasPrefix(codecLower, "h264") ||
		strings.HasPrefix(codecLower, "hvc1") || strings.HasPrefix(codecLower, "hev1") ||
		strings.HasPrefix(codecLower, "vp9") || strings.HasPrefix(codecLower, "av01") {
		if bandwidthKbps >= 2000 {
			return fmt.Sprintf("HD Video %s (%d kbps)", codecName, bandwidthKbps)
		}
		return fmt.Sprintf("SD Video %s (%d kbps)", codecName, bandwidthKbps)
	}

	// Subtitle codecs
	if strings.Contains(codecLower, "vtt") || strings.Contains(codecLower, "wvtt") {
		return "Subtitles (WebVTT)"
	}
	if strings.Contains(codecLower, "stpp") || strings.Contains(codecLower, "ttml") {
		return "Subtitles (TTML)"
	}

	// Fallback to original format
	return fmt.Sprintf("%s (%d kbps)", codecs, bandwidthKbps)
}

// formatResolutionDescription creates a description with resolution, codec, and bitrate
func formatResolutionDescription(height int, codecs string, bandwidthKbps int) string {
	codecName := simplifyCodecName(codecs)
	quality := "SD"
	if height >= 720 {
		quality = "HD"
	}
	return fmt.Sprintf("%s %dp %s (%d kbps)", quality, height, codecName, bandwidthKbps)
}

// generateMarkdownSummary generates a markdown version of the summary
func generateMarkdownSummary(uniqueKeyMap map[string]KeyDetail, renditionsByKeyAndClip map[string]map[string]map[string]bool, clipCountByKey map[string]map[string]bool) string {
	var sb strings.Builder

	// Sort keys
	var sortedKeys []string
	for kid := range uniqueKeyMap {
		sortedKeys = append(sortedKeys, kid)
	}
	sort.Strings(sortedKeys)

	// Separate keys into DASH and HLS groups
	var dashKeys, hlsKeys []string
	for _, kid := range sortedKeys {
		detail := uniqueKeyMap[kid]
		if strings.Contains(detail.EncryptionMethod, "FairPlay") || strings.Contains(detail.EncryptionMethod, "SAMPLE-AES") {
			hlsKeys = append(hlsKeys, kid)
		} else {
			dashKeys = append(dashKeys, kid)
		}
	}

	sb.WriteString("# Keys & Renditions\n\n")

	// Determine example URL(s) based on path type
	pathLower := strings.ToLower(globalManifestPath)
	isSpecificManifest := strings.HasSuffix(pathLower, ".mpd") || strings.HasSuffix(pathLower, ".m3u8")
	basePath := strings.TrimSuffix(globalManifestPath, "/")

	// Helper to write a group of keys
	writeKeyGroup := func(keys []string, title string, manifestType string) {
		if len(keys) == 0 {
			return
		}

		// Write example URL for this section
		if isSpecificManifest {
			sb.WriteString(fmt.Sprintf("**Example:** `%s`\n\n", globalManifestPath))
		} else {
			if manifestType == "DASH" {
				sb.WriteString(fmt.Sprintf("**Example:** `%s/dash/0-end/main.mpd`\n\n", basePath))
			} else {
				sb.WriteString(fmt.Sprintf("**Example:** `%s/hls/0-end/master.m3u8`\n\n", basePath))
			}
		}

		sb.WriteString(fmt.Sprintf("## %s\n\n", title))

		for _, kid := range keys {
			detail := uniqueKeyMap[kid]

			// Key header
			sb.WriteString(fmt.Sprintf("### KID: `%s`\n\n", detail.KID))

			// Key details table
			sb.WriteString("| Property | Value |\n")
			sb.WriteString("|----------|-------|\n")

			location := "❌ Not found"
			if detail.InVault {
				location = "✅ Vault"
			} else if detail.InKMS {
				location = "✅ KMS"
			}
			sb.WriteString(fmt.Sprintf("| IV | %d bytes |\n", detail.IV))
			sb.WriteString(fmt.Sprintf("| Encryption | %s |\n", detail.EncryptionMethod))
			sb.WriteString(fmt.Sprintf("| Key Location | %s |\n", location))
			if len(detail.Labels) > 0 {
				sb.WriteString(fmt.Sprintf("| Labels | %s |\n", strings.Join(detail.Labels, ", ")))
			}
			sb.WriteString("\n")

			// Renditions
			if clipRenditions, exists := renditionsByKeyAndClip[kid]; exists && len(clipRenditions) > 0 {
				clipCount := len(clipCountByKey[kid])

				if clipCount == 1 {
					sb.WriteString("**Renditions:**\n\n")
					for _, descSet := range clipRenditions {
						var rendList []string
						for desc := range descSet {
							rendList = append(rendList, desc)
						}
						sortRenditionsByBitrate(rendList)
						for _, desc := range rendList {
							sb.WriteString(fmt.Sprintf("- %s\n", desc))
						}
					}
				} else {
					sb.WriteString(fmt.Sprintf("**Renditions (%d clips):**\n\n", clipCount))
					var sortedClips []string
					for clipID := range clipRenditions {
						sortedClips = append(sortedClips, clipID)
					}
					sort.Strings(sortedClips)

					for _, clipID := range sortedClips {
						descSet := clipRenditions[clipID]
						shortClip := clipID
						if len(shortClip) > 16 {
							shortClip = shortClip[:16] + "…"
						}
						sb.WriteString(fmt.Sprintf("**Clip %s:**\n", shortClip))
						var rendList []string
						for desc := range descSet {
							rendList = append(rendList, desc)
						}
						sortRenditionsByBitrate(rendList)
						for _, desc := range rendList {
							sb.WriteString(fmt.Sprintf("  - %s\n", desc))
						}
						sb.WriteString("\n")
					}
				}
				sb.WriteString("\n")
			}
			sb.WriteString("---\n\n")
		}
	}

	writeKeyGroup(dashKeys, "DASH (Widevine/PlayReady)", "DASH")
	writeKeyGroup(hlsKeys, "HLS (FairPlay)", "HLS")

	return sb.String()
}

// printSummary prints the unique keys and rendition mappings grouped by key
func printSummary(uniqueKeyMap map[string]KeyDetail, renditions []RenditionSummary) {
	// Group renditions by key ID -> clip ID -> descriptions
	// Structure: keyID -> clipID -> set of descriptions
	renditionsByKeyAndClip := make(map[string]map[string]map[string]bool)
	clipCountByKey := make(map[string]map[string]bool) // keyID -> set of clipIDs

	for _, r := range renditions {
		keyID := r.KeyID
		if keyID == "" {
			keyID = "(no key)"
		}
		clipID := r.ClipID
		if clipID == "" || clipID == "unknown" {
			clipID = "unknown"
		}

		if renditionsByKeyAndClip[keyID] == nil {
			renditionsByKeyAndClip[keyID] = make(map[string]map[string]bool)
			clipCountByKey[keyID] = make(map[string]bool)
		}
		if renditionsByKeyAndClip[keyID][clipID] == nil {
			renditionsByKeyAndClip[keyID][clipID] = make(map[string]bool)
		}
		renditionsByKeyAndClip[keyID][clipID][r.Description] = true
		clipCountByKey[keyID][clipID] = true
	}

	// Print unique keys with their associated renditions
	fmt.Printf("\n🔑 Keys & Renditions:\n")
	var sortedKeys []string
	for kid := range uniqueKeyMap {
		sortedKeys = append(sortedKeys, kid)
	}
	sort.Strings(sortedKeys)

	if len(sortedKeys) == 0 {
		fmt.Printf("  No encrypted content found.\n")
		fmt.Printf("  This could mean:\n")
		fmt.Printf("    • The manifest file doesn't exist\n")
		fmt.Printf("    • The content is not DRM-protected\n")
		fmt.Printf("    • No valid key IDs were found\n")
		// If markdown output is requested, generate "no content" markdown
		if globalMarkdownOutput {
			var markdown string
			pathLower := strings.ToLower(globalManifestPath)
			if strings.HasSuffix(pathLower, ".mpd") || strings.HasSuffix(pathLower, ".m3u8") {
				markdown = fmt.Sprintf("# Keys & Renditions\n\n**Example:** `%s`\n\nNo encrypted content found.\n", globalManifestPath)
			} else {
				basePath := strings.TrimSuffix(globalManifestPath, "/")
				markdown = fmt.Sprintf("# Keys & Renditions\n\n**Examples:**\n- DASH: `%s/dash/0-end/main.mpd`\n- HLS: `%s/hls/0-end/master.m3u8`\n\nNo encrypted content found.\n", basePath, basePath)
			}
			if err := copyToClipboard(markdown); err != nil {
				fmt.Printf("\n⚠️  Failed to copy markdown to clipboard: %v\n", err)
			} else {
				fmt.Printf("\n📋 Markdown copied to clipboard!\n")
			}
		}
		return
	}

	// If markdown output is requested, generate it now (will copy at the end)
	var markdownErr error
	if globalMarkdownOutput {
		markdown := generateMarkdownSummary(uniqueKeyMap, renditionsByKeyAndClip, clipCountByKey)
		markdownErr = copyToClipboard(markdown)
	}

	// First pass: calculate max width needed
	maxWidth := 0
	for _, kid := range sortedKeys {
		detail := uniqueKeyMap[kid]

		// KID line
		kidLine := "KID: " + detail.KID
		if len(kidLine) > maxWidth {
			maxWidth = len(kidLine)
		}

		// Detail line
		location := "✗ Not found"
		if detail.InVault {
			location = "✓ Vault"
		} else if detail.InKMS {
			location = "✓ KMS"
		}
		detailLine := fmt.Sprintf("IV: %d bytes | %s | %s", detail.IV, detail.EncryptionMethod, location)
		if len(detailLine) > maxWidth {
			maxWidth = len(detailLine)
		}

		// Labels line
		if len(detail.Labels) > 0 {
			labelsLine := "Labels: " + strings.Join(detail.Labels, ", ")
			if len(labelsLine) > maxWidth {
				maxWidth = len(labelsLine)
			}
		}

		// Renditions
		if clipRenditions, exists := renditionsByKeyAndClip[kid]; exists {
			clipCount := len(clipCountByKey[kid])
			if clipCount > 1 {
				headerLine := fmt.Sprintf("Renditions (%d clips):", clipCount)
				if len(headerLine) > maxWidth {
					maxWidth = len(headerLine)
				}
			}
			for clipID, descSet := range clipRenditions {
				if clipCount > 1 {
					shortClip := clipID
					if len(shortClip) > 12 {
						shortClip = shortClip[:12] + "…"
					}
					clipHeader := "  Clip " + shortClip + ":"
					if len(clipHeader) > maxWidth {
						maxWidth = len(clipHeader)
					}
				}
				for desc := range descSet {
					prefix := "  • "
					if clipCount > 1 {
						prefix = "    • "
					}
					rendLine := prefix + desc
					if len(rendLine) > maxWidth {
						maxWidth = len(rendLine)
					}
				}
			}
		}
	}

	// Add padding for box borders (│ + space on each side)
	boxWidth := maxWidth + 2 // content + 2 spaces padding

	// Separate keys into DASH and HLS groups
	var dashKeys, hlsKeys []string
	for _, kid := range sortedKeys {
		detail := uniqueKeyMap[kid]
		if strings.Contains(detail.EncryptionMethod, "FairPlay") || strings.Contains(detail.EncryptionMethod, "SAMPLE-AES") {
			hlsKeys = append(hlsKeys, kid)
		} else {
			dashKeys = append(dashKeys, kid)
		}
	}

	// Helper function to print a group of keys
	printKeyGroup := func(keys []string, label string) {
		if len(keys) == 0 {
			return
		}

		fmt.Printf("\n%s\n", label)
		fmt.Printf("┌%s┐\n", strings.Repeat("─", boxWidth))
		for i, kid := range keys {
			detail := uniqueKeyMap[kid]

			// Key header
			kidLine := "KID: " + detail.KID
			fmt.Printf("│ %-*s │\n", boxWidth-2, kidLine)

			// Key details
			location := "✗ Not found"
			if detail.InVault {
				location = "✓ Vault"
			} else if detail.InKMS {
				location = "✓ KMS"
			}
			detailLine := fmt.Sprintf("IV: %d bytes | %s | %s", detail.IV, detail.EncryptionMethod, location)
			fmt.Printf("│ %-*s │\n", boxWidth-2, detailLine)

			// Labels on separate line if present
			if len(detail.Labels) > 0 {
				labelsLine := "Labels: " + strings.Join(detail.Labels, ", ")
				fmt.Printf("│ %-*s │\n", boxWidth-2, labelsLine)
			}

			// Renditions using this key
			if clipRenditions, exists := renditionsByKeyAndClip[kid]; exists && len(clipRenditions) > 0 {
				clipCount := len(clipCountByKey[kid])

				if clipCount == 1 {
					// Single clip - show simple list
					fmt.Printf("│ %-*s │\n", boxWidth-2, "Renditions:")
					for _, descSet := range clipRenditions {
						var rendList []string
						for desc := range descSet {
							rendList = append(rendList, desc)
						}
						sortRenditionsByBitrate(rendList)
						for _, desc := range rendList {
							fmt.Printf("│   • %-*s │\n", boxWidth-6, desc)
						}
					}
				} else {
					// Multiple clips - group by clip ID
					headerLine := fmt.Sprintf("Renditions (%d clips):", clipCount)
					fmt.Printf("│ %-*s │\n", boxWidth-2, headerLine)

					// Sort clip IDs for consistent output
					var sortedClips []string
					for clipID := range clipRenditions {
						sortedClips = append(sortedClips, clipID)
					}
					sort.Strings(sortedClips)

					for _, clipID := range sortedClips {
						descSet := clipRenditions[clipID]
						// Show truncated clip ID as header
						shortClip := clipID
						if len(shortClip) > 12 {
							shortClip = shortClip[:12] + "…"
						}
						clipHeader := fmt.Sprintf("Clip %s:", shortClip)
						fmt.Printf("│   %-*s │\n", boxWidth-4, clipHeader)

						var rendList []string
						for desc := range descSet {
							rendList = append(rendList, desc)
						}
						sortRenditionsByBitrate(rendList)
						for _, desc := range rendList {
							fmt.Printf("│     • %-*s │\n", boxWidth-8, desc)
						}
					}
				}
			}

			if i < len(keys)-1 {
				fmt.Printf("├%s┤\n", strings.Repeat("─", boxWidth))
			}
		}
		fmt.Printf("└%s┘\n", strings.Repeat("─", boxWidth))
	}

	// Print DASH keys first, then HLS keys
	printKeyGroup(dashKeys, "📺 DASH (Widevine/PlayReady):")
	printKeyGroup(hlsKeys, "📱 HLS (FairPlay):")

	// Show renditions with no key if any (excluding subtitles/VTT)
	if noKeyClips, exists := renditionsByKeyAndClip["(no key)"]; exists && len(noKeyClips) > 0 {
		var rendList []string
		for _, descSet := range noKeyClips {
			for desc := range descSet {
				// Skip subtitle tracks (wvtt, stpp, ttml, etc.)
				descLower := strings.ToLower(desc)
				if strings.Contains(descLower, "vtt") || strings.Contains(descLower, "stpp") ||
					strings.Contains(descLower, "ttml") || strings.Contains(descLower, "subtitle") ||
					strings.Contains(descLower, "caption") {
					continue
				}
				rendList = append(rendList, desc)
			}
		}
		if len(rendList) > 0 {
			fmt.Printf("\n📺 Unencrypted Renditions:\n")
			sortRenditionsByBitrate(rendList)
			for _, desc := range rendList {
				fmt.Printf("  • %s\n", desc)
			}
		}
	}

	// Show vault verification summary
	vaultCount := 0
	kmsCount := 0
	missingCount := 0
	for _, detail := range uniqueKeyMap {
		if detail.InVault {
			vaultCount++
		} else if detail.InKMS {
			kmsCount++
		} else {
			missingCount++
		}
	}
	if len(uniqueKeyMap) > 0 {
		fmt.Printf("\n")
		if vaultCount > 0 {
			fmt.Printf("✓ Vault: %d/%d keys verified\n", vaultCount, len(uniqueKeyMap))
		}
		if kmsCount > 0 {
			fmt.Printf("✓ KMS: %d/%d keys verified\n", kmsCount, len(uniqueKeyMap))
		}
		if missingCount > 0 {
			fmt.Printf("✗ Missing: %d/%d keys not found\n", missingCount, len(uniqueKeyMap))
		}
	}

	// Show markdown clipboard status at the end
	if globalMarkdownOutput {
		if markdownErr != nil {
			fmt.Printf("\n⚠️  Failed to copy markdown to clipboard: %v\n", markdownErr)
		} else {
			fmt.Printf("\n📋 Markdown copied to clipboard!\n")
		}
	}
}

// AnalysisStats holds counters from manifest analysis
type AnalysisStats struct {
	Analyzed    int
	Encrypted   int
	FairPlay    int
	Widevine    int
	InVault     int
	InKMS       int
	Mismatches  int
	MissingKeys int
}

// analyzeManifestFully does all analysis work and returns results (no shared state modification)
func analyzeManifestFully(analysis *MediaAnalysis, manifestPath string, envConfig EnvironmentConfig, keyFiles []string) (
	map[string]KeyDetail, []RenditionSummary, AnalysisStats,
) {
	keyDetails := make(map[string]KeyDetail)
	var renditions []RenditionSummary
	var stats AnalysisStats

	// Extract clip ID from manifest path if not already set
	clipIDFromPath := extractClipIDFromPath(manifestPath)
	if analysis.ClipID == "" || analysis.ClipID == "unknown" {
		analysis.ClipID = clipIDFromPath
	}

	// Handle HLS master manifests
	if analysis.MediaType == "HLS" && analysis.EncryptionMethod == "Master Manifest" {
		hlsStreamMap := make(map[string]HLSStreamInfo)
		for _, stream := range analysis.HLSStreams {
			hlsStreamMap[stream.Path] = stream
		}

		for _, refManifest := range analysis.ReferencedManifests {
			refLower := strings.ToLower(refManifest)
			if strings.Contains(refLower, "-cc.") || strings.Contains(refLower, "_cc.") ||
				strings.Contains(refLower, "-sub.") || strings.Contains(refLower, "_sub.") ||
				strings.Contains(refLower, "/cc/") || strings.Contains(refLower, "/sub/") ||
				strings.Contains(refLower, "subtitle") || strings.Contains(refLower, "caption") {
				continue
			}

			var refPath string
			if isURL(manifestPath) || isS3URL(manifestPath) {
				baseURL := manifestPath[:strings.LastIndex(manifestPath, "/")+1]
				refPath = baseURL + refManifest
			} else {
				refPath = filepath.Join(filepath.Dir(manifestPath), refManifest)
				if _, err := os.Stat(refPath); os.IsNotExist(err) {
					continue
				}
			}

			refAnalysis, err := analyzeHLSManifest(refPath, envConfig)
			if err != nil {
				continue
			}

			if refAnalysis.ClipID == "" || refAnalysis.ClipID == "unknown" {
				refAnalysis.ClipID = clipIDFromPath
			}

			for _, keyFile := range keyFiles {
				if strings.Contains(keyFile, "keyfile") || strings.HasSuffix(keyFile, ".key") {
					fileSize, ivLength, err := analyzeKeyFile(keyFile)
					if err == nil {
						refAnalysis.KeyFileSize = fileSize
						refAnalysis.IVLength = ivLength
					}
					break
				}
			}

			refAnalysis.KeyType = determineKeyType(refAnalysis)

			var hlsDesc string
			if streamInfo, exists := hlsStreamMap[refManifest]; exists && streamInfo.Height > 0 {
				bandwidthKbps := streamInfo.Bandwidth / 1000
				hlsDesc = formatResolutionDescription(streamInfo.Height, streamInfo.Codecs, bandwidthKbps)
			} else if streamInfo, exists := hlsStreamMap[refManifest]; exists && streamInfo.Bandwidth > 0 {
				bandwidthKbps := streamInfo.Bandwidth / 1000
				hlsDesc = formatCodecDescription(streamInfo.Codecs, bandwidthKbps)
			} else {
				hlsDesc = extractHLSRenditionDescription(refManifest)
			}

			if refAnalysis.EncryptionMethod != "" && refAnalysis.EncryptionMethod != "ClearKey" && refAnalysis.EncryptionMethod != "AES-128" {
				renditions = append(renditions, RenditionSummary{
					Description: hlsDesc,
					KeyID:       refAnalysis.KeyID,
					ClipID:      refAnalysis.ClipID,
				})
			}

			if refAnalysis.EncryptionMethod == "ClearKey" || refAnalysis.EncryptionMethod == "AES-128" {
				continue
			}

			if refAnalysis.KeyID != "" {
				stats.Analyzed++
				if refAnalysis.EncryptionMethod == "SAMPLE-AES (FairPlay)" {
					stats.FairPlay++
					stats.Encrypted++
				} else if strings.Contains(refAnalysis.EncryptionMethod, "Widevine") || strings.Contains(refAnalysis.EncryptionMethod, "CENC") {
					stats.Widevine++
					stats.Encrypted++
				} else if refAnalysis.EncryptionMethod != "None" {
					stats.Encrypted++
				}

				collectKeyDetails(refAnalysis, keyDetails, &stats)
			}
		}
		return keyDetails, renditions, stats
	}

	// Handle DASH and single HLS manifests
	if analysis.EncryptionMethod == "ClearKey" || analysis.EncryptionMethod == "AES-128" {
		return keyDetails, renditions, stats
	}

	if analysis.MediaType == "DASH" && len(analysis.Representations) > 0 {
		for _, rep := range analysis.Representations {
			var desc string
			bandwidthKbps := rep.Bandwidth / 1000
			if rep.Height > 0 {
				desc = formatResolutionDescription(rep.Height, rep.Codecs, bandwidthKbps)
			} else if rep.Codecs != "" {
				desc = formatCodecDescription(rep.Codecs, bandwidthKbps)
			} else {
				desc = fmt.Sprintf("ID:%s (%d kbps)", rep.ID, bandwidthKbps)
			}
			renditions = append(renditions, RenditionSummary{
				Description: desc,
				KeyID:       rep.KeyID,
				ClipID:      analysis.ClipID,
			})
		}
	}

	if analysis.KeyID != "" {
		stats.Analyzed++
		if analysis.EncryptionMethod == "SAMPLE-AES (FairPlay)" {
			stats.FairPlay++
			stats.Encrypted++
		} else if strings.Contains(analysis.EncryptionMethod, "Widevine") || strings.Contains(analysis.EncryptionMethod, "CENC") {
			stats.Widevine++
			stats.Encrypted++
		} else if analysis.EncryptionMethod != "None" {
			stats.Encrypted++
		}

		collectKeyDetails(analysis, keyDetails, &stats)
	}

	return keyDetails, renditions, stats
}

// collectKeyDetails extracts key details from analysis into a map
func collectKeyDetails(analysis *MediaAnalysis, keyDetails map[string]KeyDetail, stats *AnalysisStats) {
	if analysis.KeyExistsInVault {
		stats.InVault++
		if analysis.MediaType == "DASH" && len(analysis.AllVaultKeyInfo) > 0 && len(analysis.AllKeyIDs) > 0 {
			for _, keyID := range analysis.AllKeyIDs {
				if vaultInfo, exists := analysis.AllVaultKeyInfo[keyID]; exists {
					var labels []string
					if labelList, ok := vaultInfo["labels"].([]interface{}); ok {
						for _, label := range labelList {
							if labelStr, ok := label.(string); ok {
								labels = append(labels, labelStr)
							}
						}
					}
					if _, exists := keyDetails[keyID]; !exists {
						keyDetails[keyID] = KeyDetail{
							KID:              keyID,
							Labels:           labels,
							IV:               analysis.IVLength,
							EncryptionMethod: analysis.EncryptionMethod,
							InVault:          true,
							InKMS:            false,
						}
					}
				}
			}
		} else if analysis.VaultKeyInfo != nil {
			var labels []string
			if labelList, ok := analysis.VaultKeyInfo["labels"].([]interface{}); ok {
				for _, label := range labelList {
					if labelStr, ok := label.(string); ok {
						labels = append(labels, labelStr)
					}
				}
			}
			if _, exists := keyDetails[analysis.KeyID]; !exists {
				keyDetails[analysis.KeyID] = KeyDetail{
					KID:              analysis.KeyID,
					Labels:           labels,
					IV:               analysis.IVLength,
					EncryptionMethod: analysis.EncryptionMethod,
					InVault:          true,
					InKMS:            false,
				}
			}
		}
	} else if analysis.KeyExistsInKMS {
		stats.InKMS++
		if analysis.MediaType == "DASH" && len(analysis.AllKeyIDs) > 0 {
			for _, keyID := range analysis.AllKeyIDs {
				if _, exists := keyDetails[keyID]; !exists {
					keyDetails[keyID] = KeyDetail{
						KID:              keyID,
						Labels:           []string{},
						IV:               analysis.IVLength,
						EncryptionMethod: analysis.EncryptionMethod,
						InVault:          false,
						InKMS:            true,
					}
				}
			}
		} else if analysis.KeyID != "" {
			if _, exists := keyDetails[analysis.KeyID]; !exists {
				keyDetails[analysis.KeyID] = KeyDetail{
					KID:              analysis.KeyID,
					Labels:           []string{},
					IV:               analysis.IVLength,
					EncryptionMethod: analysis.EncryptionMethod,
					InVault:          false,
					InKMS:            true,
				}
			}
		}
	} else {
		stats.MissingKeys++
		if analysis.MediaType == "DASH" && len(analysis.AllKeyIDs) > 0 {
			for _, keyID := range analysis.AllKeyIDs {
				if _, exists := keyDetails[keyID]; !exists {
					keyDetails[keyID] = KeyDetail{
						KID:              keyID,
						Labels:           []string{},
						IV:               analysis.IVLength,
						EncryptionMethod: analysis.EncryptionMethod,
						InVault:          false,
						InKMS:            analysis.KeyExistsInKMS,
					}
				}
			}
		} else if analysis.KeyID != "" {
			if _, exists := keyDetails[analysis.KeyID]; !exists {
				keyDetails[analysis.KeyID] = KeyDetail{
					KID:              analysis.KeyID,
					Labels:           []string{},
					IV:               analysis.IVLength,
					EncryptionMethod: analysis.EncryptionMethod,
					InVault:          false,
					InKMS:            analysis.KeyExistsInKMS,
				}
			}
		}
	}
}

func main() {
	// Command line flags
	var (
		environment     = flag.String("env", "nonprd", "environment to use (preprd, nonprd, prd)")
		kubectlContext  = flag.String("kubectl-context", "", "kubectl context to use (auto-detected if not specified)")
		vaultMethod     = flag.String("vault-method", "", "vault authentication method (auto-detected if not specified)")
		namespace       = flag.String("namespace", "", "kubernetes namespace to check (overrides environment default)")
		skipVault       = flag.Bool("skip-vault", false, "skip vault authentication and key validation")
		skipKubectl     = flag.Bool("skip-kubectl", false, "skip kubectl context setup and use fallback methods")
		verbosity       = flag.Int("v", 0, "verbosity level: 0=summary only (default), 1=normal, 2=detailed")
		playMedia       = flag.Bool("play", false, "attempt to play the DRM-encrypted file using ffplay")
		awsProfile      = flag.String("aws-profile", "", "AWS profile to use for S3 access (e.g., main-tier4)")
		numWorkers      = flag.Int("workers", 5, "number of concurrent workers for analyzing manifests")
		includeSubclips = flag.Bool("subclips", false, "include subclip folders (0-10, 10-20, etc.) instead of just 0-end")
		markdownOutput  = flag.Bool("md", true, "copy markdown summary to clipboard (use -md=false to disable)")
	)
	flag.Parse()

	// Set global AWS profile override
	awsProfileOverride = *awsProfile

	// Set global subclips flag
	globalIncludeSubclips = *includeSubclips

	// Set global markdown output flag
	globalMarkdownOutput = *markdownOutput

	if len(flag.Args()) < 1 {
		fmt.Println("Usage: go run analyze_media_keys.go [flags] <directory_or_url>")
		fmt.Println("")
		fmt.Println("Flags:")
		fmt.Println("  -env string")
		fmt.Println("        environment to use (preprd, nonprd, prd) (default \"nonprd\")")
		fmt.Println("  -v int")
		fmt.Println("        verbosity level: 0=summary only (default), 1=normal, 2=detailed")
		fmt.Println("  -kubectl-context string")
		fmt.Println("        kubectl context to use (auto-detected if not specified)")
		fmt.Println("  -vault-method string")
		fmt.Println("        vault authentication method (auto-detected if not specified)")
		fmt.Println("  -namespace string")
		fmt.Println("        kubernetes namespace to check (overrides environment default)")
		fmt.Println("  -skip-vault")
		fmt.Println("        skip vault authentication and key validation")
		fmt.Println("  -skip-kubectl")
		fmt.Println("        skip kubectl context setup and use fallback methods")
		fmt.Println("  -play")
		fmt.Println("        attempt to play the DRM-encrypted file using ffplay")
		fmt.Println("  -aws-profile string")
		fmt.Println("        AWS profile to use for S3 access (e.g., main-tier4)")
		fmt.Println("  -workers int")
		fmt.Println("        number of concurrent workers for analyzing manifests (default 5)")
		fmt.Println("  -subclips")
		fmt.Println("        include subclip folders (0-10, 10-20, etc.) instead of just 0-end")
		fmt.Println("  -md")
		fmt.Println("        output markdown format and copy to clipboard")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  go run analyze_media_keys.go ./media_files/")
		fmt.Println("  go run analyze_media_keys.go -env=preprd https://example.com/master.m3u8")
		fmt.Println("  go run analyze_media_keys.go -env=nonprd -kubectl-context=nonprd https://example.com/master.m3u8")
		fmt.Println("  go run analyze_media_keys.go -env=prd -kubectl-context=prod -vault-method=aws https://example.com/master.m3u8")
		fmt.Println("")
		fmt.Println("This script analyzes both HLS (.m3u8) and DASH (.mpd) files")
		fmt.Println("and provides comprehensive key analysis for both formats.")
		fmt.Println("Supports local directories, individual files, and HTTP/HTTPS URLs.")
		fmt.Println("")
		fmt.Println("Features:")
		fmt.Println("  • HTTP/HTTPS URL support")
		fmt.Println("  • S3 URL support (uses AWS SDK for Go)")
		fmt.Println("  • kubectl integration for utility clip detection")
		fmt.Println("  • Vault CLI integration for key validation")
		fmt.Println("  • Production configuration checking")
		fmt.Println("")
		fmt.Println("S3 Examples:")
		fmt.Println("  go run analyze_media_keys.go s3://bucket-name/path/to/manifest.mpd")
		fmt.Println("  go run analyze_media_keys.go s3://my-bucket/media/master.m3u8")
		fmt.Println("  go run analyze_media_keys.go s3://my-bucket/media/clip/")
		fmt.Println("  go run analyze_media_keys.go s3://my-bucket/  # analyzes all manifests in bucket")
		fmt.Println("")
		fmt.Println("Note: S3 support requires AWS credentials to be configured.")
		fmt.Println("Set credentials via environment variables, ~/.aws/credentials, or IAM role.")
		fmt.Println("S3 URLs can point to a single manifest file or a prefix/folder to analyze all manifests.")
		os.Exit(1)
	}

	path := flag.Args()[0]

	// Set global verbosity
	globalVerbosity = *verbosity

	// Set global manifest path for markdown output
	globalManifestPath = path

	// Auto-detect AWS profile based on S3 bucket name
	if isS3URL(path) {
		autoSetAWSProfile(path)
	}

	// Get environment configuration
	envConfig := getEnvironmentConfig(*environment)

	// Override namespace if specified
	if *namespace != "" {
		envConfig.Namespace = *namespace
	}

	if *verbosity > 0 {
		fmt.Printf("🔍 Analyzing Media files in: %s\n", path)
		fmt.Printf("🌍 Environment: %s (namespace: %s)\n", envConfig.Name, envConfig.Namespace)
		fmt.Println(strings.Repeat("=", 60))
	}

	// Setup infrastructure access (only show output if verbosity >= 2)
	if *verbosity >= 2 {
		fmt.Printf("\n🔧 Setting up infrastructure access...\n")
	}

	// Setup kubectl context
	if !*skipKubectl {
		if *kubectlContext != "" {
			if *verbosity >= 2 {
				fmt.Printf("🔧 Using specified kubectl context: %s\n", *kubectlContext)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cmd := exec.CommandContext(ctx, "kubectl", "config", "use-context", *kubectlContext)
			err := cmd.Run()
			cancel()
			if err != nil {
				if *verbosity >= 1 {
					fmt.Printf("⚠️  Failed to switch to kubectl context %s: %v\n", *kubectlContext, err)
				}
			}
		} else {
			// Automatically switch context based on environment
			if err := setupKubectlContext(envConfig.Name); err != nil {
				if *verbosity >= 1 {
					fmt.Printf("⚠️  kubectl setup failed: %v\n", err)
					fmt.Printf("   Will use fallback methods for utility clip detection\n")
				}
			}
		}
		if *verbosity >= 2 {
			fmt.Printf("🔧 Will check namespace: %s\n", envConfig.Namespace)
		}
	} else {
		if *verbosity >= 2 {
			fmt.Printf("⏭️  Skipping kubectl setup (--skip-kubectl flag)\n")
		}
	}

	// Setup vault authentication
	if !*skipVault {
		// Set the VAULT_ADDR environment variable based on the environment
		if *verbosity >= 2 {
			fmt.Printf("🔐 Setting Vault server: %s\n", envConfig.VaultServer)
		}
		os.Setenv("VAULT_ADDR", envConfig.VaultServer)

		if *vaultMethod != "" {
			if *verbosity >= 2 {
				fmt.Printf("🔐 Using specified vault method: %s\n", *vaultMethod)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cmd := exec.CommandContext(ctx, "vault", "auth", "-method="+*vaultMethod)
			cmd.Env = append(os.Environ(), "VAULT_ADDR="+envConfig.VaultServer)
			err := cmd.Run()
			cancel()
			if err != nil {
				if *verbosity >= 1 {
					fmt.Printf("⚠️  Failed to authenticate with vault using %s: %v\n", *vaultMethod, err)
				}
			}
		} else {
			if err := setupVaultAuth(); err != nil {
				if *verbosity >= 1 {
					fmt.Printf("⚠️  Vault setup failed: %v\n", err)
					fmt.Printf("   Will skip key validation in Vault\n")
				}
			}
		}
	} else {
		if *verbosity >= 2 {
			fmt.Printf("⏭️  Skipping vault setup (--skip-vault flag)\n")
		}
	}

	if *verbosity > 0 {
		fmt.Printf("\n")
	}

	// Start spinner for verbosity 0 (summary mode)
	var spinner *Spinner
	if *verbosity == 0 {
		spinner = NewSpinner("Analyzing manifests...")
		spinner.Start()
	}

	// Find media manifest files
	manifestFiles, err := findMediaFiles(path)
	if err != nil {
		if spinner != nil {
			spinner.Stop()
		}
		fmt.Printf("\n❌ File not found or not accessible: %s\n", path)
		fmt.Printf("   Error: %v\n", err)
		os.Exit(1)
	}

	// Find key files (only for local directories, not URLs or S3)
	var keyFiles []string
	if !isURL(path) && !isS3URL(path) {
		keyFiles, err = findKeyFiles(path)
		if err != nil {
			fmt.Printf("❌ Error finding key files: %v\n", err)
			os.Exit(1)
		}
	}

	if *verbosity >= 1 {
		fmt.Printf("📁 Found %d media files and %d key files\n", len(manifestFiles), len(keyFiles))
	} else if len(manifestFiles) == 0 {
		// Even in quiet mode, report if no files found
		fmt.Printf("❌ Error: No media files found\n")
		os.Exit(1)
	}

	// Summary stats for verbosity level 0
	var (
		totalAnalyzed    = 0
		totalEncrypted   = 0
		totalFairPlay    = 0
		totalWidevine    = 0
		totalInVault     = 0
		totalInKMS       = 0
		totalMismatches  = 0
		totalMissingKeys = 0
	)
	uniqueKeyMap := make(map[string]KeyDetail) // Track unique keys to avoid duplicates
	var renditionSummaries []RenditionSummary  // Track renditions for summary
	var uniqueKeyMapMu sync.Mutex              // Mutex for concurrent access

	// Use concurrent processing for verbosity 0 (summary mode) with multiple files
	useConcurrent := *verbosity == 0 && len(manifestFiles) > 1 && *numWorkers > 1

	if useConcurrent {
		// Concurrent processing with worker pool
		type workItem struct {
			index        int
			manifestPath string
		}

		workChan := make(chan workItem, len(manifestFiles))
		var wg sync.WaitGroup
		var processedCount int64

		// Start workers
		workerCount := *numWorkers
		if workerCount > len(manifestFiles) {
			workerCount = len(manifestFiles)
		}

		for w := 0; w < workerCount; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for work := range workChan {
					manifestPath := work.manifestPath

					// Update spinner with progress (atomic increment)
					count := atomic.AddInt64(&processedCount, 1)
					if spinner != nil {
						shortPath := manifestPath
						if len(shortPath) > 40 {
							shortPath = "..." + shortPath[len(shortPath)-37:]
						}
						spinner.Update(fmt.Sprintf("Analyzing %d/%d (%d workers): %s", count, len(manifestFiles), workerCount, shortPath))
					}

					var analysis *MediaAnalysis
					var err error

					// Determine file type and analyze accordingly
					if strings.HasSuffix(manifestPath, ".m3u8") {
						analysis, err = analyzeHLSManifest(manifestPath, envConfig)
					} else if strings.HasSuffix(manifestPath, ".mpd") {
						analysis, err = analyzeDASHManifest(manifestPath, envConfig)
					} else {
						continue
					}

					if err != nil {
						continue
					}

					// Do ALL analysis work OUTSIDE the lock (including HLS child manifests)
					// This collects results without holding the mutex
					localKeyDetails, localRenditions, localStats := analyzeManifestFully(
						analysis, manifestPath, envConfig, keyFiles)

					// Only update shared state inside the lock (fast operation)
					uniqueKeyMapMu.Lock()
					for kid, detail := range localKeyDetails {
						if _, exists := uniqueKeyMap[kid]; !exists {
							uniqueKeyMap[kid] = detail
						}
					}
					renditionSummaries = append(renditionSummaries, localRenditions...)
					totalAnalyzed += localStats.Analyzed
					totalEncrypted += localStats.Encrypted
					totalFairPlay += localStats.FairPlay
					totalWidevine += localStats.Widevine
					totalInVault += localStats.InVault
					totalInKMS += localStats.InKMS
					totalMismatches += localStats.Mismatches
					totalMissingKeys += localStats.MissingKeys
					uniqueKeyMapMu.Unlock()
				}
			}()
		}

		// Send work to workers
		for i, manifestPath := range manifestFiles {
			workChan <- workItem{index: i, manifestPath: manifestPath}
		}
		close(workChan)

		// Wait for all workers to finish
		wg.Wait()

		// Stop spinner and print summary
		if spinner != nil {
			spinner.Stop()
		}
		printSummary(uniqueKeyMap, renditionSummaries)
		return
	}

	// Sequential processing (for verbose modes or single file)
	for i, manifestPath := range manifestFiles {
		// Update spinner with current file
		if spinner != nil {
			shortPath := manifestPath
			if len(shortPath) > 50 {
				shortPath = "..." + shortPath[len(shortPath)-47:]
			}
			spinner.Update(fmt.Sprintf("Analyzing %d/%d: %s", i+1, len(manifestFiles), shortPath))
		}

		if *verbosity >= 1 {
			fmt.Printf("\n📋 Media File %d: %s\n", i+1, manifestPath)
			fmt.Println(strings.Repeat("-", 40))
		}

		var analysis *MediaAnalysis
		var err error

		// Determine file type and analyze accordingly
		if strings.HasSuffix(manifestPath, ".m3u8") {
			analysis, err = analyzeHLSManifest(manifestPath, envConfig)
		} else if strings.HasSuffix(manifestPath, ".mpd") {
			analysis, err = analyzeDASHManifest(manifestPath, envConfig)
		} else {
			if *verbosity >= 1 {
				fmt.Printf("❌ Unknown file type: %s\n", manifestPath)
			}
			continue
		}

		if err != nil {
			// Always show access/fetch errors even at verbosity 0 - these are critical
			errStr := err.Error()
			if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "403") ||
				strings.Contains(errStr, "404") || strings.Contains(errStr, "NoSuchKey") ||
				strings.Contains(errStr, "failed to fetch") {
				if spinner != nil {
					spinner.Stop()
				}
				fmt.Printf("❌ Error analyzing %s: %v\n", manifestPath, err)
				if spinner != nil {
					spinner = NewSpinner("Analyzing manifests...")
					spinner.Start()
				}
			} else if *verbosity >= 1 {
				fmt.Printf("❌ Error analyzing media file: %v\n", err)
			}
			continue
		}

		// Handle HLS master manifests
		if analysis.MediaType == "HLS" && analysis.EncryptionMethod == "Master Manifest" {
			// Build a map from path to stream info for quick lookup
			hlsStreamMap := make(map[string]HLSStreamInfo)
			for _, stream := range analysis.HLSStreams {
				hlsStreamMap[stream.Path] = stream
			}

			if *verbosity >= 1 {
				fmt.Printf("🎯 HLS Master Manifest detected with %d referenced streams:\n", len(analysis.ReferencedManifests))
				for j, refManifest := range analysis.ReferencedManifests {
					fmt.Printf("  %d. %s\n", j+1, refManifest)
				}
				fmt.Printf("\n🔍 Analyzing referenced HLS manifests:\n")
			}
			for j, refManifest := range analysis.ReferencedManifests {
				// Skip subtitle/CC manifests - they don't have encryption keys
				refLower := strings.ToLower(refManifest)
				if strings.Contains(refLower, "-cc.") || strings.Contains(refLower, "_cc.") ||
					strings.Contains(refLower, "-sub.") || strings.Contains(refLower, "_sub.") ||
					strings.Contains(refLower, "/cc/") || strings.Contains(refLower, "/sub/") ||
					strings.Contains(refLower, "subtitle") || strings.Contains(refLower, "caption") {
					continue
				}

				// Construct full path to referenced manifest
				var refPath string
				if isURL(manifestPath) || isS3URL(manifestPath) {
					// For URLs and S3 URLs, construct the full URL
					baseURL := manifestPath[:strings.LastIndex(manifestPath, "/")+1]
					refPath = baseURL + refManifest
				} else {
					// For local files, use filepath.Join
					refPath = filepath.Join(filepath.Dir(manifestPath), refManifest)
					if _, err := os.Stat(refPath); os.IsNotExist(err) {
						if *verbosity >= 1 {
							fmt.Printf("  ❌ Referenced manifest not found: %s\n", refPath)
						}
						continue
					}
				}

				refAnalysis, err := analyzeHLSManifest(refPath, envConfig)
				if err != nil {
					if *verbosity >= 1 {
						fmt.Printf("  ❌ Error analyzing %s: %v\n", refManifest, err)
					}
					continue
				}

				// Try to find corresponding key file
				var keyFilePath string
				for _, keyFile := range keyFiles {
					if strings.Contains(keyFile, "keyfile") || strings.HasSuffix(keyFile, ".key") {
						keyFilePath = keyFile
						break
					}
				}

				// Analyze key file if found
				if keyFilePath != "" {
					fileSize, ivLength, err := analyzeKeyFile(keyFilePath)
					if err != nil {
						if *verbosity >= 1 {
							fmt.Printf("  ❌ Error analyzing key file: %v\n", err)
						}
					} else {
						refAnalysis.KeyFileSize = fileSize
						refAnalysis.IVLength = ivLength
					}
				}

				// Determine key type
				refAnalysis.KeyType = determineKeyType(refAnalysis)

				// Collect HLS rendition for summary (even for non-DRM to show complete picture)
				var hlsDesc string
				if streamInfo, exists := hlsStreamMap[refManifest]; exists && streamInfo.Height > 0 {
					// Use resolution-based description like DASH
					bandwidthKbps := streamInfo.Bandwidth / 1000
					hlsDesc = formatResolutionDescription(streamInfo.Height, streamInfo.Codecs, bandwidthKbps)
				} else if streamInfo, exists := hlsStreamMap[refManifest]; exists && streamInfo.Bandwidth > 0 {
					// Use bandwidth-based description if no resolution
					bandwidthKbps := streamInfo.Bandwidth / 1000
					hlsDesc = formatCodecDescription(streamInfo.Codecs, bandwidthKbps)
				} else {
					// Fallback to filename-based description
					hlsDesc = extractHLSRenditionDescription(refManifest)
				}
				if refAnalysis.EncryptionMethod != "" && refAnalysis.EncryptionMethod != "ClearKey" && refAnalysis.EncryptionMethod != "AES-128" {
					renditionSummaries = append(renditionSummaries, RenditionSummary{
						Description: hlsDesc,
						KeyID:       refAnalysis.KeyID,
						ClipID:      refAnalysis.ClipID,
					})
				}

				// Skip detailed output for non-DRM content (ClearKey, AES-128)
				if refAnalysis.EncryptionMethod == "ClearKey" || refAnalysis.EncryptionMethod == "AES-128" {
					if *verbosity >= 1 {
						fmt.Printf("\n  📋 Referenced Manifest %d: %s - 🔓 Skipping non-DRM (%s)\n", j+1, refManifest, refAnalysis.EncryptionMethod)
					}
					continue
				}

				// Print header and results for DRM content
				if *verbosity >= 1 {
					fmt.Printf("\n  📋 Referenced Manifest %d: %s\n", j+1, refManifest)
					fmt.Printf("  %s\n", strings.Repeat("-", 30))
					fmt.Printf("  🔑 Key URI: %s\n", refAnalysis.KeyURI)
					fmt.Printf("  🆔 Key ID: %s\n", refAnalysis.KeyID)
					fmt.Printf("  📎 Clip ID: %s\n", refAnalysis.ClipID)
					fmt.Printf("  🔐 Encryption: %s\n", refAnalysis.EncryptionMethod)
					fmt.Printf("  📏 Key File Size: %d bytes\n", refAnalysis.KeyFileSize)
					fmt.Printf("  🔢 IV Length: %d bytes\n", refAnalysis.IVLength)
					fmt.Printf("  🏷️  Key Type: %s\n", refAnalysis.KeyType)
					fmt.Printf("  ⚡ Utility Clip: %t (source: %s)\n", refAnalysis.IsUtilityClip, refAnalysis.UtilityClipSource)
				}

				// Key validation for referenced manifests
				if refAnalysis.KeyID != "" {
					totalAnalyzed++
					if refAnalysis.EncryptionMethod == "SAMPLE-AES (FairPlay)" {
						totalFairPlay++
						totalEncrypted++
					} else if strings.Contains(refAnalysis.EncryptionMethod, "Widevine") || strings.Contains(refAnalysis.EncryptionMethod, "CENC") {
						totalWidevine++
						totalEncrypted++
					} else if refAnalysis.EncryptionMethod != "None" {
						totalEncrypted++
					}

					if refAnalysis.KeyExistsInVault {
						totalInVault++
						// Collect key details for summary
						if refAnalysis.VaultKeyInfo != nil {
							var labels []string
							if labelList, ok := refAnalysis.VaultKeyInfo["labels"].([]interface{}); ok {
								for _, label := range labelList {
									if labelStr, ok := label.(string); ok {
										labels = append(labels, labelStr)
									}
								}
							}
							if _, exists := uniqueKeyMap[refAnalysis.KeyID]; !exists {
								uniqueKeyMap[refAnalysis.KeyID] = KeyDetail{
									KID:              refAnalysis.KeyID,
									Labels:           labels,
									IV:               refAnalysis.IVLength,
									EncryptionMethod: refAnalysis.EncryptionMethod,
									InVault:          true,
									InKMS:            false,
								}
							}
						}
						if *verbosity >= 1 {
							fmt.Printf("  🔐 Key in Vault: ✅ Found\n")
						}
						// Check for encryption method / label mismatch
						if refAnalysis.VaultKeyInfo != nil {
							if labels, ok := refAnalysis.VaultKeyInfo["labels"].([]interface{}); ok {
								hasWidevine := false
								hasFairPlay := false
								for _, label := range labels {
									if labelStr, ok := label.(string); ok {
										switch labelStr {
										case "widevine":
											hasWidevine = true
										case "fairplay":
											hasFairPlay = true
										}
									}
								}
								// Validate encryption method matches labels (always show mismatches)
								if refAnalysis.EncryptionMethod == "SAMPLE-AES (FairPlay)" && hasWidevine && !hasFairPlay {
									totalMismatches++
									fmt.Printf("  ⚠️  MISMATCH: FairPlay encryption but key has 'widevine' label!\n")
								} else if strings.Contains(refAnalysis.EncryptionMethod, "Widevine") && hasFairPlay && !hasWidevine {
									totalMismatches++
									fmt.Printf("  ⚠️  MISMATCH: Widevine encryption but key has 'fairplay' label!\n")
								}
							}
						}
					} else if refAnalysis.KeyExistsInKMS {
						totalInKMS++
						// Collect key details for summary (KMS keys)
						if _, exists := uniqueKeyMap[refAnalysis.KeyID]; !exists {
							uniqueKeyMap[refAnalysis.KeyID] = KeyDetail{
								KID:              refAnalysis.KeyID,
								Labels:           []string{},
								IV:               refAnalysis.IVLength,
								EncryptionMethod: refAnalysis.EncryptionMethod,
								InVault:          false,
								InKMS:            true,
							}
						}
						if *verbosity >= 1 {
							fmt.Printf("  🔐 Key in KMS: ✅ Found\n")
							if refAnalysis.KMSKeyInfo != nil {
								if kmsURL, ok := refAnalysis.KMSKeyInfo["kms_url"].(string); ok {
									fmt.Printf("  📋 KMS URL: %s\n", kmsURL)
								}
							}
						}
					} else {
						totalMissingKeys++
						// Still add to key details for summary even if not found
						if _, exists := uniqueKeyMap[refAnalysis.KeyID]; !exists {
							uniqueKeyMap[refAnalysis.KeyID] = KeyDetail{
								KID:              refAnalysis.KeyID,
								Labels:           []string{},
								IV:               refAnalysis.IVLength,
								EncryptionMethod: refAnalysis.EncryptionMethod,
								InVault:          false,
								InKMS:            false,
							}
						}
						if *verbosity >= 1 {
							fmt.Printf("  🔐 Key in Vault: ❌ Not found\n")
							fmt.Printf("  🔐 Key in KMS: ❌ Not found\n")
						}
					}
				}

				// Print hex dump of key file if found
				if keyFilePath != "" && *verbosity >= 2 {
					fmt.Printf("  📄 Hex dump of key file (first 16 bytes):\n")
					err := printHexDump(keyFilePath, 16)
					if err != nil {
						fmt.Printf("  ❌ Error printing hex dump: %v\n", err)
					}
				}

				// Summary
				if *verbosity >= 1 {
					fmt.Printf("  📊 Summary: ")
					if refAnalysis.EncryptionMethod == "SAMPLE-AES (FairPlay)" && refAnalysis.IVLength == 16 {
						fmt.Printf("✅ FairPlay utility clip using SD key with 16-byte IV\n")
					} else if refAnalysis.EncryptionMethod == "SAMPLE-AES (FairPlay)" {
						fmt.Printf("⚠️  FairPlay clip - check IV length configuration\n")
					} else if refAnalysis.EncryptionMethod == "ClearKey" {
						fmt.Printf("ℹ️  ClearKey encryption with local key file\n")
					} else if refAnalysis.EncryptionMethod == "AES-128" {
						fmt.Printf("ℹ️  AES-128 encryption with URI-based key\n")
					} else {
						fmt.Printf("ℹ️  %s encryption detected\n", refAnalysis.EncryptionMethod)
					}
				}
			}
			continue
		}

		// Try to find corresponding key file for HLS
		var keyFilePath string
		if analysis.MediaType == "HLS" {
			for _, keyFile := range keyFiles {
				// Look for key file that might correspond to this manifest
				if strings.Contains(keyFile, "keyfile") || strings.HasSuffix(keyFile, ".key") {
					keyFilePath = keyFile
					break
				}
			}
		}

		// Analyze key file if found
		if keyFilePath != "" {
			fileSize, ivLength, err := analyzeKeyFile(keyFilePath)
			if err != nil {
				if *verbosity >= 1 {
					fmt.Printf("❌ Error analyzing key file: %v\n", err)
				}
			} else {
				analysis.KeyFileSize = fileSize
				analysis.IVLength = ivLength
			}
		}

		// Determine key type
		analysis.KeyType = determineKeyType(analysis)

		// Skip detailed output for non-DRM content (ClearKey, AES-128)
		if analysis.EncryptionMethod == "ClearKey" || analysis.EncryptionMethod == "AES-128" {
			if *verbosity >= 1 {
				fmt.Printf("🔓 Skipping non-DRM content (%s)\n", analysis.EncryptionMethod)
			}
			continue
		}

		// Print results for DRM content
		if *verbosity >= 1 {
			fmt.Printf("📺 Media Type: %s\n", analysis.MediaType)
			if analysis.KeyURI != "" {
				fmt.Printf("🔑 Key URI: %s\n", analysis.KeyURI)
			}

			// For DASH DRM, show all Key IDs; for HLS show single Key ID
			if analysis.MediaType == "DASH" && len(analysis.AllKeyIDs) > 0 {
				if len(analysis.AllKeyIDs) == 1 {
					fmt.Printf("🆔 Key ID: %s\n", analysis.AllKeyIDs[0])
				} else {
					fmt.Printf("🆔 Key IDs (%d total):\n", len(analysis.AllKeyIDs))
					for i, keyID := range analysis.AllKeyIDs {
						fmt.Printf("   %d. %s\n", i+1, keyID)
					}
				}
			} else {
				fmt.Printf("🆔 Key ID: %s\n", analysis.KeyID)
			}

			fmt.Printf("📎 Clip ID: %s\n", analysis.ClipID)
			fmt.Printf("🔐 Encryption: %s\n", analysis.EncryptionMethod)

			// Show Key File Size only for HLS (non-DRM or if key file exists)
			if analysis.MediaType == "HLS" && analysis.KeyFileSize > 0 {
				fmt.Printf("📏 Key File Size: %d bytes\n", analysis.KeyFileSize)
			}

			// Show IV Length for all DRM types
			if analysis.IVLength > 0 {
				fmt.Printf("🔢 IV Length: %d bytes\n", analysis.IVLength)
			}

			fmt.Printf("🏷️  Key Type: %s\n", analysis.KeyType)
			fmt.Printf("⚡ Utility Clip: %t (source: %s)\n", analysis.IsUtilityClip, analysis.UtilityClipSource)
		}

		// Key validation
		if analysis.KeyID != "" {
			totalAnalyzed++
			if analysis.EncryptionMethod == "SAMPLE-AES (FairPlay)" {
				totalFairPlay++
				totalEncrypted++
			} else if strings.Contains(analysis.EncryptionMethod, "Widevine") || strings.Contains(analysis.EncryptionMethod, "CENC") {
				totalWidevine++
				totalEncrypted++
			} else if analysis.EncryptionMethod != "None" {
				totalEncrypted++
			}

			if analysis.KeyExistsInVault {
				totalInVault++
				// Collect key details for summary
				// For DASH with multiple keys, use AllVaultKeyInfo to get individual labels
				if analysis.MediaType == "DASH" && len(analysis.AllVaultKeyInfo) > 0 && len(analysis.AllKeyIDs) > 0 {
					for _, keyID := range analysis.AllKeyIDs {
						if vaultInfo, exists := analysis.AllVaultKeyInfo[keyID]; exists {
							var labels []string
							if labelList, ok := vaultInfo["labels"].([]interface{}); ok {
								for _, label := range labelList {
									if labelStr, ok := label.(string); ok {
										labels = append(labels, labelStr)
									}
								}
							}
							if _, exists := uniqueKeyMap[keyID]; !exists {
								uniqueKeyMap[keyID] = KeyDetail{
									KID:              keyID,
									Labels:           labels,
									IV:               analysis.IVLength,
									EncryptionMethod: analysis.EncryptionMethod,
									InVault:          true,
									InKMS:            false,
								}
							}
						}
					}
				} else if analysis.VaultKeyInfo != nil {
					// For HLS or single key, use VaultKeyInfo
					var labels []string
					if labelList, ok := analysis.VaultKeyInfo["labels"].([]interface{}); ok {
						for _, label := range labelList {
							if labelStr, ok := label.(string); ok {
								labels = append(labels, labelStr)
							}
						}
					}
					if _, exists := uniqueKeyMap[analysis.KeyID]; !exists {
						uniqueKeyMap[analysis.KeyID] = KeyDetail{
							KID:              analysis.KeyID,
							Labels:           labels,
							IV:               analysis.IVLength,
							EncryptionMethod: analysis.EncryptionMethod,
							InVault:          true,
							InKMS:            false,
						}
					}
				}
				if *verbosity >= 1 {
					fmt.Printf("🔐 Key in Vault: ✅ Found\n")
				}
				// Check for encryption method / label mismatch
				if analysis.VaultKeyInfo != nil {
					if labels, ok := analysis.VaultKeyInfo["labels"].([]interface{}); ok {
						hasWidevine := false
						hasFairPlay := false
						for _, label := range labels {
							if labelStr, ok := label.(string); ok {
								switch labelStr {
								case "widevine":
									hasWidevine = true
								case "fairplay":
									hasFairPlay = true
								}
							}
						}
						// Validate encryption method matches labels (always show mismatches)
						if analysis.EncryptionMethod == "SAMPLE-AES (FairPlay)" && hasWidevine && !hasFairPlay {
							totalMismatches++
							fmt.Printf("⚠️  MISMATCH: FairPlay encryption but key has 'widevine' label!\n")
						} else if strings.Contains(analysis.EncryptionMethod, "Widevine") && hasFairPlay && !hasWidevine {
							totalMismatches++
							fmt.Printf("⚠️  MISMATCH: Widevine encryption but key has 'fairplay' label!\n")
						}
					}
				}
			} else if analysis.KeyExistsInKMS {
				totalInKMS++
				// Collect key details for summary
				if analysis.MediaType == "DASH" && len(analysis.AllKeyIDs) > 0 {
					for _, keyID := range analysis.AllKeyIDs {
						if _, exists := uniqueKeyMap[keyID]; !exists {
							uniqueKeyMap[keyID] = KeyDetail{
								KID:              keyID,
								Labels:           []string{},
								IV:               analysis.IVLength,
								EncryptionMethod: analysis.EncryptionMethod,
								InVault:          false,
								InKMS:            true,
							}
						}
					}
				} else if analysis.KeyID != "" {
					if _, exists := uniqueKeyMap[analysis.KeyID]; !exists {
						uniqueKeyMap[analysis.KeyID] = KeyDetail{
							KID:              analysis.KeyID,
							Labels:           []string{},
							IV:               analysis.IVLength,
							EncryptionMethod: analysis.EncryptionMethod,
							InVault:          false,
							InKMS:            true,
						}
					}
				}
				if *verbosity >= 1 {
					fmt.Printf("🔐 Key in KMS: ✅ Found\n")
					if analysis.KMSKeyInfo != nil {
						if kmsURL, ok := analysis.KMSKeyInfo["kms_url"].(string); ok {
							fmt.Printf("📋 KMS URL: %s\n", kmsURL)
						}
					}
				}
			} else {
				totalMissingKeys++
				// Still add to key details for summary even if not found
				if analysis.MediaType == "DASH" && len(analysis.AllKeyIDs) > 0 {
					for _, keyID := range analysis.AllKeyIDs {
						if _, exists := uniqueKeyMap[keyID]; !exists {
							uniqueKeyMap[keyID] = KeyDetail{
								KID:              keyID,
								Labels:           []string{},
								IV:               analysis.IVLength,
								EncryptionMethod: analysis.EncryptionMethod,
								InVault:          false,
								InKMS:            analysis.KeyExistsInKMS,
							}
						}
					}
				} else if analysis.KeyID != "" {
					if _, exists := uniqueKeyMap[analysis.KeyID]; !exists {
						uniqueKeyMap[analysis.KeyID] = KeyDetail{
							KID:              analysis.KeyID,
							Labels:           []string{},
							IV:               analysis.IVLength,
							EncryptionMethod: analysis.EncryptionMethod,
							InVault:          false,
							InKMS:            analysis.KeyExistsInKMS,
						}
					}
				}
				if *verbosity >= 1 {
					fmt.Printf("🔐 Key in Vault: ❌ Not found\n")
					fmt.Printf("🔐 Key in KMS: ❌ Not found\n")
				}
			}
		}

		// Collect rendition summaries for the summary output
		if analysis.MediaType == "DASH" && len(analysis.Representations) > 0 {
			for _, rep := range analysis.Representations {
				var desc string
				bandwidthKbps := rep.Bandwidth / 1000
				if rep.Height > 0 {
					desc = formatResolutionDescription(rep.Height, rep.Codecs, bandwidthKbps)
				} else if rep.Codecs != "" {
					desc = formatCodecDescription(rep.Codecs, bandwidthKbps)
				} else {
					desc = fmt.Sprintf("ID:%s (%d kbps)", rep.ID, bandwidthKbps)
				}
				renditionSummaries = append(renditionSummaries, RenditionSummary{
					Description: desc,
					KeyID:       rep.KeyID,
					ClipID:      analysis.ClipID,
				})
			}
		}
		// Note: We don't add generic entries for standalone HLS child manifests
		// because they're typically already covered by master manifest analysis
		// and would just create duplicate "HLS (SAMPLE-AES)" entries without
		// useful resolution/bitrate info

		// Print DASH-specific information
		if analysis.MediaType == "DASH" && *verbosity >= 1 {
			// Print representation details with associated keys
			fmt.Printf("\n📊 Representations with Keys (%d total):\n", len(analysis.Representations))
			for j, rep := range analysis.Representations {
				fmt.Printf("  %d. ID: %s, %dx%d, %d kbps, %s",
					j+1, rep.ID, rep.Width, rep.Height, rep.Bandwidth/1000, rep.Codecs)
				if rep.KeyID != "" {
					fmt.Printf(" | Key: %s, IV: %d bytes", rep.KeyID, analysis.IVLength)
				}
				fmt.Printf("\n")
			}

			// Decode and display PSSH data
			if analysis.PSSHData != "" && *verbosity >= 2 {
				decodeBase64Data(analysis.PSSHData, "PSSH Data")
			}

			// Decode and display Pro data
			if analysis.ProData != "" && *verbosity >= 2 {
				decodeBase64Data(analysis.ProData, "PlayReady Pro Data")
			}
		}

		// Print hex dump of key file if found
		if keyFilePath != "" && *verbosity >= 2 {
			err := printHexDump(keyFilePath, 32)
			if err != nil {
				fmt.Printf("❌ Error printing hex dump: %v\n", err)
			}
		}

		// Summary - show key status and summary together (like FairPlay)
		if *verbosity >= 1 {
			switch analysis.MediaType {
			case "HLS":
				// HLS shows: Key in Vault + Summary line
				fmt.Printf("\n📊 Summary: ")
				if analysis.EncryptionMethod == "SAMPLE-AES (FairPlay)" && analysis.IVLength == 16 {
					fmt.Printf("✅ FairPlay utility clip using SD key with 16-byte IV\n")
				} else if analysis.EncryptionMethod == "SAMPLE-AES (FairPlay)" {
					fmt.Printf("⚠️  FairPlay clip - check IV length configuration\n")
				} else if analysis.EncryptionMethod == "ClearKey" {
					fmt.Printf("ℹ️  ClearKey encryption with local key file\n")
				} else if analysis.EncryptionMethod == "AES-128" {
					fmt.Printf("ℹ️  AES-128 encryption with URI-based key\n")
				} else {
					fmt.Printf("ℹ️  %s encryption detected\n", analysis.EncryptionMethod)
				}
			case "DASH":
				// DASH shows: Summary line (matching FairPlay format)
				fmt.Printf("\n📊 Summary: ")
				if (analysis.EncryptionMethod == "Widevine (CENC)" || analysis.EncryptionMethod == "PlayReady (CENC)" || analysis.EncryptionMethod == "CENC (Common Encryption)") && analysis.IVLength == 8 {
					if analysis.IsUtilityClip {
						fmt.Printf("✅ CENC utility clip using HD key with 8-byte IV\n")
					} else {
						fmt.Printf("✅ CENC clip using HD key with 8-byte IV\n")
					}
				} else if analysis.EncryptionMethod == "Widevine (CENC)" || analysis.EncryptionMethod == "PlayReady (CENC)" || analysis.EncryptionMethod == "CENC (Common Encryption)" {
					fmt.Printf("⚠️  CENC clip - check IV length configuration\n")
				} else {
					fmt.Printf("ℹ️  DASH encryption method: %s\n", analysis.EncryptionMethod)
				}
			}
		}

		// Play media if --play flag is set
		if *playMedia && analysis.MediaType != "" {
			if *verbosity >= 1 {
				fmt.Printf("\n🎬 Attempting to play media file...\n")
			}
			playMediaFile(manifestPath, analysis, envConfig, *verbosity)
		}
	}

	// Stop spinner and print verbosity 0 summary after analyzing all manifests
	if *verbosity == 0 {
		if spinner != nil {
			spinner.Stop()
		}
		printSummary(uniqueKeyMap, renditionSummaries)
	}
}
