// Package analysis provides HLS and DASH manifest analysis.
package analysis

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zerogee00/whichkey/internal/aws"
	"github.com/zerogee00/whichkey/internal/k8s"
	"github.com/zerogee00/whichkey/internal/output"
	"github.com/zerogee00/whichkey/internal/types"
	"github.com/zerogee00/whichkey/internal/vault"
)

// Verbosity level for logging
var Verbosity int

// AnalyzeHLSManifest analyzes an HLS manifest file
func AnalyzeHLSManifest(manifestPath string, config types.EnvironmentConfig) (*types.MediaAnalysis, error) {
	var reader io.Reader
	var err error

	if aws.IsS3URL(manifestPath) {
		reader, err = aws.FetchS3Content(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch manifest from S3: %w", err)
		}
	} else if aws.IsURL(manifestPath) {
		reader, err = aws.FetchURLContent(manifestPath)
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
	var hlsStreams []types.HLSStreamInfo

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#EXT-X-STREAM-INF:") {
			isMasterManifest = true

			streamInfo := types.HLSStreamInfo{}

			if bwMatch := regexp.MustCompile(`BANDWIDTH=(\d+)`).FindStringSubmatch(line); len(bwMatch) > 1 {
				fmt.Sscanf(bwMatch[1], "%d", &streamInfo.Bandwidth)
			}

			if resMatch := regexp.MustCompile(`RESOLUTION=(\d+)x(\d+)`).FindStringSubmatch(line); len(resMatch) > 2 {
				fmt.Sscanf(resMatch[1], "%d", &streamInfo.Width)
				fmt.Sscanf(resMatch[2], "%d", &streamInfo.Height)
			}

			if codecMatch := regexp.MustCompile(`CODECS="([^"]+)"`).FindStringSubmatch(line); len(codecMatch) > 1 {
				streamInfo.Codecs = codecMatch[1]
			}

			if scanner.Scan() {
				refManifest := strings.TrimSpace(scanner.Text())
				if !strings.HasPrefix(refManifest, "#") && refManifest != "" {
					referencedManifests = append(referencedManifests, refManifest)
					streamInfo.Path = refManifest
					hlsStreams = append(hlsStreams, streamInfo)
				}
			}
		} else if strings.HasPrefix(line, "#EXT-X-KEY:") {
			uriRegex := regexp.MustCompile(`URI="([^"]+)"`)
			matches := uriRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				keyURI = matches[1]
			}

			if strings.Contains(line, "METHOD=SAMPLE-AES") {
				encryptionMethod = "SAMPLE-AES (FairPlay)"
			} else if strings.Contains(line, "METHOD=AES-128") {
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

	if isMasterManifest {
		return &types.MediaAnalysis{
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

	keyID, clipID := ParseKeyURI(keyURI)

	var isUtilityClip bool
	var utilitySource string
	var keyExistsInKMS bool
	var kmsKeyInfo map[string]interface{}
	var keyExistsInVault bool
	var vaultKeyInfo map[string]interface{}
	var ivLength int

	if encryptionMethod == "SAMPLE-AES (FairPlay)" || encryptionMethod == "Widevine (CENC)" || encryptionMethod == "PlayReady (CENC)" || encryptionMethod == "CENC (Common Encryption)" {
		isUtilityClip, utilitySource = k8s.IsUtilityClipID(clipID, config)

		if keyID != "" {
			if Verbosity >= 2 {
				fmt.Printf("🔐 Checking Vault for key metadata...\n")
			}
			vaultInfo, vaultErr := vault.GetKeyInfoFromVault(keyID, config)
			if vaultErr != nil {
				if Verbosity >= 2 {
					fmt.Printf("⚠️  Key not found in Vault: %v\n", vaultErr)
					fmt.Printf("   Trying KMS service as fallback...\n")
				}

				kmsExists, kmsInfo, kmsErr := vault.CheckKeyInKMS(keyID, config)
				if kmsErr != nil {
					if Verbosity >= 1 {
						fmt.Printf("⚠️  Key not found in KMS service: %v\n", kmsErr)
					}
				} else {
					keyExistsInKMS = kmsExists
					kmsKeyInfo = kmsInfo
					if Verbosity >= 2 {
						fmt.Printf("✅ Found key in KMS service\n")
					}
				}
			} else {
				keyExistsInVault = true
				vaultKeyInfo = vaultInfo
				if Verbosity >= 2 {
					fmt.Printf("✅ Found key metadata in Vault\n")
				}
			}
		}

		switch encryptionMethod {
		case "SAMPLE-AES (FairPlay)":
			ivLength = 16
		case "Widevine (CENC)", "PlayReady (CENC)", "CENC (Common Encryption)":
			ivLength = 8
		}
	} else {
		isUtilityClip = false
		utilitySource = "not applicable (non-DRM)"
	}

	return &types.MediaAnalysis{
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

// AnalyzeDASHManifest analyzes a DASH manifest file
func AnalyzeDASHManifest(manifestPath string, config types.EnvironmentConfig) (*types.MediaAnalysis, error) {
	var reader io.Reader
	var err error

	if aws.IsS3URL(manifestPath) {
		reader, err = aws.FetchS3Content(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch manifest from S3: %w", err)
		}
	} else if aws.IsURL(manifestPath) {
		reader, err = aws.FetchURLContent(manifestPath)
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

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest types.DASHManifest
	if err := xml.Unmarshal(content, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse DASH manifest: %w", err)
	}

	analysis := &types.MediaAnalysis{
		MediaType: "DASH",
	}

	allKeyIDs := make(map[string]bool)
	var representations []types.RepresentationInfo

	for _, period := range manifest.Periods {
		for _, adaptSet := range period.AdaptationSets {
			var keyID string
			var encMethod string
			var psshData, proData string

			for _, cp := range adaptSet.ContentProtection {
				if cp.DefaultKID != "" {
					keyID = vault.NormalizeKeyID(cp.DefaultKID)
					allKeyIDs[keyID] = true
				}

			schemeURI := strings.ToLower(cp.SchemeIDURI)
			// Widevine UUID: edef8ba9-79d6-4ace-a3c8-27dcd51d21ed
			// PlayReady UUID: 9a04f079-9840-4286-ab92-e65be0885f95
			if strings.Contains(schemeURI, "widevine") || strings.Contains(schemeURI, "edef8ba9") {
				encMethod = "CENC (Common Encryption)"
				if cp.PSSH != "" {
					psshData = cp.PSSH
				}
			} else if strings.Contains(schemeURI, "playready") || strings.Contains(schemeURI, "9a04f079") {
				encMethod = "CENC (Common Encryption)"
				if cp.Pro != "" {
					proData = cp.Pro
				}
			} else if strings.Contains(schemeURI, "cenc") {
				encMethod = "CENC (Common Encryption)"
			}
			}

			for _, rep := range adaptSet.Representations {
				repInfo := types.RepresentationInfo{
					ID:        rep.ID,
					Bandwidth: rep.Bandwidth,
					Codecs:    rep.Codecs,
					Width:     rep.Width,
					Height:    rep.Height,
					KeyID:     keyID,
				}
				representations = append(representations, repInfo)
			}

			if analysis.EncryptionMethod == "" {
				analysis.EncryptionMethod = encMethod
			}
			if analysis.PSSHData == "" {
				analysis.PSSHData = psshData
			}
			if analysis.ProData == "" {
				analysis.ProData = proData
			}
		}
	}

	var keyIDList []string
	for kid := range allKeyIDs {
		keyIDList = append(keyIDList, kid)
	}
	analysis.AllKeyIDs = keyIDList
	analysis.Representations = representations

	if len(keyIDList) > 0 {
		analysis.KeyID = keyIDList[0]
	}

	if analysis.EncryptionMethod == "" {
		analysis.EncryptionMethod = "None"
	} else {
		analysis.IVLength = 8

		allVaultKeyInfo := make(map[string]map[string]interface{})
		anyKeyInVault := false
		anyKeyInKMS := false

		for _, keyID := range keyIDList {
			if Verbosity >= 2 {
				fmt.Printf("🔐 Checking Vault for key: %s\n", keyID)
			}
			vaultInfo, vaultErr := vault.GetKeyInfoFromVault(keyID, config)
			if vaultErr == nil {
				anyKeyInVault = true
				allVaultKeyInfo[keyID] = vaultInfo
				if Verbosity >= 2 {
					fmt.Printf("✅ Found key in Vault: %s\n", keyID)
				}
			} else {
				if Verbosity >= 2 {
					fmt.Printf("⚠️  Key not found in Vault: %v\n", vaultErr)
					fmt.Printf("   Trying KMS service as fallback...\n")
				}
				kmsExists, _, kmsErr := vault.CheckKeyInKMS(keyID, config)
				if kmsErr != nil {
					if Verbosity >= 1 {
						fmt.Printf("⚠️  KMS check failed for key %s: %v\n", keyID, kmsErr)
					}
				} else if kmsExists {
					anyKeyInKMS = true
					if Verbosity >= 2 {
						fmt.Printf("✅ Found key in KMS service: %s\n", keyID)
					}
				} else {
					if Verbosity >= 1 {
						fmt.Printf("⚠️  Key not found in KMS service: %s\n", keyID)
					}
				}
			}
		}

		analysis.KeyExistsInVault = anyKeyInVault
		analysis.AllVaultKeyInfo = allVaultKeyInfo
		analysis.KeyExistsInKMS = anyKeyInKMS
	}

	return analysis, nil
}

// ParseKeyURI extracts key ID and clip ID from a key URI
func ParseKeyURI(uri string) (string, string) {
	keyIDRegex := regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	keyIDMatches := keyIDRegex.FindAllString(uri, -1)

	var keyID, clipID string
	for _, match := range keyIDMatches {
		normalized := vault.NormalizeKeyID(match)
		if strings.HasPrefix(normalized, "00000000") {
			keyID = match
		} else {
			if clipID == "" {
				clipID = match
			}
		}
	}

	if keyID == "" && len(keyIDMatches) > 0 {
		keyID = keyIDMatches[len(keyIDMatches)-1]
	}

	if clipID == "" {
		hexRegex := regexp.MustCompile(`/([0-9a-fA-F]{24})/`)
		if matches := hexRegex.FindStringSubmatch(uri); len(matches) > 1 {
			clipID = matches[1]
		}
	}

	return keyID, clipID
}

// ExtractClipIDFromPath extracts clip ID from manifest path
// Pre-compiled regex for hex string matching
var hexStringRegex = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func ExtractClipIDFromPath(manifestPath string) string {
	if idx := strings.Index(manifestPath, "/clip/"); idx != -1 {
		after := manifestPath[idx+6:]
		parts := strings.Split(after, "/")
		for _, part := range parts {
			if len(part) >= 24 && len(part) <= 25 {
				if hexStringRegex.MatchString(part) {
					return part
				}
			}
			if strings.Contains(part, "_") {
				subParts := strings.Split(part, "_")
				if len(subParts[0]) >= 24 {
					if hexStringRegex.MatchString(subParts[0]) {
						return subParts[0]
					}
				}
			}
		}
	}

	uuidRegex := regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	if matches := uuidRegex.FindAllString(manifestPath, -1); len(matches) > 0 {
		for _, match := range matches {
			if !strings.HasPrefix(strings.ToLower(match), "00000000") {
				return match
			}
		}
	}

	hexRegex := regexp.MustCompile(`/([0-9a-fA-F]{24,25})/`)
	if matches := hexRegex.FindStringSubmatch(manifestPath); len(matches) > 1 {
		return matches[1]
	}

	return "unknown"
}

// ExtractHLSRenditionDescription extracts rendition description from HLS manifest path
func ExtractHLSRenditionDescription(manifestPath string) string {
	fileName := filepath.Base(manifestPath)
	fileName = strings.TrimSuffix(fileName, filepath.Ext(fileName))

	codecTypes := map[string]string{
		"avc1": "H.264", "h264": "H.264",
		"hvc1": "HEVC", "hevc": "HEVC", "hev1": "HEVC",
		"mp4a": "AAC", "aac": "AAC",
		"ac-3": "AC-3", "ec-3": "E-AC-3",
	}

	for codec, name := range codecTypes {
		if strings.Contains(strings.ToLower(fileName), codec) {
			return fmt.Sprintf("%s stream", name)
		}
	}

	resolutions := []struct {
		pattern string
		quality string
	}{
		{"2160", "4K"},
		{"1080", "HD 1080p"},
		{"720", "HD 720p"},
		{"576", "SD 576p"},
		{"480", "SD 480p"},
		{"360", "SD 360p"},
		{"240", "SD 240p"},
	}

	for _, res := range resolutions {
		if strings.Contains(fileName, res.pattern) {
			return fmt.Sprintf("%s video", res.quality)
		}
	}

	if strings.Contains(strings.ToLower(fileName), "audio") {
		return "Audio stream"
	}

	return fileName
}

// FindMediaFiles finds manifest files in a directory
func FindMediaFiles(path string) ([]string, error) {
	if aws.IsS3URL(path) {
		return aws.ListS3Manifests(path, false)
	}

	var files []string
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".mpd" || ext == ".m3u8" {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

// CollectKeyDetails collects key details from analysis into maps
func CollectKeyDetails(analysis *types.MediaAnalysis, keyDetails map[string]types.KeyDetail, stats *types.AnalysisStats) {
	if analysis.MediaType == "DASH" && len(analysis.AllKeyIDs) > 0 {
		for _, keyID := range analysis.AllKeyIDs {
			if _, exists := keyDetails[keyID]; exists {
				continue
			}

			var labels []string
			if analysis.KeyExistsInVault && analysis.AllVaultKeyInfo != nil {
				if vaultInfo, exists := analysis.AllVaultKeyInfo[keyID]; exists {
					if labelList, ok := vaultInfo["labels"].([]interface{}); ok {
						for _, label := range labelList {
							if labelStr, ok := label.(string); ok {
								labels = append(labels, labelStr)
							}
						}
					}
				}
			}

			keyDetails[keyID] = types.KeyDetail{
				KID:              keyID,
				Labels:           labels,
				IV:               analysis.IVLength,
				EncryptionMethod: analysis.EncryptionMethod,
				InVault:          analysis.KeyExistsInVault,
				InKMS:            analysis.KeyExistsInKMS,
			}
		}
	} else if analysis.KeyID != "" {
		if _, exists := keyDetails[analysis.KeyID]; !exists {
			var labels []string
			if analysis.KeyExistsInVault && analysis.VaultKeyInfo != nil {
				if labelList, ok := analysis.VaultKeyInfo["labels"].([]interface{}); ok {
					for _, label := range labelList {
						if labelStr, ok := label.(string); ok {
							labels = append(labels, labelStr)
						}
					}
				}
			}

			keyDetails[analysis.KeyID] = types.KeyDetail{
				KID:              analysis.KeyID,
				Labels:           labels,
				IV:               analysis.IVLength,
				EncryptionMethod: analysis.EncryptionMethod,
				InVault:          analysis.KeyExistsInVault,
				InKMS:            analysis.KeyExistsInKMS,
			}
		}
	}

	if analysis.KeyExistsInVault {
		stats.InVault++
	} else if analysis.KeyExistsInKMS {
		stats.InKMS++
	}
}

// CollectRenditions collects rendition summaries from analysis
func CollectRenditions(analysis *types.MediaAnalysis, clipID string) []types.RenditionSummary {
	var renditions []types.RenditionSummary

	if analysis.MediaType == "DASH" && len(analysis.Representations) > 0 {
		for _, rep := range analysis.Representations {
			var desc string
			bandwidthKbps := rep.Bandwidth / 1000
			if rep.Height > 0 {
				desc = output.FormatResolutionDescription(rep.Height, rep.Codecs, bandwidthKbps)
			} else if rep.Codecs != "" {
				desc = output.FormatCodecDescription(rep.Codecs, bandwidthKbps)
			} else {
				desc = fmt.Sprintf("ID:%s (%d kbps)", rep.ID, bandwidthKbps)
			}
			renditions = append(renditions, types.RenditionSummary{
				Description: desc,
				KeyID:       rep.KeyID,
				ClipID:      clipID,
			})
		}
	}

	return renditions
}
