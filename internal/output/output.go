// Package output provides output formatting including spinner, summary, and markdown.
package output

import (
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/roddd/whichkey/internal/types"
)

// ManifestPath is the global manifest path for markdown output
var ManifestPath string

// MarkdownOutput indicates whether to generate markdown
var MarkdownOutput bool

// CopyToClipboard copies text to the system clipboard (macOS)
func CopyToClipboard(text string) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

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

// ExtractBitrateForSort extracts a numeric value from rendition description for sorting
func ExtractBitrateForSort(desc string) int {
	// Try to extract bitrate in kbps
	bitrateRegex := regexp.MustCompile(`(\d+)\s*kbps`)
	if matches := bitrateRegex.FindStringSubmatch(desc); len(matches) > 1 {
		val := 0
		fmt.Sscanf(matches[1], "%d", &val)
		return val
	}

	// Try to extract resolution and convert to approximate bitrate for sorting
	resRegex := regexp.MustCompile(`(\d+)p`)
	if matches := resRegex.FindStringSubmatch(desc); len(matches) > 1 {
		val := 0
		fmt.Sscanf(matches[1], "%d", &val)
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
			return val * 3
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

// SortRenditionsByBitrate sorts rendition descriptions by bitrate (lowest to highest)
func SortRenditionsByBitrate(rendList []string) {
	sort.Slice(rendList, func(i, j int) bool {
		return ExtractBitrateForSort(rendList[i]) < ExtractBitrateForSort(rendList[j])
	})
}

// SimplifyCodecName returns a human-readable codec name
func SimplifyCodecName(codecs string) string {
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

// FormatCodecDescription creates a human-readable description from codec and bitrate
func FormatCodecDescription(codecs string, bandwidthKbps int) string {
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

	// Video codecs
	codecName := SimplifyCodecName(codecs)
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

	return fmt.Sprintf("%s (%d kbps)", codecs, bandwidthKbps)
}

// FormatResolutionDescription creates a description with resolution, codec, and bitrate
func FormatResolutionDescription(height int, codecs string, bandwidthKbps int) string {
	codecName := SimplifyCodecName(codecs)
	quality := "SD"
	if height >= 720 {
		quality = "HD"
	}
	return fmt.Sprintf("%s %dp %s (%d kbps)", quality, height, codecName, bandwidthKbps)
}

// GenerateMarkdownSummary generates a markdown version of the summary
func GenerateMarkdownSummary(uniqueKeyMap map[string]types.KeyDetail, renditionsByKeyAndClip map[string]map[string]map[string]bool, clipCountByKey map[string]map[string]bool) string {
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
	pathLower := strings.ToLower(ManifestPath)
	isSpecificManifest := strings.HasSuffix(pathLower, ".mpd") || strings.HasSuffix(pathLower, ".m3u8")
	basePath := strings.TrimSuffix(ManifestPath, "/")

	// Helper to write a group of keys
	writeKeyGroup := func(keys []string, title string, manifestType string) {
		if len(keys) == 0 {
			return
		}

		// Write example URL for this section
		if isSpecificManifest {
			sb.WriteString(fmt.Sprintf("**Example:** `%s`\n\n", ManifestPath))
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
						SortRenditionsByBitrate(rendList)
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
						SortRenditionsByBitrate(rendList)
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

// PrintSummary prints the unique keys and rendition mappings grouped by key
func PrintSummary(uniqueKeyMap map[string]types.KeyDetail, renditions []types.RenditionSummary) {
	// Group renditions by key ID -> clip ID -> descriptions
	renditionsByKeyAndClip := make(map[string]map[string]map[string]bool)
	clipCountByKey := make(map[string]map[string]bool)

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
		if MarkdownOutput {
			var markdown string
			pathLower := strings.ToLower(ManifestPath)
			if strings.HasSuffix(pathLower, ".mpd") || strings.HasSuffix(pathLower, ".m3u8") {
				markdown = fmt.Sprintf("# Keys & Renditions\n\n**Example:** `%s`\n\nNo encrypted content found.\n", ManifestPath)
			} else {
				basePath := strings.TrimSuffix(ManifestPath, "/")
				markdown = fmt.Sprintf("# Keys & Renditions\n\n**Examples:**\n- DASH: `%s/dash/0-end/main.mpd`\n- HLS: `%s/hls/0-end/master.m3u8`\n\nNo encrypted content found.\n", basePath, basePath)
			}
			if err := CopyToClipboard(markdown); err != nil {
				fmt.Printf("\n⚠️  Failed to copy markdown to clipboard: %v\n", err)
			} else {
				fmt.Printf("\n📋 Markdown copied to clipboard!\n")
			}
		}
		return
	}

	// If markdown output is requested, generate it now (will copy at the end)
	var markdownErr error
	if MarkdownOutput {
		markdown := GenerateMarkdownSummary(uniqueKeyMap, renditionsByKeyAndClip, clipCountByKey)
		markdownErr = CopyToClipboard(markdown)
	}

	// First pass: calculate max width needed
	maxWidth := 0
	for _, kid := range sortedKeys {
		detail := uniqueKeyMap[kid]

		kidLine := "KID: " + detail.KID
		if len(kidLine) > maxWidth {
			maxWidth = len(kidLine)
		}

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

		if len(detail.Labels) > 0 {
			labelsLine := "Labels: " + strings.Join(detail.Labels, ", ")
			if len(labelsLine) > maxWidth {
				maxWidth = len(labelsLine)
			}
		}

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

	boxWidth := maxWidth + 2

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

			kidLine := "KID: " + detail.KID
			fmt.Printf("│ %-*s │\n", boxWidth-2, kidLine)

			location := "✗ Not found"
			if detail.InVault {
				location = "✓ Vault"
			} else if detail.InKMS {
				location = "✓ KMS"
			}
			detailLine := fmt.Sprintf("IV: %d bytes | %s | %s", detail.IV, detail.EncryptionMethod, location)
			fmt.Printf("│ %-*s │\n", boxWidth-2, detailLine)

			if len(detail.Labels) > 0 {
				labelsLine := "Labels: " + strings.Join(detail.Labels, ", ")
				fmt.Printf("│ %-*s │\n", boxWidth-2, labelsLine)
			}

			if clipRenditions, exists := renditionsByKeyAndClip[kid]; exists && len(clipRenditions) > 0 {
				clipCount := len(clipCountByKey[kid])

				if clipCount == 1 {
					fmt.Printf("│ %-*s │\n", boxWidth-2, "Renditions:")
					for _, descSet := range clipRenditions {
						var rendList []string
						for desc := range descSet {
							rendList = append(rendList, desc)
						}
						SortRenditionsByBitrate(rendList)
						for _, desc := range rendList {
							fmt.Printf("│   • %-*s │\n", boxWidth-6, desc)
						}
					}
				} else {
					headerLine := fmt.Sprintf("Renditions (%d clips):", clipCount)
					fmt.Printf("│ %-*s │\n", boxWidth-2, headerLine)

					var sortedClips []string
					for clipID := range clipRenditions {
						sortedClips = append(sortedClips, clipID)
					}
					sort.Strings(sortedClips)

					for _, clipID := range sortedClips {
						descSet := clipRenditions[clipID]
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
						SortRenditionsByBitrate(rendList)
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

	printKeyGroup(dashKeys, "📺 DASH (Widevine/PlayReady):")
	printKeyGroup(hlsKeys, "📱 HLS (FairPlay):")

	// Show renditions with no key if any
	if noKeyClips, exists := renditionsByKeyAndClip["(no key)"]; exists && len(noKeyClips) > 0 {
		var rendList []string
		for _, descSet := range noKeyClips {
			for desc := range descSet {
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
			SortRenditionsByBitrate(rendList)
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
	if MarkdownOutput {
		if markdownErr != nil {
			fmt.Printf("\n⚠️  Failed to copy markdown to clipboard: %v\n", markdownErr)
		} else {
			fmt.Printf("\n📋 Markdown copied to clipboard!\n")
		}
	}
}
