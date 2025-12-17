package types

import (
	"encoding/xml"
	"testing"
)

func TestEnvironmentConfig(t *testing.T) {
	config := EnvironmentConfig{
		Name:          "nonprd",
		Namespace:     "nonprd-service-media-center",
		ConfigMapName: "configmap.service-media-center-utility-clip-ids",
		SecretName:    "secret.service-media-center",
		KMSEndpoint:   "https://service-video-kms-use1-1.nonprd.pluto.tv/v1",
		KMSToken:      "test-token",
		VaultPath:     "app/common/shared-encryption/nonprd",
		VaultServer:   "https://vault-nonprd.devops.pluto.tv",
		VaultKey:      "STATIC_ENCRYPTION_KEYS",
	}

	if config.Name != "nonprd" {
		t.Errorf("Name = %q, want %q", config.Name, "nonprd")
	}
	if config.Namespace != "nonprd-service-media-center" {
		t.Errorf("Namespace = %q, want %q", config.Namespace, "nonprd-service-media-center")
	}
	if config.ConfigMapName != "configmap.service-media-center-utility-clip-ids" {
		t.Errorf("ConfigMapName = %q, want %q", config.ConfigMapName, "configmap.service-media-center-utility-clip-ids")
	}
	if config.SecretName != "secret.service-media-center" {
		t.Errorf("SecretName = %q, want %q", config.SecretName, "secret.service-media-center")
	}
	if config.KMSEndpoint != "https://service-video-kms-use1-1.nonprd.pluto.tv/v1" {
		t.Errorf("KMSEndpoint = %q, want %q", config.KMSEndpoint, "https://service-video-kms-use1-1.nonprd.pluto.tv/v1")
	}
	if config.KMSToken != "test-token" {
		t.Errorf("KMSToken = %q, want %q", config.KMSToken, "test-token")
	}
	if config.VaultPath != "app/common/shared-encryption/nonprd" {
		t.Errorf("VaultPath = %q, want %q", config.VaultPath, "app/common/shared-encryption/nonprd")
	}
	if config.VaultServer != "https://vault-nonprd.devops.pluto.tv" {
		t.Errorf("VaultServer = %q, want %q", config.VaultServer, "https://vault-nonprd.devops.pluto.tv")
	}
	if config.VaultKey != "STATIC_ENCRYPTION_KEYS" {
		t.Errorf("VaultKey = %q, want %q", config.VaultKey, "STATIC_ENCRYPTION_KEYS")
	}
}

func TestMediaAnalysis(t *testing.T) {
	analysis := MediaAnalysis{
		MediaType:        "DASH",
		KeyID:            "00000000-1234-5678-9abc-def012345678",
		AllKeyIDs:        []string{"00000000-1234-5678-9abc-def012345678"},
		EncryptionMethod: "CENC (Common Encryption)",
		IVLength:         8,
		KeyExistsInVault: true,
	}

	if analysis.MediaType != "DASH" {
		t.Errorf("MediaType = %q, want %q", analysis.MediaType, "DASH")
	}
	if analysis.KeyID != "00000000-1234-5678-9abc-def012345678" {
		t.Errorf("KeyID = %q, want %q", analysis.KeyID, "00000000-1234-5678-9abc-def012345678")
	}
	if len(analysis.AllKeyIDs) != 1 {
		t.Errorf("AllKeyIDs length = %d, want %d", len(analysis.AllKeyIDs), 1)
	}
	if analysis.EncryptionMethod != "CENC (Common Encryption)" {
		t.Errorf("EncryptionMethod = %q, want %q", analysis.EncryptionMethod, "CENC (Common Encryption)")
	}
	if analysis.IVLength != 8 {
		t.Errorf("IVLength = %d, want %d", analysis.IVLength, 8)
	}
	if !analysis.KeyExistsInVault {
		t.Errorf("KeyExistsInVault = %v, want %v", analysis.KeyExistsInVault, true)
	}
}

func TestRepresentationInfo(t *testing.T) {
	rep := RepresentationInfo{
		ID:        "v1",
		Bandwidth: 5000000,
		Codecs:    "avc1.4d401f",
		Width:     1920,
		Height:    1080,
		KeyID:     "00000000-1234-5678-9abc-def012345678",
	}

	if rep.ID != "v1" {
		t.Errorf("ID = %q, want %q", rep.ID, "v1")
	}
	if rep.Bandwidth != 5000000 {
		t.Errorf("Bandwidth = %d, want %d", rep.Bandwidth, 5000000)
	}
	if rep.Codecs != "avc1.4d401f" {
		t.Errorf("Codecs = %q, want %q", rep.Codecs, "avc1.4d401f")
	}
	if rep.Width != 1920 {
		t.Errorf("Width = %d, want %d", rep.Width, 1920)
	}
	if rep.Height != 1080 {
		t.Errorf("Height = %d, want %d", rep.Height, 1080)
	}
	if rep.KeyID != "00000000-1234-5678-9abc-def012345678" {
		t.Errorf("KeyID = %q, want %q", rep.KeyID, "00000000-1234-5678-9abc-def012345678")
	}
}

func TestHLSStreamInfo(t *testing.T) {
	stream := HLSStreamInfo{
		Path:      "720p.m3u8",
		Bandwidth: 2500000,
		Width:     1280,
		Height:    720,
		Codecs:    "avc1.4d401e,mp4a.40.2",
	}

	if stream.Path != "720p.m3u8" {
		t.Errorf("Path = %q, want %q", stream.Path, "720p.m3u8")
	}
	if stream.Bandwidth != 2500000 {
		t.Errorf("Bandwidth = %d, want %d", stream.Bandwidth, 2500000)
	}
	if stream.Width != 1280 {
		t.Errorf("Width = %d, want %d", stream.Width, 1280)
	}
	if stream.Height != 720 {
		t.Errorf("Height = %d, want %d", stream.Height, 720)
	}
	if stream.Codecs != "avc1.4d401e,mp4a.40.2" {
		t.Errorf("Codecs = %q, want %q", stream.Codecs, "avc1.4d401e,mp4a.40.2")
	}
}

func TestKeyDetail(t *testing.T) {
	detail := KeyDetail{
		KID:              "00000000-1234-5678-9abc-def012345678",
		Labels:           []string{"hd-video", "widevine"},
		IV:               8,
		EncryptionMethod: "CENC (Common Encryption)",
		InVault:          true,
		InKMS:            false,
	}

	if detail.KID != "00000000-1234-5678-9abc-def012345678" {
		t.Errorf("KID = %q, want %q", detail.KID, "00000000-1234-5678-9abc-def012345678")
	}
	if len(detail.Labels) != 2 {
		t.Errorf("Labels length = %d, want %d", len(detail.Labels), 2)
	}
	if detail.IV != 8 {
		t.Errorf("IV = %d, want %d", detail.IV, 8)
	}
	if detail.EncryptionMethod != "CENC (Common Encryption)" {
		t.Errorf("EncryptionMethod = %q, want %q", detail.EncryptionMethod, "CENC (Common Encryption)")
	}
	if !detail.InVault {
		t.Error("InVault should be true")
	}
	if detail.InKMS {
		t.Error("InKMS should be false")
	}
}

func TestRenditionSummary(t *testing.T) {
	summary := RenditionSummary{
		Description: "HD 1080p H.264 (5000 kbps)",
		KeyID:       "00000000-1234-5678-9abc-def012345678",
		ClipID:      "622721e908d75d0007f44311",
	}

	if summary.Description != "HD 1080p H.264 (5000 kbps)" {
		t.Errorf("Description = %q, want %q", summary.Description, "HD 1080p H.264 (5000 kbps)")
	}
	if summary.KeyID != "00000000-1234-5678-9abc-def012345678" {
		t.Errorf("KeyID = %q, want %q", summary.KeyID, "00000000-1234-5678-9abc-def012345678")
	}
	if summary.ClipID != "622721e908d75d0007f44311" {
		t.Errorf("ClipID = %q, want %q", summary.ClipID, "622721e908d75d0007f44311")
	}
}

func TestManifestResult(t *testing.T) {
	result := ManifestResult{
		ManifestPath:     "/path/to/manifest.mpd",
		TotalAnalyzed:    10,
		TotalEncrypted:   8,
		TotalFairPlay:    4,
		TotalWidevine:    4,
		TotalInVault:     6,
		TotalInKMS:       2,
		TotalMismatches:  0,
		TotalMissingKeys: 0,
	}

	if result.ManifestPath != "/path/to/manifest.mpd" {
		t.Errorf("ManifestPath = %q, want %q", result.ManifestPath, "/path/to/manifest.mpd")
	}
	if result.TotalAnalyzed != 10 {
		t.Errorf("TotalAnalyzed = %d, want %d", result.TotalAnalyzed, 10)
	}
	if result.TotalEncrypted != 8 {
		t.Errorf("TotalEncrypted = %d, want %d", result.TotalEncrypted, 8)
	}
	if result.TotalFairPlay != 4 {
		t.Errorf("TotalFairPlay = %d, want %d", result.TotalFairPlay, 4)
	}
	if result.TotalWidevine != 4 {
		t.Errorf("TotalWidevine = %d, want %d", result.TotalWidevine, 4)
	}
	if result.TotalInVault != 6 {
		t.Errorf("TotalInVault = %d, want %d", result.TotalInVault, 6)
	}
	if result.TotalInKMS != 2 {
		t.Errorf("TotalInKMS = %d, want %d", result.TotalInKMS, 2)
	}
	if result.TotalMismatches != 0 {
		t.Errorf("TotalMismatches = %d, want %d", result.TotalMismatches, 0)
	}
	if result.TotalMissingKeys != 0 {
		t.Errorf("TotalMissingKeys = %d, want %d", result.TotalMissingKeys, 0)
	}
}

func TestAnalysisStats(t *testing.T) {
	stats := AnalysisStats{
		Analyzed:    100,
		Encrypted:   80,
		FairPlay:    40,
		Widevine:    40,
		InVault:     70,
		InKMS:       10,
		Mismatches:  2,
		MissingKeys: 0,
	}

	if stats.Analyzed != 100 {
		t.Errorf("Analyzed = %d, want %d", stats.Analyzed, 100)
	}
	if stats.Encrypted != 80 {
		t.Errorf("Encrypted = %d, want %d", stats.Encrypted, 80)
	}
	if stats.FairPlay+stats.Widevine != stats.Encrypted {
		t.Errorf("FairPlay(%d) + Widevine(%d) != Encrypted(%d)", stats.FairPlay, stats.Widevine, stats.Encrypted)
	}
	if stats.InVault != 70 {
		t.Errorf("InVault = %d, want %d", stats.InVault, 70)
	}
	if stats.InKMS != 10 {
		t.Errorf("InKMS = %d, want %d", stats.InKMS, 10)
	}
	if stats.Mismatches != 2 {
		t.Errorf("Mismatches = %d, want %d", stats.Mismatches, 2)
	}
	if stats.MissingKeys != 0 {
		t.Errorf("MissingKeys = %d, want %d", stats.MissingKeys, 0)
	}
}

func TestDASHManifestXMLParsing(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011">
  <Period id="1">
    <AdaptationSet id="1" contentType="video">
      <ContentProtection schemeIdUri="urn:mpeg:dash:mp4protection:2011" value="cenc" default_KID="00000000-1234-5678-9abc-def012345678"/>
      <ContentProtection schemeIdUri="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed">
        <pssh>SGVsbG8gV29ybGQ=</pssh>
      </ContentProtection>
      <Representation id="v1" bandwidth="5000000" codecs="avc1.4d401f" width="1920" height="1080"/>
      <Representation id="v2" bandwidth="2500000" codecs="avc1.4d401e" width="1280" height="720"/>
    </AdaptationSet>
    <AdaptationSet id="2" contentType="audio">
      <Representation id="a1" bandwidth="128000" codecs="mp4a.40.2"/>
    </AdaptationSet>
  </Period>
</MPD>`

	var manifest DASHManifest
	err := xml.Unmarshal([]byte(xmlData), &manifest)
	if err != nil {
		t.Fatalf("Failed to unmarshal DASH manifest: %v", err)
	}

	if len(manifest.Periods) != 1 {
		t.Errorf("Periods count = %d, want %d", len(manifest.Periods), 1)
	}

	period := manifest.Periods[0]
	if period.ID != "1" {
		t.Errorf("Period ID = %q, want %q", period.ID, "1")
	}

	if len(period.AdaptationSets) != 2 {
		t.Errorf("AdaptationSets count = %d, want %d", len(period.AdaptationSets), 2)
	}

	videoAdaptation := period.AdaptationSets[0]
	if videoAdaptation.ContentType != "video" {
		t.Errorf("ContentType = %q, want %q", videoAdaptation.ContentType, "video")
	}

	if len(videoAdaptation.ContentProtection) != 2 {
		t.Errorf("ContentProtection count = %d, want %d", len(videoAdaptation.ContentProtection), 2)
	}

	// Check first content protection (CENC)
	cp := videoAdaptation.ContentProtection[0]
	if cp.DefaultKID != "00000000-1234-5678-9abc-def012345678" {
		t.Errorf("DefaultKID = %q, want %q", cp.DefaultKID, "00000000-1234-5678-9abc-def012345678")
	}

	// Check Widevine PSSH
	wvCP := videoAdaptation.ContentProtection[1]
	if wvCP.PSSH != "SGVsbG8gV29ybGQ=" {
		t.Errorf("PSSH = %q, want %q", wvCP.PSSH, "SGVsbG8gV29ybGQ=")
	}

	// Check representations
	if len(videoAdaptation.Representations) != 2 {
		t.Errorf("Representations count = %d, want %d", len(videoAdaptation.Representations), 2)
	}

	rep := videoAdaptation.Representations[0]
	if rep.ID != "v1" {
		t.Errorf("Representation ID = %q, want %q", rep.ID, "v1")
	}
	if rep.Bandwidth != 5000000 {
		t.Errorf("Bandwidth = %d, want %d", rep.Bandwidth, 5000000)
	}
	if rep.Height != 1080 {
		t.Errorf("Height = %d, want %d", rep.Height, 1080)
	}
}

func TestContentProtection(t *testing.T) {
	cp := ContentProtection{
		Value:       "cenc",
		SchemeIDURI: "urn:mpeg:dash:mp4protection:2011",
		DefaultKID:  "00000000-1234-5678-9abc-def012345678",
		PSSH:        "base64encodedpssh",
		Pro:         "base64encodedpro",
	}

	if cp.Value != "cenc" {
		t.Errorf("Value = %q, want %q", cp.Value, "cenc")
	}
	if cp.SchemeIDURI != "urn:mpeg:dash:mp4protection:2011" {
		t.Errorf("SchemeIDURI = %q, want %q", cp.SchemeIDURI, "urn:mpeg:dash:mp4protection:2011")
	}
	if cp.DefaultKID != "00000000-1234-5678-9abc-def012345678" {
		t.Errorf("DefaultKID = %q, want %q", cp.DefaultKID, "00000000-1234-5678-9abc-def012345678")
	}
	if cp.PSSH != "base64encodedpssh" {
		t.Errorf("PSSH = %q, want %q", cp.PSSH, "base64encodedpssh")
	}
	if cp.Pro != "base64encodedpro" {
		t.Errorf("Pro = %q, want %q", cp.Pro, "base64encodedpro")
	}
}

func TestRepresentation(t *testing.T) {
	rep := Representation{
		ID:        "video_1080p",
		Bandwidth: 8000000,
		Codecs:    "avc1.640028",
		MimeType:  "video/mp4",
		Width:     1920,
		Height:    1080,
	}

	if rep.ID != "video_1080p" {
		t.Errorf("ID = %q, want %q", rep.ID, "video_1080p")
	}
	if rep.Bandwidth != 8000000 {
		t.Errorf("Bandwidth = %d, want %d", rep.Bandwidth, 8000000)
	}
	if rep.Codecs != "avc1.640028" {
		t.Errorf("Codecs = %q, want %q", rep.Codecs, "avc1.640028")
	}
	if rep.MimeType != "video/mp4" {
		t.Errorf("MimeType = %q, want %q", rep.MimeType, "video/mp4")
	}
	if rep.Width != 1920 {
		t.Errorf("Width = %d, want %d", rep.Width, 1920)
	}
	if rep.Height != 1080 {
		t.Errorf("Height = %d, want %d", rep.Height, 1080)
	}
}
