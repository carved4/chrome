package wifi

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"chrome-decrypt/pkg/credentials"
)

// Extractor implements the credentials.Extractor interface
type Extractor struct {
	verbose bool
}

// NewExtractor creates a new WiFi extractor
func NewExtractor(verbose bool) *Extractor {
	return &Extractor{verbose: verbose}
}

// Extract extracts WiFi network passwords
func (e *Extractor) Extract() (interface{}, error) {
	if e.verbose {
		fmt.Println("[*] Extracting WiFi passwords...")
	}

	var profiles []credentials.WiFiProfile

	// Get list of WiFi profiles
	cmd := exec.Command("netsh", "wlan", "show", "profiles")
	output, err := cmd.Output()
	if err != nil {
		return profiles, fmt.Errorf("failed to get WiFi profiles: %v", err)
	}

	// Parse profile names
	profileRegex := regexp.MustCompile(`All User Profile\s*:\s*(.+)`)
	matches := profileRegex.FindAllStringSubmatch(string(output), -1)

	for _, match := range matches {
		if len(match) > 1 {
			profileName := strings.TrimSpace(match[1])
			if profile := e.parseWiFiProfile(profileName); profile.SSID != "" {
				profiles = append(profiles, profile)
			}
		}
	}

	if e.verbose {
		fmt.Printf("[+] Found %d WiFi profiles\n", len(profiles))
	}
	return profiles, nil
}

// GetType returns the extractor type
func (e *Extractor) GetType() string {
	return "wifi_profiles"
}

// parseWiFiProfile parses WiFi profile details from netsh output
func (e *Extractor) parseWiFiProfile(profileName string) credentials.WiFiProfile {
	profile := credentials.WiFiProfile{
		SSID: profileName,
	}

	// Get detailed profile information
	cmd := exec.Command("netsh", "wlan", "show", "profile", profileName, "key=clear")
	output, err := cmd.Output()
	if err != nil {
		return profile
	}

	content := string(output)

	// Extract authentication and encryption
	if authMatch := regexp.MustCompile(`Authentication\s*:\s*(.+)`).FindStringSubmatch(content); len(authMatch) > 1 {
		profile.Authentication = strings.TrimSpace(authMatch[1])
	}

	if encMatch := regexp.MustCompile(`Cipher\s*:\s*(.+)`).FindStringSubmatch(content); len(encMatch) > 1 {
		profile.Encryption = strings.TrimSpace(encMatch[1])
	}

	// Extract password/key
	if keyMatch := regexp.MustCompile(`Key Content\s*:\s*(.+)`).FindStringSubmatch(content); len(keyMatch) > 1 {
		profile.Password = strings.TrimSpace(keyMatch[1])
	}

	// If no password found, try key material
	if profile.Password == "" {
		if keyMaterialMatch := regexp.MustCompile(`Key Material\s*:\s*(.+)`).FindStringSubmatch(content); len(keyMaterialMatch) > 1 {
			profile.KeyMaterial = strings.TrimSpace(keyMaterialMatch[1])
		}
	}

	return profile
}
