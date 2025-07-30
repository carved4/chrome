package credmanager

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"chrome-decrypt/pkg/credentials"
)

// Windows API structures and functions for Credential Manager
var (
	advapi32          = syscall.NewLazyDLL("advapi32.dll")
	procCredEnumerate = advapi32.NewProc("CredEnumerateW")
	procCredFree      = advapi32.NewProc("CredFree")
)

// Credential types
const (
	CRED_TYPE_GENERIC                 = 1
	CRED_TYPE_DOMAIN_PASSWORD         = 2
	CRED_TYPE_DOMAIN_CERTIFICATE      = 3
	CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 4
	CRED_TYPE_GENERIC_CERTIFICATE     = 5
	CRED_TYPE_DOMAIN_EXTENDED         = 6
	CRED_TYPE_MAXIMUM                 = 7
)

// Windows Credential structure (from wincred.h)
type winCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// Extractor implements the credentials.Extractor interface
type Extractor struct {
	verbose bool
}

// NewExtractor creates a new credential manager extractor
func NewExtractor(verbose bool) *Extractor {
	return &Extractor{verbose: verbose}
}

// Extract extracts passwords from Windows Credential Manager
func (e *Extractor) Extract() (interface{}, error) {
	if e.verbose {
		fmt.Println("[*] Extracting Windows Credential Manager passwords...")
	}

	var creds []credentials.Credential
	var credPtr uintptr
	var count uint32

	// Enumerate all credentials
	ret, _, _ := procCredEnumerate.Call(
		0,                            // Filter (NULL for all)
		0,                            // Flags
		uintptr(unsafe.Pointer(&count)), // Count
		uintptr(unsafe.Pointer(&credPtr)), // Credentials
	)

	if ret == 0 {
		return creds, fmt.Errorf("failed to enumerate credentials")
	}

	defer procCredFree.Call(credPtr)

	// Convert the array of credential pointers
	credArray := (*[1 << 20]*winCredential)(unsafe.Pointer(credPtr))[:count:count]

	for i := uint32(0); i < count; i++ {
		winCred := credArray[i]

		credential := credentials.Credential{
			Type:        e.getCredentialTypeName(winCred.Type),
			TargetName:  e.utf16PtrToString(winCred.TargetName),
			Comment:     e.utf16PtrToString(winCred.Comment),
			UserName:    e.utf16PtrToString(winCred.UserName),
			LastWritten: time.Unix(0, winCred.LastWritten.Nanoseconds()).Format(time.RFC3339),
			Persist:     e.getPersistTypeName(winCred.Persist),
		}

		// Extract password if available
		if winCred.CredentialBlobSize > 0 && winCred.CredentialBlob != nil {
			passwordBytes := (*[1 << 20]byte)(unsafe.Pointer(winCred.CredentialBlob))[:winCred.CredentialBlobSize:winCred.CredentialBlobSize]
			credential.Password = e.handlePasswordEncoding(passwordBytes)
		}

		creds = append(creds, credential)
	}

	if e.verbose {
		fmt.Printf("[+] Found %d credentials in Credential Manager\n", len(creds))
	}
	return creds, nil
}

// GetType returns the extractor type
func (e *Extractor) GetType() string {
	return "credential_manager"
}

// Helper functions
func (e *Extractor) utf16PtrToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}

	// Convert UTF-16 pointer to Go string
	var result []uint16
	for {
		char := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(len(result)*2)))
		if char == 0 {
			break
		}
		result = append(result, char)
	}

	return syscall.UTF16ToString(result)
}

func (e *Extractor) getCredentialTypeName(credType uint32) string {
	switch credType {
	case CRED_TYPE_GENERIC:
		return "Generic"
	case CRED_TYPE_DOMAIN_PASSWORD:
		return "Domain Password"
	case CRED_TYPE_DOMAIN_CERTIFICATE:
		return "Domain Certificate"
	case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
		return "Domain Visible Password"
	case CRED_TYPE_GENERIC_CERTIFICATE:
		return "Generic Certificate"
	case CRED_TYPE_DOMAIN_EXTENDED:
		return "Domain Extended"
	default:
		return fmt.Sprintf("Unknown (%d)", credType)
	}
}

func (e *Extractor) getPersistTypeName(persist uint32) string {
	switch persist {
	case 1:
		return "Session"
	case 2:
		return "Local Machine"
	case 3:
		return "Enterprise"
	default:
		return fmt.Sprintf("Unknown (%d)", persist)
	}
}

// handlePasswordEncoding handles various password encodings from Windows credentials
func (e *Extractor) handlePasswordEncoding(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Debug: print raw bytes if verbose
	if e.verbose && len(data) <= 50 {
		fmt.Printf("[DEBUG] Raw password bytes: %v (hex: %x)\n", data, data)
	}

	// Method 1: Try as plain UTF-8/ASCII first (many Windows passwords are stored this way)
	// Remove null bytes and check if it's readable
	var asciiResult []byte
	for _, b := range data {
		if b != 0 && b >= 32 && b <= 126 { // Printable ASCII range
			asciiResult = append(asciiResult, b)
		}
	}
	if len(asciiResult) > 0 {
		asciiStr := string(asciiResult)
		// Check if this looks like a reasonable password (no weird characters)
		if e.isReasonablePassword(asciiStr) {
			return asciiStr
		}
	}

	// Method 2: Try UTF-16LE decoding
	if len(data) >= 2 && len(data)%2 == 0 {
		utf16Data := make([]uint16, len(data)/2)
		for i := 0; i < len(utf16Data); i++ {
			// Little-endian byte order
			utf16Data[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
		}

		// Remove trailing null terminators
		for len(utf16Data) > 0 && utf16Data[len(utf16Data)-1] == 0 {
			utf16Data = utf16Data[:len(utf16Data)-1]
		}

		// Convert UTF-16 to string
		if len(utf16Data) > 0 {
			if decoded := syscall.UTF16ToString(utf16Data); decoded != "" && e.isReasonablePassword(decoded) {
				return decoded
			}
		}
	}

	// Method 3: Try UTF-16BE (big-endian)
	if len(data) >= 2 && len(data)%2 == 0 {
		utf16Data := make([]uint16, len(data)/2)
		for i := 0; i < len(utf16Data); i++ {
			// Big-endian byte order
			utf16Data[i] = uint16(data[i*2])<<8 | uint16(data[i*2+1])
		}

		// Remove trailing null terminators
		for len(utf16Data) > 0 && utf16Data[len(utf16Data)-1] == 0 {
			utf16Data = utf16Data[:len(utf16Data)-1]
		}

		// Convert UTF-16 to string
		if len(utf16Data) > 0 {
			if decoded := syscall.UTF16ToString(utf16Data); decoded != "" && e.isReasonablePassword(decoded) {
				return decoded
			}
		}
	}

	// If all decoding methods fail, return hex representation
	return fmt.Sprintf("[Encrypted/Binary: %x]", data)
}

// isReasonablePassword checks if a decoded string looks like a reasonable password
func (e *Extractor) isReasonablePassword(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	
	// Check if string contains mostly printable ASCII characters
	printableCount := 0
	for _, r := range s {
		if r >= 32 && r <= 126 {
			printableCount++
		}
	}
	
	// At least 80% of characters should be printable ASCII
	return float64(printableCount)/float64(len(s)) >= 0.8
}
