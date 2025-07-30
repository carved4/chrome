
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"chrome-decrypt/pkg/decrypt"
	"chrome-decrypt/pkg/coordinate"
)

func main() {
	var (
		verbose     = flag.Bool("verbose", false, "Enable verbose logging")
		outputPath  = flag.String("output", "", "Output directory for extracted data")
		extractCreds = flag.Bool("extract-creds", false, "Extract Windows credentials (Credential Manager, RDP, WiFi, Domain)")
		credsOnly   = flag.Bool("creds-only", false, "Only extract Windows credentials, skip browser data")
		win11Mode   = flag.Bool("win11-mode", false, "Enable Windows 11 compatibility mode (experimental)")
	)
	flag.Parse()

	if *outputPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("Failed to get home directory:", err)
		}
		*outputPath = filepath.Join(homeDir, "Desktop", "chrome_decrypt_output")
	}

	log.Printf("Starting extraction...")
	log.Printf("Output path: %s", *outputPath)
	log.Printf("Verbose mode: %v", *verbose)
	
	if *win11Mode {
		log.Printf("[INFO] Windows 11 compatibility mode enabled")
		log.Printf("[WARNING] Windows 11 App-Bound encryption may prevent browser data extraction")
		log.Printf("[TIP] Consider running as administrator or with browser closed")
	}

	// Extract Windows credentials if requested
	if *extractCreds || *credsOnly {
		log.Printf("[*] Extracting Windows credentials...")
		credsOutputPath := filepath.Join(*outputPath, "windows_credentials")
		if err := coordinate.RunCredentialExtraction(*verbose, credsOutputPath); err != nil {
			log.Printf("[-] Windows credential extraction failed: %v", err)
		} else {
			log.Printf("[+] Windows credential extraction completed!")
		}
	}

	// Skip browser extraction if creds-only mode
	if *credsOnly {
		log.Printf("Credential extraction completed successfully!")
		return
	}

	// Extract browser data
	log.Printf("[*] Extracting browser data...")
	if err := decrypt.RunDecryption(*verbose, *outputPath); err != nil {
		log.Fatal("Browser decryption failed:", err)
	}

	log.Printf("[+] Browser decryption completed successfully!")

	// Test HTTP client if requested

	log.Printf("All operations completed successfully!")
}
