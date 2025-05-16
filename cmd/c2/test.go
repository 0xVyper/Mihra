package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/0xvyper/mihra/core/crypto"
	"github.com/0xvyper/mihra/core/security"
	"github.com/0xvyper/mihra/shell"
)

func TestCrypto(t *testing.T) {

	fmt.Println("Testing AES encryption/decryption...")

	originalData := []byte("This is a test message for AES encryption")
	passphrase := []byte("test-passphrase-123")

	encrypted, err := crypto.AESEncrypt(originalData, passphrase)
	if err != nil {
		t.Fatalf("AES encryption failed: %v", err)
	}

	decrypted, err := crypto.AESDecrypt(encrypted, passphrase)
	if err != nil {
		t.Fatalf("AES decryption failed: %v", err)
	}

	if string(decrypted) != string(originalData) {
		t.Fatalf("AES decryption result doesn't match original data")
	}

	fmt.Println("AES encryption/decryption test passed")

	fmt.Println("Testing RSA key generation and encryption/decryption...")

	publicKey, privateKey, err := crypto.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("RSA key generation failed: %v", err)
	}

	testData := []byte("This is a test message for RSA encryption")

	rsaEncrypted, err := crypto.RSAEncrypt(publicKey, testData)
	if err != nil {
		t.Fatalf("RSA encryption failed: %v", err)
	}

	rsaDecrypted, err := crypto.RSADecrypt(privateKey, rsaEncrypted)
	if err != nil {
		t.Fatalf("RSA decryption failed: %v", err)
	}

	if string(rsaDecrypted) != string(testData) {
		t.Fatalf("RSA decryption result doesn't match original data")
	}

	fmt.Println("RSA encryption/decryption test passed")
}
func TestSecurity(t *testing.T) {
	fmt.Println("Testing security manager...")

	secManager := security.NewSecurityManager()

	err := secManager.Initialize()
	if err != nil {
		t.Fatalf("Security manager initialization failed: %v", err)
	}

	status := secManager.GetSecurityStatus()
	fmt.Printf("Security status: %+v\n", status)

	recommendations := secManager.GetSecurityRecommendations()
	fmt.Println("Security recommendations:")
	for _, rec := range recommendations {
		fmt.Printf("- %s\n", rec)
	}

	fmt.Println("Security manager test passed")
}
func TestShell(t *testing.T) {
	fmt.Println("Testing shell functionality...")

	sh := shell.NewShell()

	output, err := sh.ExecuteCommand("echo 'Hello, World!'")
	if err != nil {
		t.Fatalf("Command execution failed: %v", err)
	}

	fmt.Printf("Command output: %s\n", output)

	cmd, args := sh.ParseCommand("ls -la /tmp")
	if cmd != "ls" || len(args) != 2 || args[0] != "-la" || args[1] != "/tmp" {
		t.Fatalf("Command parsing failed: got %s, %v", cmd, args)
	}

	testFile := "test_file.txt"
	testContent := "This is a test file"

	err = os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	files, err := sh.ListFiles("")
	if err != nil {
		t.Fatalf("Failed to list files: %v", err)
	}

	fmt.Println("Files in current directory:")
	for _, file := range files {
		fmt.Println(file)
	}

	os.Remove(testFile)

	fmt.Println("Shell functionality test passed")
}
func main() {

	fmt.Println("Running simplified C2 tests...")

	t := &testing.T{}

	TestCrypto(t)
	TestSecurity(t)
	TestShell(t)

	fmt.Println("All tests passed!")
}
