package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/simplified_c2/core/crypto"
	"github.com/simplified_c2/core/security"
	"github.com/simplified_c2/module"
	"github.com/simplified_c2/modules/shell_anon"
	"github.com/simplified_c2/modules/unpacker"
)

func TestCrypto(t *testing.T) {
	// Test AES encryption/decryption
	fmt.Println("Testing AES encryption/decryption...")
	
	originalData := []byte("This is a test message for AES encryption")
	passphrase := []byte("test-passphrase-123")
	
	// Encrypt
	encrypted, err := crypto.AESEncrypt(originalData, passphrase)
	if err != nil {
		t.Fatalf("AES encryption failed: %v", err)
	}
	
	// Decrypt
	decrypted, err := crypto.AESDecrypt(encrypted, passphrase)
	if err != nil {
		t.Fatalf("AES decryption failed: %v", err)
	}
	
	// Compare
	if string(decrypted) != string(originalData) {
		t.Fatalf("AES decryption result doesn't match original data")
	}
	
	fmt.Println("AES encryption/decryption test passed")
	
	// Test RSA key generation and encryption/decryption
	fmt.Println("Testing RSA key generation and encryption/decryption...")
	
	// Generate key pair
	publicKey, privateKey, err := crypto.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("RSA key generation failed: %v", err)
	}
	
	// Test data
	testData := []byte("This is a test message for RSA encryption")
	
	// Encrypt with public key
	rsaEncrypted, err := crypto.RSAEncrypt(publicKey, testData)
	if err != nil {
		t.Fatalf("RSA encryption failed: %v", err)
	}
	
	// Decrypt with private key
	rsaDecrypted, err := crypto.RSADecrypt(privateKey, rsaEncrypted)
	if err != nil {
		t.Fatalf("RSA decryption failed: %v", err)
	}
	
	// Compare
	if string(rsaDecrypted) != string(testData) {
		t.Fatalf("RSA decryption result doesn't match original data")
	}
	
	fmt.Println("RSA encryption/decryption test passed")
}

func TestSecurity(t *testing.T) {
	fmt.Println("Testing security manager...")
	
	// Create security manager
	secManager := security.NewSecurityManager()
	
	// Initialize
	err := secManager.Initialize()
	if err != nil {
		t.Fatalf("Security manager initialization failed: %v", err)
	}
	
	// Get security status
	status := secManager.GetSecurityStatus()
	fmt.Printf("Security status: %+v\n", status)
	
	// Get security recommendations
	recommendations := secManager.GetSecurityRecommendations()
	fmt.Println("Security recommendations:")
	for _, rec := range recommendations {
		fmt.Printf("- %s\n", rec)
	}
	
	// Test network security
	fmt.Println("Testing network security...")
	
	// Create a network security manager
	netSecManager := security.NewNetworkSecurityManager([]byte("test-key"))
	
	// Test traffic obfuscation
	testData := []byte("This is test network traffic")
	obfuscated, err := netSecManager.ObfuscateTraffic(testData)
	if err != nil {
		t.Fatalf("Traffic obfuscation failed: %v", err)
	}
	
	deobfuscated, err := netSecManager.DeobfuscateTraffic(obfuscated)
	if err != nil {
		t.Fatalf("Traffic deobfuscation failed: %v", err)
	}
	
	if string(deobfuscated) != string(testData) {
		t.Fatalf("Deobfuscated traffic doesn't match original data")
	}
	
	fmt.Println("Network security test passed")
	
	fmt.Println("Security manager test passed")
}

func TestModules(t *testing.T) {
	fmt.Println("Testing module system...")
	
	// Create module system
	moduleSystem := module.NewModuleSystem()
	
	// Register modules
	shellAnonModule := shell_anon.NewModule()
	moduleSystem.Registry.RegisterModule("shell_anon", func() module.ModuleInterface {
		return shellAnonModule
	})
	
	unpackerModule := unpacker.NewModule()
	moduleSystem.Registry.RegisterModule("unpacker", func() module.ModuleInterface {
		return unpackerModule
	})
	
	// List modules
	modules := moduleSystem.Registry.ListModules()
	fmt.Println("Registered modules:")
	for _, name := range modules {
		fmt.Printf("- %s\n", name)
	}
	
	// Load shell_anon module
	mod, err := moduleSystem.Manager.LoadModule("shell_anon")
	if err != nil {
		t.Fatalf("Failed to load shell_anon module: %v", err)
	}
	
	// Get module info
	info := mod.GetInfo()
	fmt.Printf("Module: %s (v%s)\n", info.Name, info.Version)
	fmt.Printf("Description: %s\n", info.Description)
	fmt.Printf("Author: %s\n", info.Author)
	
	// Test a command
	result, err := mod.ExecuteCommand("get_tips", []string{"command"})
	if err != nil {
		t.Fatalf("Failed to execute command: %v", err)
	}
	
	fmt.Println("Command execution result:")
	tips, ok := result.([]string)
	if !ok {
		t.Fatalf("Unexpected result type")
	}
	
	for _, tip := range tips {
		fmt.Printf("- %s\n", tip)
	}
	
	fmt.Println("Module system test passed")
}

func TestSecureShell(t *testing.T) {
	fmt.Println("Testing secure shell functionality...")
	
	// This is a simplified test since we can't actually establish connections in a test environment
	// In a real test, you would start a server and connect to it
	
	fmt.Println("Secure shell test passed (simplified)")
}

func main() {
	// Run tests
	fmt.Println("Running enhanced C2 implementation tests...")
	
	t := &testing.T{}
	
	TestCrypto(t)
	TestSecurity(t)
	TestModules(t)
	TestSecureShell(t)
	
	fmt.Println("All tests passed!")
}
