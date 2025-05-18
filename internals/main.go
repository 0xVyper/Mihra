package main
import (
	"fmt"
	"os"
	"github.com/0xvyper/mihra/internals/keys"
)
func main() {
	fmt.Println("Building Mihra with secure key generation...")
	
	privateKeyPEM, publicKeyPEM, err := keys.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key pair: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Generated RSA key pair successfully.")
	
	if err := os.WriteFile("private_key.pem", privateKeyPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile("public_key.pem", publicKeyPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving public key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Saved keys to private_key.pem and public_key.pem")
	
	code, err := keys.GenerateEmbeddedKeysCode(privateKeyPEM, publicKeyPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating embedded keys code: %v\n", err)
		os.Exit(1)
	}
	
	if err := keys.SaveEmbeddedKeysCode(code, "keys/generated_keys.go"); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving embedded keys code: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Generated and saved embedded keys code to keys/generated_keys.go")
}
