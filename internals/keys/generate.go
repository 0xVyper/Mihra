package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func generateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}
	return bytes, nil
}

func GenerateKeyPair() (privateKeyPEM, publicKeyPEM []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key pair: %v", err)
	}

	publicKey := &privateKey.PublicKey

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	publicKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKeyPEM, publicKeyPEM, nil
}

func ObfuscateKey(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

func GenerateEmbeddedKeysCode(privateKeyPEM, publicKeyPEM []byte) (string, error) {
	obfuscationKey, err := generateRandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate obfuscation key: %v", err)
	}

	obfuscatedPrivateKey := ObfuscateKey(privateKeyPEM, obfuscationKey)
	obfuscatedPublicKey := ObfuscateKey(publicKeyPEM, obfuscationKey)

	privateKeyB64 := base64.StdEncoding.EncodeToString(obfuscatedPrivateKey)
	publicKeyB64 := base64.StdEncoding.EncodeToString(obfuscatedPublicKey)
	obfuscationKeyHex := hex.EncodeToString(obfuscationKey)

	privateKeyHash := sha256.Sum256(privateKeyPEM)
	publicKeyHash := sha256.Sum256(publicKeyPEM)
	privateKeyFingerprint := hex.EncodeToString(privateKeyHash[:])
	publicKeyFingerprint := hex.EncodeToString(publicKeyHash[:])

	buildID := fmt.Sprintf("%d", time.Now().Unix())

	code := fmt.Sprintf(`
package keys

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"runtime"
	"sync"
	"time"
	"github.com/0xvyper/mihra/internals/keys"

)

const (
	BuildID        = "%s"
	BuildTimestamp = %d
)

var (
	privateKeyObfuscated  = "%s"
	publicKeyObfuscated   = "%s"
	obfuscationKeyHex     = "%s"
	privateKeyFingerprint = "%s"
	publicKeyFingerprint  = "%s"
	cacheMutex            = sync.Mutex{}
	cachedPrivateKey      []byte
	cachedPublicKey       []byte
)

func GetPrivateKeyPEM() ([]byte, error) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if cachedPrivateKey != nil {
		return cachedPrivateKey, nil
	}

	if isBeingAnalyzed() {
		return nil, fmt.Errorf("security violation: analysis tools detected")
	}

	obfuscationKey, err := hex.DecodeString(obfuscationKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode obfuscation key: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(privateKeyObfuscated)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	result := keys.ObfuscateKey(decoded, obfuscationKey)
	if !verifyFingerprint(result, privateKeyFingerprint) {
		return nil, fmt.Errorf("private key verification failed")
	}

	cachedPrivateKey = result
	return result, nil
}

func GetPublicKeyPEM() ([]byte, error) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if cachedPublicKey != nil {
		return cachedPublicKey, nil
	}

	obfuscationKey, err := hex.DecodeString(obfuscationKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode obfuscation key: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(publicKeyObfuscated)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}

	result := keys.ObfuscateKey(decoded, obfuscationKey)
	if !verifyFingerprint(result, publicKeyFingerprint) {
		return nil, fmt.Errorf("public key verification failed")
	}

	cachedPublicKey = result
	return result, nil
}

func verifyFingerprint(key []byte, fingerprint string) bool {
	hash := sha256.Sum256(key)
	return hex.EncodeToString(hash[:]) == fingerprint
}

func isBeingAnalyzed() bool {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	if memStats.NumGC < 1 || memStats.PauseTotalNs == 0 {
		return true
	}

	start := time.Now().UnixNano()
	for i := 0; i < 10000; i++ {
		_ = i * i
	}
	elapsed := time.Now().UnixNano() - start

	return elapsed > 15000000 
}
`, buildID, time.Now().Unix(), privateKeyB64, publicKeyB64, obfuscationKeyHex,
		privateKeyFingerprint, publicKeyFingerprint)

	return code, nil
}

func SaveEmbeddedKeysCode(code string, outputPath string) error {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	if err := os.WriteFile(outputPath, []byte(code), 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	return nil
}
