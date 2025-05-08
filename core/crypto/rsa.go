package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func RsaDecoding(privateKeyPEM []byte, ciphertext []byte) ([]byte, error) {
	if len(privateKeyPEM) == 0 {
		return nil, fmt.Errorf("private key PEM is empty")
	}
	block, rest := pem.Decode(privateKeyPEM)
	if block == nil || len(rest) > 0 {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	// Try parsing as PKCS#8 first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	rsaPrivateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parsed key is not an RSA private key")
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is empty")
	}
	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}
	return decrypted, nil
}

func RsaEnconding(publicKeyPEM []byte, content []byte) ([]byte, error) {
	if len(publicKeyPEM) == 0 {
		return nil, fmt.Errorf("public key PEM is empty")
	}
	block, rest := pem.Decode(publicKeyPEM)
	if block == nil || len(rest) > 0 {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an RSA public key")
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("content to encrypt is empty")
	}
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, content)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %v", err)
	}
	return encrypted, nil
}
