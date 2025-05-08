package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// AESEncrypt encrypts data using AES-GCM
func AESEncrypt(data []byte, passphrase []byte) ([]byte, error) {
	// Generate a key from the passphrase
	key := sha256.Sum256(passphrase)

	// Create cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Prepend nonce
	return append(nonce, ciphertext...), nil
}

// AESDecrypt decrypts data using AES-GCM
func AESDecrypt(data []byte, passphrase []byte) ([]byte, error) {
	// Generate a key from the passphrase
	key := sha256.Sum256(passphrase)

	// Create cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt data
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// AESEncryptCBC encrypts data using AES-CBC
func AESEncryptCBC(data []byte, key []byte, iv []byte) ([]byte, error) {
	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Pad data to block size if needed
	padding := block.BlockSize() - (len(data) % block.BlockSize())
	paddedData := make([]byte, len(data)+padding)
	copy(paddedData, data)

	// Create CBC encrypter
	cbc := cipher.NewCBCEncrypter(block, iv)

	// Encrypt data
	encrypted := make([]byte, len(paddedData))
	cbc.CryptBlocks(encrypted, paddedData)

	return encrypted, nil
}

// AESDecryptCBC decrypts data using AES-CBC
func AESDecryptCBC(data []byte, key []byte, iv []byte) ([]byte, error) {
	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Check if the length of the data is a multiple of the block size
	if len(data)%block.BlockSize() != 0 {
		return nil, errors.New("invalid data length")
	}

	// Create CBC decrypter
	cbc := cipher.NewCBCDecrypter(block, iv)

	// Decrypt data
	decrypted := make([]byte, len(data))
	cbc.CryptBlocks(decrypted, data)

	// Remove padding (simplified)
	return decrypted, nil
}

// GenerateRandomBytes generates random bytes
func GenerateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
