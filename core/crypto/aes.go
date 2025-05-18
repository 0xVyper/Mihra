package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

func AESEncrypt(data []byte, passphrase []byte) ([]byte, error) {
	
	key := sha256.Sum256(passphrase)

	
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	
	return append(nonce, ciphertext...), nil
}

func AESDecrypt(data []byte, passphrase []byte) ([]byte, error) {
	
	key := sha256.Sum256(passphrase)

	
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func AESEncryptCBC(data []byte, key []byte, iv []byte) ([]byte, error) {
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	
	padding := block.BlockSize() - (len(data) % block.BlockSize())
	paddedData := make([]byte, len(data)+padding)
	copy(paddedData, data)

	
	cbc := cipher.NewCBCEncrypter(block, iv)

	
	encrypted := make([]byte, len(paddedData))
	cbc.CryptBlocks(encrypted, paddedData)

	return encrypted, nil
}

func AESDecryptCBC(data []byte, key []byte, iv []byte) ([]byte, error) {
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	
	if len(data)%block.BlockSize() != 0 {
		return nil, errors.New("invalid data length")
	}

	
	cbc := cipher.NewCBCDecrypter(block, iv)

	
	decrypted := make([]byte, len(data))
	cbc.CryptBlocks(decrypted, data)

	
	return decrypted, nil
}

func GenerateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
