package crypto

import (
	"fmt"

	"golang.org/x/crypto/chacha20"
)

func ChaCha20Encrypt(input, key, nonce []byte) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	encryptedData := make([]byte, len(input))
	cipher.XORKeyStream(encryptedData, input)
	return encryptedData, nil
}

func DecryptChaCha20(input, key, nonce []byte) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20 cipher: %v", err)
	}
	decryptedData := make([]byte, len(input))
	cipher.XORKeyStream(decryptedData, input)
	return decryptedData, nil
}
