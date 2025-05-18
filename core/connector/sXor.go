package connector

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"
)

type SecureBytes struct {
	encKey        []byte 
	iv            []byte 
	encValue      []byte 
	fakeValue     []byte 
	initialized   bool
	hackDetecting bool
	observers     []Observer
	mutex         sync.RWMutex 
}

type Observer interface {
	Update(value string)
}

type Watcher struct {
	Name string
}

func (w *Watcher) Update(value string) {
	fmt.Println("An event occurred:", value)
}

func NewBytes(value []byte) *SecureBytes {
	
	key := make([]byte, 32) 
	iv := make([]byte, 16)  

	_, err := io.ReadFull(crand.Reader, key)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate secure key: %v", err))
	}

	_, err = io.ReadFull(crand.Reader, iv)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate secure IV: %v", err))
	}

	s := &SecureBytes{
		encKey:      key,
		iv:          iv,
		fakeValue:   value,
		initialized: false,
	}

	s.Apply(value)
	return s
}

func (s *SecureBytes) Apply(value []byte) *SecureBytes {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.initialized {
		s.encValue = s.encrypt(value)
		s.initialized = true
	}
	return s
}

func (s *SecureBytes) Get() []byte {
	return s.Decrypt()
}

func (s *SecureBytes) encrypt(value []byte) []byte {
	block, err := aes.NewCipher(s.encKey)
	if err != nil {
		panic(fmt.Sprintf("Failed to create cipher: %v", err))
	}

	
	ctr := cipher.NewCTR(block, s.iv)

	
	encrypted := make([]byte, len(value))
	ctr.XORKeyStream(encrypted, value)

	return encrypted
}

func (s *SecureBytes) decrypt(value []byte) []byte {
	block, err := aes.NewCipher(s.encKey)
	if err != nil {
		panic(fmt.Sprintf("Failed to create cipher: %v", err))
	}

	
	ctr := cipher.NewCTR(block, s.iv)

	
	decrypted := make([]byte, len(value))
	ctr.XORKeyStream(decrypted, value)

	return decrypted
}

func (s *SecureBytes) Set(value []byte) *SecureBytes {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.initialized = false
	return s.Apply(value)
}

func (s *SecureBytes) RandomizeKey() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	
	decrypted := s.decrypt(s.encValue)

	
	newKey := make([]byte, 32)
	_, err := io.ReadFull(crand.Reader, newKey)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate secure key: %v", err))
	}

	
	newIV := make([]byte, 16)
	_, err = io.ReadFull(crand.Reader, newIV)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate secure IV: %v", err))
	}

	
	s.encKey = newKey
	s.iv = newIV

	
	s.encValue = s.encrypt(decrypted)
}

func (s *SecureBytes) Decrypt() []byte {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if !s.initialized {
		return []byte{}
	}

	decryptedValue := s.decrypt(s.encValue)

	if s.hackDetecting && !isEqual(decryptedValue, s.fakeValue) {
		s.NotifyAll(fmt.Sprintf("hack attempt detected: %v", s.fakeValue))
	}

	return decryptedValue
}

func (s *SecureBytes) AddWatcher(observer Observer) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.observers = append(s.observers, observer)
	s.hackDetecting = true
}

func (s *SecureBytes) NotifyAll(value string) {
	for _, observer := range s.observers {
		observer.Update(value)
	}
}

func (s *SecureBytes) RefreshKeyPeriodically() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			s.RandomizeKey()
		}
	}()
}

func isEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	
	var result byte = 0
	for i := range a {
		result |= a[i] ^ b[i]
	}

	return result == 0
}
