package connector

import (
	"fmt"
	"math/rand"
	"time"
)

const KEY int = 7153234

type SecureBytes struct {
	key           int
	realValue     []byte
	fakeValue     []byte
	initialized   bool
	hackDetecting bool
	observers     []Observer
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
	s := &SecureBytes{
		key:         KEY,
		realValue:   value,
		fakeValue:   value,
		initialized: false,
	}
	s.Apply()
	return s
}

func (s *SecureBytes) Apply() *SecureBytes {
	if !s.initialized {
		s.realValue = s.XOR(s.realValue, s.key)
		s.initialized = true
	}
	return s
}

func (s *SecureBytes) Get() []byte {
	return s.Decrypt()
}

func (s *SecureBytes) XOR(value []byte, key int) []byte {
	res := make([]byte, len(value))
	for j, v := range value {
		res[j] = v ^ byte(key)
	}
	return res
}

func (s *SecureBytes) SetKey(key int) {
	s.key = key
}

func (s *SecureBytes) Set(value []byte) *SecureBytes {
	s.realValue = value
	s.initialized = false
	return s.Apply()
}

func (s *SecureBytes) RandomizeKey() {
	rand.Seed(time.Now().UnixNano())
	s.realValue = s.Decrypt()
	s.key = rand.Intn(int(^uint(0) >> 1))
	s.realValue = s.XOR(s.realValue, s.key)
}

func (s *SecureBytes) Decrypt() []byte {
	if !s.initialized {
		return []byte{}
	}

	decryptedValue := s.XOR(s.realValue, s.key)

	if s.hackDetecting && !isEqual(decryptedValue, s.fakeValue) {
		s.NotifyAll(fmt.Sprintf("hack attempt detected: %v", s.fakeValue))
	}

	return decryptedValue
}

func (s *SecureBytes) AddWatcher(observer Observer) {
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
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
