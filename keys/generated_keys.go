// Code generated automatically at build time. DO NOT EDIT.
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

// Build information
const (
	BuildID        = "1747595332"
	BuildTimestamp = 1747595332
)

// Obfuscated keys
var (
	privateKeyObfuscated  = "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"
	publicKeyObfuscated   = "rgz9zXuHWoqftZ3M108VbfkImFs10aP3+hK2jPsssmPpYJ6iMa5upb2S+qX1PRtl622VXy2zzZuGB/2M+yyyaeRqk6EHgF60lLrP0ed+NUnuGaFKLbbliZxQ78vqAMdj5E+9qR+UcYHgrdj/02goQNhagWYAmPew5Wrot/4MqWzsSpKufaZwurzD/+y6bGFR4n69bT7J3pWhSeutuAq9Y8J5h4YmhGi6lJnx/7FHN3PXcJJZP8zCtaJFl63RVoJf+3LhjyHuLpuitI7P6E8Sc+t4tUQrn8u/pWj7ruJvvHvkReKTIqJruKa80660Rix37V+gVge94bu2Csul2B+3f7JkvrMioGuYgM7o7cAiLFDDaZxrKJPWuKILy4r3CvpeqBaWqSW1b/2Fqvyp1XtqTvNFkUxeveuXrn7pktoppkv3Y5amJPBdp52Ox660eTcT+H2GKxrM1JjhUNDqhFSeIMBnvas7rGe974Ls5c95Mk/1ZJQvK5Xv758Li5fBJ7lf8ECIog61Rf+XmPC3wV8tTONd4y0VzruOhkaM9IEQuBmJdqepEoROjJTxkLGvIHRh9GzzTjm+wpOUH/eE60jdB64M2g=="
	obfuscationKeyHex     = "8321d0e056c51fcdd6fbbd9c820d5924ba28d31e6cfc8edad73fbcc1b265f02a"
	privateKeyFingerprint = "c070bd6e0d961fcafeb2712d09c5e22de0ba3cc1e74ef52c88e66e7869e0052c"
	publicKeyFingerprint  = "355972796124e17a4fa13152f489e2b3447b2c939d06958bfb49f2d10668fc54"
	cacheMutex            = sync.Mutex{}
	cachedPrivateKey      []byte
	cachedPublicKey       []byte
)

// GetPrivateKeyPEM returns the deobfuscated private key
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
		return nil, fmt.Errorf("failed to decode obfuscation key: %!v(MISSING)", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(privateKeyObfuscated)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %!v(MISSING)", err)
	}

	result := keys.ObfuscateKey(decoded, obfuscationKey)
	if !verifyFingerprint(result, privateKeyFingerprint) {
		return nil, fmt.Errorf("private key verification failed")
	}

	cachedPrivateKey = result
	return result, nil
}

// GetPublicKeyPEM returns the deobfuscated public key
func GetPublicKeyPEM() ([]byte, error) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if cachedPublicKey != nil {
		return cachedPublicKey, nil
	}

	obfuscationKey, err := hex.DecodeString(obfuscationKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode obfuscation key: %!v(MISSING)", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(publicKeyObfuscated)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %!v(MISSING)", err)
	}

	result := keys.ObfuscateKey(decoded, obfuscationKey)
	if !verifyFingerprint(result, publicKeyFingerprint) {
		return nil, fmt.Errorf("public key verification failed")
	}

	cachedPublicKey = result
	return result, nil
}

// verifyFingerprint checks if the key matches its fingerprint
func verifyFingerprint(key []byte, fingerprint string) bool {
	hash := sha256.Sum256(key)
	return hex.EncodeToString(hash[:]) == fingerprint
}

// isBeingAnalyzed attempts to detect debugging or analysis tools
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

	return elapsed > 15000000 // 15ms
}