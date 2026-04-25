package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// EncryptionService provides AES-256-GCM encryption for sensitive data
type EncryptionService struct {
	key []byte // 32 bytes for AES-256
}

// NewEncryptionService creates a new encryption service with the provided key
// The key should be a 64-character hex string (32 bytes)
func NewEncryptionService(keyHex string) (*EncryptionService, error) {
	if keyHex == "" {
		return nil, fmt.Errorf("encryption key is required")
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key format: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes (64 hex characters), got %d bytes", len(key))
	}

	return &EncryptionService{key: key}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM
// Returns: nonce (12 bytes) + ciphertext + tag (16 bytes)
func (s *EncryptionService) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext encrypted with Encrypt()
// Expects: nonce (12 bytes) + ciphertext + tag (16 bytes)
func (s *EncryptionService) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns hex-encoded ciphertext
func (s *EncryptionService) EncryptString(plaintext string) (string, error) {
	encrypted, err := s.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encrypted), nil
}

// DecryptString decrypts hex-encoded ciphertext to a string
func (s *EncryptionService) DecryptString(ciphertextHex string) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex encoding: %w", err)
	}
	plaintext, err := s.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// GenerateKey generates a new random 32-byte encryption key and returns it as a hex string
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}
	return hex.EncodeToString(key), nil
}
