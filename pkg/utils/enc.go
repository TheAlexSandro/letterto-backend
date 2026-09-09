package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
)

var secret = os.Getenv("ENC_SECRET")

func deriveNonce(plaintext string, nonceKey []byte, size int) []byte {
	mac := hmac.New(sha256.New, nonceKey)
	mac.Write([]byte(plaintext))
	sum := mac.Sum(nil)
	return sum[:size]
}

func EncryptDeterministic(text string) (string, error) {
	encKey, nonceKey := DeriveKeys(secret)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := deriveNonce(text, nonceKey, gcm.NonceSize())

	encrypted := gcm.Seal(nonce, nonce, []byte(text), nil)

	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func Decrypt(encryptedText string) (string, error) {
	encKey, _ := DeriveKeys(secret)

	data, err := base64.RawURLEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt")
	}

	return string(decrypted), nil
}
