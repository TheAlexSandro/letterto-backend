package utils

import (
	"os"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"github.com/gorilla/securecookie"
)

var s *securecookie.SecureCookie

func InitCookie() {
	hashKey := []byte(os.Getenv("COOKIE_SIGN"))
	s = securecookie.New(hashKey, nil)
}

func EncodeCookie(name string, value string) (string, error) {
	return s.Encode(name, value)
}

func DecodeCookie(name string, cookieValue string) (string, error) {
	var value string
	if err := s.Decode(name, cookieValue, &value); err != nil {
		return "", err
	}
	return value, nil
}

var (
	ErrInvalidSignature = errors.New("cookie: invalid signature")
	ErrInvalidFormat    = errors.New("cookie: invalid format")
)

const sep = "."

func EncryptCookie(plaintext string) (string, error) {
	secret := os.Getenv("COOKIE_SECRET")
	encKey, macKey := DeriveKeys(secret)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, nonce)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, []byte(plaintext))

	mac := hmac.New(sha256.New, macKey)
	mac.Write(nonce)
	mac.Write(ciphertext)
	signature := mac.Sum(nil)

	parts := []string{
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(ciphertext),
		base64.RawURLEncoding.EncodeToString(signature),
	}
	return strings.Join(parts, sep), nil
}

func VerifySignature(cookieValue string) bool {
	secret := os.Getenv("COOKIE_SECRET")
	parts := strings.Split(cookieValue, sep)
	if len(parts) != 3 {
		return false
	}

	nonce, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	ciphertext, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	signature, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}

	_, macKey := DeriveKeys(secret)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(nonce)
	mac.Write(ciphertext)
	expected := mac.Sum(nil)

	return subtle.ConstantTimeCompare(signature, expected) == 1
}

func DecryptCookie(cookieValue string, secret string) (string, error) {
	if !VerifySignature(cookieValue) {
		return "", ErrInvalidSignature
	}

	parts := strings.Split(cookieValue, sep)
	if len(parts) != 3 {
		return "", ErrInvalidFormat
	}

	nonce, _ := base64.RawURLEncoding.DecodeString(parts[0])
	ciphertext, _ := base64.RawURLEncoding.DecodeString(parts[1])

	encKey, _ := DeriveKeys(secret)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, nonce)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}
