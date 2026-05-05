package utils

import (
	"os"

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
