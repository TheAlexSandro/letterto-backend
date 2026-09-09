package utils

import (
	"crypto/rand"
	"math/big"
	"strings"
	"unicode"
)

const backupCodeCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func generateBackupCode() (string, error) {
	b := make([]byte, 10)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(backupCodeCharset))))
		if err != nil {
			return "", err
		}
		b[i] = backupCodeCharset[n.Int64()]
	}
	return string(b[:5]) + "-" + string(b[5:]), nil
}

func GenerateBackupCodes(count int) ([]string, error) {
	codes := make([]string, 0, count)
	seen := make(map[string]bool)

	for len(codes) < count {
		code, err := generateBackupCode()
		if err != nil {
			return nil, err
		}
		if seen[code] {
			continue
		}
		seen[code] = true
		codes = append(codes, code)
	}

	return codes, nil
}

func NormalizeBackupCode(input string) string {
	upper := strings.ToUpper(input)

	var clean strings.Builder
	for _, r := range upper {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			clean.WriteRune(r)
		}
	}

	stripped := clean.String()
	if len(stripped) != 10 {
		return stripped
	}

	return stripped[:5] + "-" + stripped[5:]
}
