package utils

import (
	"regexp"
	"strings"
)

var htmlTagRegex = regexp.MustCompile(`<[^>]*>`)

func StripHTML(input string) string {
	plain := htmlTagRegex.ReplaceAllString(input, "")
	plain = strings.ReplaceAll(plain, "&nbsp;", "")
	plain = strings.TrimSpace(plain)
	return plain
}

func IsMessageEmpty(message string, minLength int) bool {
	return len(StripHTML(message)) < minLength
}
