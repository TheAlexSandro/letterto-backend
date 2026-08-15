package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type turnstileVerifyResponse struct {
	Success     bool     `json:"success"`
	ErrorCodes  []string `json:"error-codes"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
}

func VerifyTurnstile(token, remoteIP string) (bool, error) {
	payload := map[string]string{
		"secret":   os.Getenv("CF_SECRET"),
		"response": token,
		"remoteip": remoteIP,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	resp, err := http.Post(
		"https://challenges.cloudflare.com/turnstile/v0/siteverify",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result turnstileVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	fmt.Println(result)
	return result.Success, nil
}
