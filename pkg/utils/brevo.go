package utils

import (
	"LetterToBackend/config"
	"LetterToBackend/models"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/email/otp.html
var otpEmailTemplate string

type BrevoClient struct {
	APIKey    string
	FromEmail string
	FromName  string
}

type sendEmailRequest struct {
	Sender struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"sender"`

	To []struct {
		Email string `json:"email"`
		Name  string `json:"name,omitempty"`
	} `json:"to"`

	Subject     string `json:"subject"`
	HTMLContent string `json:"htmlContent"`
	TextContent string `json:"textContent,omitempty"`
}

type otpEmailData struct {
	Name              string
	Code              string
	ExpiryMinutes     int
	Year              int
	PrivacyPolicyURL  string
	TermsOfServiceURL string
}

func NewBrevoClient() *BrevoClient {
	return &BrevoClient{
		APIKey:    os.Getenv("BREVO_API_KEY"),
		FromEmail: os.Getenv("BREVO_FROM_EMAIL"),
		FromName:  os.Getenv("BREVO_FROM_NAME"),
	}
}

func renderOTPEmail(name, otp string) (string, error) {
	tmpl, err := template.New("otp_email").Parse(otpEmailTemplate)
	if err != nil {
		return "", err
	}

	expiry, _ := strconv.Atoi(os.Getenv("OTP_EXPIRY"))

	data := otpEmailData{
		Name:              name,
		Code:              otp,
		ExpiryMinutes:     expiry,
		Year:              time.Now().Year(),
		PrivacyPolicyURL:  os.Getenv("URL_PP"),
		TermsOfServiceURL: os.Getenv("URL_TS"),
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (b *BrevoClient) SendOTP(
	toEmail string,
	otp string,
	hashString string,
	userId string,
	name string,
) error {
	htmlBody, err := renderOTPEmail(name, otp)
	if err != nil {
		return err
	}

	reqBody := sendEmailRequest{}

	reqBody.Sender.Name = b.FromName
	reqBody.Sender.Email = b.FromEmail

	reqBody.To = append(reqBody.To, struct {
		Email string `json:"email"`
		Name  string `json:"name,omitempty"`
	}{
		Email: toEmail,
	})

	reqBody.Subject = "Verification Code - " + otp
	reqBody.HTMLContent = htmlBody
	reqBody.TextContent = fmt.Sprintf(
		"Your verification code is: %s\n\nThis code will expire in 5 minutes.",
		otp,
	)

	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		"https://api.brevo.com/v3/smtp/email",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}

	req.Header.Set("accept", "application/json")
	req.Header.Set("api-key", b.APIKey)
	req.Header.Set("content-type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf(
			"brevo returned status %d",
			resp.StatusCode,
		)
	}

	expiry, _ := strconv.Atoi(os.Getenv("OTP_EXPIRY"))
	config.DB.Table("otps").Where("LOWER(user_id) = ?", strings.ToLower(userId)).Delete(&models.Otp{})
	otps := models.Otp{
		OtpId:     GenerateID(10),
		UserId:    userId,
		Otp:       hashString,
		ExpiresAt: NowTz().Add(time.Duration(expiry) * time.Minute),
		Email:     toEmail,
	}

	if err := config.DB.Table("otps").Create(otps).Error; err != nil {
		return err
	}

	return nil
}

func GenerateOtp() (string, error) {
	var b [4]byte

	_, err := rand.Read(b[:])
	if err != nil {
		return "", err
	}

	n := uint32(b[0])<<24 |
		uint32(b[1])<<16 |
		uint32(b[2])<<8 |
		uint32(b[3])

	n %= 1000000

	return fmt.Sprintf("%06d", n), nil
}

func VerifyOTP(
	storedHash string,
	inputHash string,
	expiresAt time.Time,
) bool {
	if NowTz().After(expiresAt) {
		return false
	}

	return subtle.ConstantTimeCompare(
		[]byte(storedHash),
		[]byte(inputHash),
	) == 1
}
