package utils

import (
	"LetterToBackend/config"
	"LetterToBackend/models"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

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

func NewBrevoClient() *BrevoClient {
	return &BrevoClient{
		APIKey:    os.Getenv("BREVO_API_KEY"),
		FromEmail: os.Getenv("BREVO_FROM_EMAIL"),
		FromName:  os.Getenv("BREVO_FROM_NAME"),
	}
}

func (b *BrevoClient) SendOTP(
	toEmail string,
	otp string,
	hashString string,
	userId string,
) error {
	config.DB.Table("otps").Where("LOWER(user_id) = ?", strings.ToLower(userId)).Delete(&models.Otp{})
	otps := models.Otp{
		OtpId:     GenerateID(10),
		UserId:    userId,
		Otp:       hashString,
		ExpiresAt: NowTz().Add(300),
		Email:     toEmail,
	}

	if err := config.DB.Table("otps").Create(otps).Error; err != nil {
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

	reqBody.HTMLContent = fmt.Sprintf(`
<!doctype html>
<html lang="en">
	<head>
		<meta charset="UTF-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />

		<title>LetterTo Security</title>

		<style>
			@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap');

			body {
				margin: 0;
				padding: 0;
				background-color: #fffbfe;
				font-family: 'Poppins', Arial, sans-serif;
				color: #050505;
			}

			table {
				border-spacing: 0;
				border-collapse: collapse;
			}

			.email-wrapper {
				width: 100%%;
				background-color: #fffbfe;
				padding: 40px 16px;
			}

			.email-container {
				width: 100%%;
				max-width: 520px;
				margin: 0 auto;
				background-color: #ffffff;
				border: 1px solid #ede9fe;
				border-radius: 16px;
				overflow: hidden;
			}

			.header {
				padding: 30px 32px 26px;
				text-align: center;
				background-color: #f7f2fa;
				border-bottom: 1px solid #ede9fe;
			}

			.logo {
				margin: 0;
				font-size: 24px;
				font-weight: 700;
				color: #7c3aed;
				letter-spacing: -0.5px;
			}

			.header-subtitle {
				margin: 6px 0 0;
				font-size: 13px;
				font-weight: 400;
				color: #65676b;
			}

			.content {
				padding: 36px 32px 32px;
				text-align: center;
			}

			.title {
				margin: 0 0 10px;
				font-size: 22px;
				font-weight: 600;
				line-height: 1.4;
				color: #050505;
			}

			.description {
				margin: 0 auto;
				max-width: 400px;
				font-size: 14px;
				line-height: 1.7;
				color: #65676b;
			}

			.code-wrapper {
				margin: 28px 0 20px;
				padding: 22px 16px;
				background-color: #f3edf7;
				border: 1px solid #ede9fe;
				border-radius: 12px;
			}

			.code-label {
				display: block;
				margin-bottom: 8px;
				font-size: 11px;
				font-weight: 600;
				letter-spacing: 1.5px;
				text-transform: uppercase;
				color: #8a8d91;
			}

			.code {
				margin: 0;
				font-size: 32px;
				font-weight: 700;
				letter-spacing: 8px;
				line-height: 1.2;
				color: #7c3aed;
			}

			.expiry {
				margin: 0;
				font-size: 12px;
				line-height: 1.6;
				color: #8a8d91;
			}

			.expiry strong {
				font-weight: 600;
				color: #65676b;
			}

			.security-note {
				margin-top: 28px;
				padding: 14px 16px;
				background-color: #f3eeff;
				border-radius: 10px;
				text-align: center;
			}

			.security-note p {
				margin: 0;
				font-size: 12px;
				line-height: 1.6;
				color: #65676b;
			}

			.security-note strong {
				color: #6d28d9;
				font-weight: 600;
			}

			.footer {
				padding: 20px 32px 26px;
				border-top: 1px solid #ced0d4;
				text-align: center;
			}

			.footer p {
				margin: 0;
				font-size: 11px;
				line-height: 1.7;
				color: #8a8d91;
			}

			.footer-brand {
				margin-top: 8px !important;
				font-weight: 600;
				color: #7c3aed !important;
			}

			@media screen and (max-width: 600px) {
				.email-wrapper {
					padding: 20px 10px;
				}

				.header {
					padding: 26px 20px 22px;
				}

				.content {
					padding: 30px 20px 26px;
				}

				.footer {
					padding: 18px 20px 22px;
				}

				.title {
					font-size: 20px;
				}

				.code {
					font-size: 28px;
					letter-spacing: 6px;
				}
			}
		</style>
	</head>

	<body>
		<table
			role="presentation"
			width="100%%"
			cellpadding="0"
			cellspacing="0"
			border="0"
			class="email-wrapper"
		>
			<tr>
				<td align="center">
					<table
						role="presentation"
						width="100%%"
						cellpadding="0"
						cellspacing="0"
						border="0"
						class="email-container"
					>
						<tr>
							<td class="header">
								<h1 class="logo">LetterTo Security</h1>

								<p class="header-subtitle">Account Verification</p>
							</td>
						</tr>

						<tr>
							<td class="content">
								<p class="description">
									Use the verification code below to continue. For your security, please don't share
									this code with anyone.
								</p>

								<div class="code-wrapper">
									<span class="code-label"> Verification Code </span>

									<p class="code">%s</p>
								</div>

								<p class="expiry">
									This code will expire in
									<strong>5 minutes</strong>.
								</p>

								<div class="security-note">
									<p>
										We never ask you to share your verification code through email, chat,
										or any other channel.
									</p>
								</div>
							</td>
						</tr>

						<tr>
							<td class="footer">
								<p>
									If you didn't request this verification code, you can safely ignore this email.
								</p>

								<p class="footer-brand">LetterTo Security Service</p>
							</td>
						</tr>
					</table>
				</td>
			</tr>
		</table>
	</body>
</html>
`, otp)

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
	if !NowTz().After(expiresAt) {
		return false
	}

	return subtle.ConstantTimeCompare(
		[]byte(storedHash),
		[]byte(inputHash),
	) == 1
}
