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
	"strconv"
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
	name string,
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
		<title>LetterTo</title>

		<style>
			@import url('https://fonts.googleapis.com/css2?family=Playwrite+NZ+Guides&display=swap');
			@import url('https://fonts.googleapis.com/css2?family=Poppins:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;0,800;0,900;1,100;1,200;1,300;1,400;1,500;1,600;1,700;1,800;1,900&display=swap');

			body {
				margin: 0;
				padding: 0;
				background-color: #ffffff;
				font-family: 'Poppins', sans-serif;
			}

			a {
				color: #7c3aed;
				text-decoration: underline;
				text-underline-offset: 2px;
				text-decoration-color: #ede9fe;
			}

			table {
				border-spacing: 0;
				border-collapse: collapse;
			}

			.wrapper {
				width: 100%%;
				background-color: #ffffff;
				padding: 24px 16px;
			}

			.container {
				width: 100%%;
				max-width: 480px;
				margin: 0 auto;
			}

			.header {
				padding: 10px 8px 20px;
				border-bottom: 1px solid #d6d5d5;
			}

			.header-row td {
				vertical-align: middle;
			}

			.logo-box img {
				width: 35px;
				height: auto;
				vertical-align: middle;
				display: inline-block;
			}

			.logo-box span {
				font-family: 'Playwrite NZ Guides', cursive;
				font-style: normal;
				vertical-align: middle;
				font-size: 19px;
				line-height: 35px;
				color: #1c1c1c;
				padding-left: 7px;
			}

			.logo-right {
				font-weight: 500;
				font-size: 14px;
				line-height: 35px;
				padding-top: 8px;
				color: #1c1c1c;
			}

			.content {
				padding: 24px 8px 8px;
			}

			.content p {
				margin: 0 0 16px;
				font-size: 14px;
				line-height: 1.6;
				color: #1c1c1c;
			}

			.code-box {
				background-color: #f4f4f4;
				border: 1px solid #7c3aed;
				border-radius: 6px;
				margin: 24px 0;
				padding: 10px;
				text-align: center;
			}

			.code-box p {
				margin: 0;
				font-size: 28px;
				font-weight: 600;
				letter-spacing: 4px;
				color: #1c1c1c;
			}

			.code-caption {
				margin: 8px 0 0 !important;
				font-size: 12px !important;
				color: #676767 !important;
				text-align: center;
			}

			.info-row {
				padding-bottom: 7px;
			}

			.info-row span {
				font-size: 14px;
				line-height: 1.6;
				color: #1c1c1c;
			}

			.footer {
				padding: 20px 8px 0;
				border-top: 1px solid #d6d5d5;
			}

			.footer p {
				margin: 0;
				font-size: 12px;
				line-height: 1.6;
				color: #676767;
			}

			.footer .link a {
				font-size: 12px;
				padding-left: 10px;
			}

			.footer .link a:first-child {
				padding-left: 0;
			}

			@media screen and (max-width: 480px) {
				.footer-copy,
				.footer-links {
					display: block !important;
					width: 100%% !important;
					text-align: center !important;
				}

				.footer-copy {
					padding-bottom: 10px;
				}

				.footer .link {
					justify-content: center;
				}

				.footer .link a:first-child {
					padding-left: 0;
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
			class="wrapper"
		>
			<tr>
				<td align="center">
					<table
						role="presentation"
						width="100%%"
						cellpadding="0"
						cellspacing="0"
						border="0"
						class="container"
					>
						<tr>
							<td class="header">
								<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0">
									<tr class="header-row">
										<td class="logo-box" align="left">
											<img src="https://storage.letterto.site/assets/favicon.svg" alt="logo" />
											<span>LetterTo</span>
										</td>
										<td class="logo-right" align="right">Security Service</td>
									</tr>
								</table>
							</td>
						</tr>

						<tr>
							<td class="content">
								<p>Hi %s,</p>
								<p>
									Use the verification code below to continue. For your security, please don't share
									this code with anyone.
								</p>

								<div class="code-box">
									<p>%s</p>
								</div>
								<p class="code-caption">This code expires in 5 minutes.</p>

								<table
									role="presentation"
									width="100%%"
									cellpadding="0"
									cellspacing="0"
									border="0"
									style="margin-top: 24px"
								>
									<tr>
										<td class="info-row">
											<span
												>Never share this code with anyone, even if they claim to be from LetterTo.
												We never ask you to share this code.</span
											>
										</td>
									</tr>
									<tr>
										<td class="info-row">
											<span
												>If you didn't request this code, you can safely ignore this email.</span
											>
										</td>
									</tr>
								</table>
							</td>
						</tr>

						<tr>
							<td class="footer">
								<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0">
									<tr>
										<td align="left" class="footer-copy">
											<p>&copy; %s by LetterTo Security Service</p>
										</td>
										<td align="right" class="link footer-links">
											<a href="/letterto.site/blog/privacy-policy">Privacy Policy</a>
											<a href="/letterto.site/blog/tos">Terms Of Service</a>
										</td>
									</tr>
								</table>
							</td>
						</tr>
					</table>
				</td>
			</tr>
		</table>
	</body>
</html>

`, name, otp, strconv.Itoa(time.Now().Year()))

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
