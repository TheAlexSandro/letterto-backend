package utils

import (
	"LetterToBackend/models"
	"encoding/json"
	"fmt"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type Response struct {
	StatusCode int         `json:"status_code"`
	OK         bool        `json:"ok"`
	Message    string      `json:"message,omitempty"`
	Data       interface{} `json:"data,omitempty"`
	ErrorCode  string      `json:"error_code,omitempty"`
}

func JSON(c *gin.Context, status_code int, ok bool, message string, data interface{}, errCode string) {
	res := Response{
		StatusCode: status_code,
		OK:         ok,
		Message:    message,
		Data:       data,
	}

	if !ok {
		res.ErrorCode = errCode
	}

	c.JSON(status_code, res)
}

func GenerateID(length int) string {
	const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		result[i] = characters[rand.Intn(len(characters))]
	}

	return string(result)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 11)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func CheckPasswordHash(password, hash string) bool {
	cleanPassword := strings.TrimSpace(password)
	cleanHash := strings.TrimSpace(hash)
	err := bcrypt.CompareHashAndPassword([]byte(cleanHash), []byte(cleanPassword))
	return err == nil
}

func GetExpiry() time.Duration {
	expiresTime := os.Getenv("SES_EXP")
	h, errTime := strconv.Atoi(expiresTime)

	if errTime != nil {
		return 7 * 24 * time.Hour
	}

	return time.Duration(h) * time.Hour
}

func GetErrorJson(code string, target *models.ErrorDetail) {
	file, _ := os.ReadFile("internal/constant/http_code.json")
	var allErrors map[string]models.ErrorDetail
	json.Unmarshal(file, &allErrors)

	if val, ok := allErrors[code]; ok {
		*target = val
	}
}

func GetFileType(file *multipart.FileHeader) (string, error) {
	f, err := file.Open()
	if err != nil {
		return "", err
	}
	defer f.Close()

	buffer := make([]byte, 512)
	_, err = f.Read(buffer)
	if err != nil {
		return "", err
	}
	_, _ = f.Seek(0, 0)
	contentType := http.DetectContentType(buffer)

	if strings.HasPrefix(contentType, "image/") {
		return "image", nil
	} else if strings.HasPrefix(contentType, "video/") {
		return "video", nil
	}

	return "unknown", nil
}

func ValidateLength(ctx *gin.Context, value string, paramName string) bool {
	maxLen, _ := strconv.Atoi(os.Getenv("LEN_MAX"))
	minLen, _ := strconv.Atoi(os.Getenv("LEN_MIN"))

	if paramName == "password" && len(value) < minLen {
		var errJson models.ErrorDetail
		GetErrorJson("LENGTH_TOO_SHORT", &errJson)

		rplc := strings.NewReplacer(
			"{param}", paramName,
			"{len}", strconv.Itoa(minLen),
		)

		JSON(ctx, errJson.Http, false, rplc.Replace(errJson.Message), nil, errJson.Code)
		return false
	}

	if len(value) > maxLen {
		var errJson models.ErrorDetail
		GetErrorJson("LENGTH_TOO_LONG", &errJson)

		rplc := strings.NewReplacer(
			"{param}", paramName,
			"{len}", strconv.Itoa(maxLen),
		)

		JSON(ctx, errJson.Http, false, rplc.Replace(errJson.Message), nil, errJson.Code)
		return false
	}
	return true
}

func ValidateEnum(ctx *gin.Context, paramName string, value string, allowed []string) bool {
	isValid := false
	for _, a := range allowed {
		if a == value {
			isValid = true
			break
		}
	}

	if !isValid {
		var errJson models.ErrorDetail
		GetErrorJson("FIELD_CONTENT_INVALID", &errJson)

		allowedStr := strings.Join(allowed, ", ")

		rplc := strings.NewReplacer(
			"{param}", paramName,
			"{field}", allowedStr,
		)

		JSON(ctx, errJson.Http, false, rplc.Replace(errJson.Message), nil, errJson.Code)
		return false
	}
	return true
}

func FormatBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func InvFileSizeRes(ctx *gin.Context, fileType string, size int64) bool {
	var errJson models.ErrorDetail
	GetErrorJson("FILE_TOO_LARGE", &errJson)
	sizeStr := FormatBytes(size)
	rplc := strings.NewReplacer("{param}", fileType, "{size}", sizeStr)

	JSON(ctx, errJson.Http, false, rplc.Replace(errJson.Message), nil, errJson.Code)
	return false
}

func SetCookieSameSite() http.SameSite {
	getType := os.Getenv("COOKIE_SAME_SITE")

	switch getType {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func TruncateText(s string, max int) string {
	runes := []rune(s)

	if len(runes) <= max {
		return s
	}

	return string(runes[:max]) + "..."
}
