package middleware

import (
	"LetterToBackend/config"
	"LetterToBackend/models"
	"LetterToBackend/pkg/utils"
	"encoding/json"
	"os"

	"github.com/gin-gonic/gin"
)

func VerifyLetter(ctx *gin.Context, letterId string) bool {
	getCookie, errCookie := ctx.Cookie(os.Getenv("KEY_SES_LETTER"))
	if getCookie == "" || errCookie != nil {
		return false
	}

	decodeCookie, deErr := utils.DecodeCookie(os.Getenv("KEY_SES_LETTER"), getCookie)
	if deErr != nil {
		return false
	}

	var cookieData models.LetterCookieData
	if err := json.Unmarshal([]byte(decodeCookie), &cookieData); err != nil {
		return false
	}

	var t string
	getDb := config.DB.Table("letter_sessions").
		Where("session_id = ?", cookieData.SessionID).
		Limit(1).Scan(&t)

	if getDb.RowsAffected < 1 {
		return false
	}

	if cookieData.LetterID != letterId {
		return false
	}

	return true
}
