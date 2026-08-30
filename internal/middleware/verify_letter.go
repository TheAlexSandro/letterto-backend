package middleware

import (
	"LetterToBackend/config"
	"LetterToBackend/models"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func VerifyLetter(ctx *gin.Context, letterId string) bool {
	getCookie, errCookie := ctx.Cookie(letterId + "-" + os.Getenv("KEY_SES_LETTER"))
	if getCookie == "" || errCookie != nil {
		return false
	}
	var letterInfo models.LetterSession
	getDb := config.DB.Table("letter_sessions").
		Where("LOWER(session_id) = ?", strings.ToLower(getCookie)).First(&letterInfo)

	if getDb.RowsAffected < 1 {
		return false
	}

	if letterInfo.LetterID != letterId {
		return false
	}

	return true
}
