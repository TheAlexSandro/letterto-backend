package middleware

import (
	"LetterToBackend/config"
	"LetterToBackend/models"
	"LetterToBackend/pkg/utils"
	"os"

	"github.com/gin-gonic/gin"
)

func VerifyLetter(ctx *gin.Context) bool {
	getCookie, errCookie := ctx.Cookie(os.Getenv("KEY_SES_LETTER"))
	if getCookie == "" || errCookie != nil {
		return false
	}

	decodeCookie, deErr := utils.DecodeCookie(os.Getenv("KEY_SES_LETTER"), getCookie)
	if deErr != nil {
		return false
	}

	var letterSession models.LetterSession
	getDb := config.DB.Table("letter_sessions").Select("session_id").Where("session_id = ?", decodeCookie).First(&letterSession)
	if getDb.RowsAffected < 1 {
		return false
	}

	if decodeCookie != letterSession.SessionID {
		return false
	}

	return true
}
