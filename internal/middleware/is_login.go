package middleware

import (
	"LetterToBackend/config"
	"LetterToBackend/models"
	"LetterToBackend/pkg/utils"
	"os"

	"time"

	"github.com/gin-gonic/gin"
)

func IsLogin(ctx *gin.Context) (bool, *models.User) {
	getCookie, err := ctx.Cookie(os.Getenv("KEY_SES_USER"))
	if getCookie == "" || err != nil {
		return false, nil
	}

	decodeCookie, deErr := utils.DecodeCookie(os.Getenv("KEY_SES_USER"), getCookie)
	if deErr != nil {
		return false, nil
	}

	var user models.User
	result := config.DB.Table("users").
		Select("users.user_id", "users.name", "users.username", "users.password").
		Joins("JOIN sessions ON sessions.user_id = users.user_id").
		Where("sessions.refresh_token = ? AND sessions.expires_at > ?", decodeCookie, time.Now()).
		First(&user)

	if result.Error != nil || result.RowsAffected < 0 {
		return false, nil
	}

	return true, &user
}
