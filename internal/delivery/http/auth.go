package http

import (
	"LetterToBackend/config"
	"LetterToBackend/models"
	"LetterToBackend/pkg/utils"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type SignUp struct {
	Name     string `json:"name" binding:"required"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type SignIn struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func Auth(r *gin.Engine) {
	Auth := r.Group("/auth")
	{
		Auth.POST("/signUp", func(ctx *gin.Context) {
			var value SignUp
			var errJson models.ErrorDetail

			if err := ctx.ShouldBindJSON(&value); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "name, username, password", 1), nil, "")
				return
			}

			var t string
			getUser := config.DB.Table("users").Select("user_id", "name", "username").
				Where("username = ?", value.Username).
				Limit(1).Scan(&t)

			if getUser.RowsAffected > 0 {
				utils.GetErrorJson("USER_ALREADY_EXIST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if !utils.ValidateLength(ctx, value.Password, "Password") || !utils.ValidateLength(ctx, value.Username, "Username") || !utils.ValidateLength(ctx, value.Name, "Name") {
				return
			}

			if !utils.RegexFormat(value.Username, ctx, "Username") || !utils.RegexFormat(value.Password, ctx, "Password") {
				return
			}

			hashedPw, err := utils.HashPassword(value.Password)
			if err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}
			userId := utils.GenerateID(10)
			refreshToken := utils.GenerateID(50)

			newUser := models.User{
				UserID:   userId,
				Name:     value.Name,
				Username: value.Username,
				Password: string(hashedPw),
				Profile:  "-",
			}

			newSession := models.Session{
				RefreshToken: refreshToken,
				UserID:       userId,
				ExpiresAt:    utils.NowTz().Add(utils.GetExpiry()),
				LoginAt:      utils.NowTz(),
			}

			if err := config.DB.Table("users").Create(&newUser).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, "Error creating new user...", nil, errJson.Code)
				return
			}

			if err := config.DB.Table("sessions").Create(&newSession).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			signedValue, cookieErr := utils.EncodeCookie(os.Getenv("KEY_SES_USER"), refreshToken)
			if cookieErr != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			timeout, _ := strconv.Atoi(os.Getenv("COOKIE_TIMEOUT"))
			http.SetCookie(ctx.Writer, &http.Cookie{
				Name:     os.Getenv("KEY_SES_USER"),
				Value:    signedValue,
				Path:     "/",
				MaxAge:   timeout,
				HttpOnly: true,
				Secure:   true,
				SameSite: utils.SetCookieSameSite(),
				Domain:   os.Getenv("DOMAIN"),
			})

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		Auth.POST("/signIn", func(ctx *gin.Context) {
			var value SignIn
			var errJson models.ErrorDetail
			var user models.User

			if err := ctx.ShouldBindJSON(&value); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "username, password", 1), nil, errJson.Code)
				return
			}

			getUser := config.DB.Table("users").Select("user_id", "password").
				Where("username = ?", value.Username).
				First(&user)

			if getUser.RowsAffected < 1 {
				utils.GetErrorJson("USER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			checkPw := utils.CheckPasswordHash(value.Password, user.Password)
			if !checkPw {
				utils.GetErrorJson("INVALID_PASSWORD", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			refreshToken := utils.GenerateID(50)
			newSession := models.Session{
				RefreshToken: refreshToken,
				UserID:       user.UserID,
				ExpiresAt:    utils.NowTz().Add(utils.GetExpiry()),
				LoginAt:      utils.NowTz(),
			}

			if err := config.DB.Table("sessions").Create(&newSession).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			signedValue, cookieErr := utils.EncodeCookie(os.Getenv("KEY_SES_USER"), refreshToken)
			if cookieErr != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			timeout, _ := strconv.Atoi(os.Getenv("COOKIE_TIMEOUT"))
			http.SetCookie(ctx.Writer, &http.Cookie{
				Name:     os.Getenv("KEY_SES_USER"),
				Value:    signedValue,
				Path:     "/",
				MaxAge:   timeout,
				HttpOnly: true,
				Secure:   true,
				SameSite: utils.SetCookieSameSite(),
				Domain:   os.Getenv("DOMAIN"),
			})

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})
	}
}
