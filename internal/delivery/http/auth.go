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

type VerifyUsername struct {
	Username string `json:"username" binding:"required"`
	Method   string `json:"method" binding:"required"`
}

func Auth(r *gin.Engine) {
	auth := r.Group("/auth")
	{
		auth.POST("/verifyUsername", func(ctx *gin.Context) {
			var value VerifyUsername
			var errJson models.ErrorDetail
			var user models.User

			if err := ctx.ShouldBindJSON(&value); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "username, method", 1), nil, errJson.Code)
				return
			}

			if !utils.ValidateLength(ctx, value.Username, "Username") || !utils.RegexFormat(value.Username, ctx, "Username") {
				return
			}

			getUser := config.DB.Table("users").Select("user_id").
				Where("LOWER(username) = ?", strings.ToLower(value.Username)).
				First(&user)

			if getUser.RowsAffected < 1 && value.Method == "signin" {
				utils.GetErrorJson("USER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if getUser.RowsAffected > 0 && value.Method == "signup" {
				utils.GetErrorJson("USER_ALREADY_EXIST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		auth.POST("/signUp", func(ctx *gin.Context) {
			var value SignUp
			var errJson models.ErrorDetail

			isMaintenance := os.Getenv("MAINTENANCE")
			if isMaintenance == "true" {
				utils.GetErrorJson("MAINTENANCE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := ctx.ShouldBindJSON(&value); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "name, username, password", 1), nil, "")
				return
			}

			var t string
			getUser := config.DB.Table("users").Select("user_id", "name", "username").
				Where("LOWER(username) = ?", strings.ToLower(value.Username)).
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

			newUser := models.User{
				UserID:   userId,
				Name:     value.Name,
				Username: value.Username,
				Password: string(hashedPw),
				Profile:  "-",
			}

			if err := config.DB.Table("users").Create(&newUser).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, "Error creating new user...", nil, errJson.Code)
				return
			}

			refreshToken := utils.GenerateID(50)
			newSession := models.Session{
				RefreshToken: refreshToken,
				UserID:       userId,
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

			loginId := utils.GenerateID(50)
			lastLogTimeout, _ := strconv.Atoi(os.Getenv("LAST_LOGIN_TIMEOUT"))

			loginIdSes := models.LoginIdSession{
				UserId:  userId,
				LoginId: loginId,
			}

			http.SetCookie(ctx.Writer, &http.Cookie{
				Name:     os.Getenv("KEY_LAST_LOGIN"),
				Value:    loginId,
				Path:     "/",
				MaxAge:   lastLogTimeout,
				HttpOnly: true,
				Secure:   true,
				SameSite: utils.SetCookieSameSite(),
				Domain:   os.Getenv("DOMAIN"),
			})

			var ind string
			getDb := config.DB.Table("login_id_sessions").Select("login_id").Where("LOWER(user_id) = ?", strings.ToLower(userId)).Limit(1).Scan(&ind)
			if getDb.RowsAffected < 1 {
				if err := config.DB.Table("login_id_sessions").Create(&loginIdSes).Error; err != nil {
					utils.GetErrorJson("BAD_REQUEST", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
					return
				}
			} else {
				updateData := map[string]interface{}{
					"user_id":  userId,
					"login_id": loginId,
				}

				if err := config.DB.Table("login_id_sessions").Where("LOWER(user_id) = ?", strings.ToLower(userId)).Updates(updateData).Error; err != nil {
					utils.GetErrorJson("BAD_REQUEST", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
					return
				}
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		auth.POST("/signIn", func(ctx *gin.Context) {
			var value SignIn
			var errJson models.ErrorDetail
			var user models.User

			if err := ctx.ShouldBindJSON(&value); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "username, password", 1), nil, errJson.Code)
				return
			}

			getUser := config.DB.Table("users").Select("user_id", "password").
				Where("LOWER(username) = ?", strings.ToLower(value.Username)).
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

			loginId := utils.GenerateID(50)
			lastLogTimeout, _ := strconv.Atoi(os.Getenv("LAST_LOGIN_TIMEOUT"))

			loginIdSes := models.LoginIdSession{
				UserId:  user.UserID,
				LoginId: loginId,
			}

			http.SetCookie(ctx.Writer, &http.Cookie{
				Name:     os.Getenv("KEY_LAST_LOGIN"),
				Value:    loginId,
				Path:     "/",
				MaxAge:   lastLogTimeout,
				HttpOnly: true,
				Secure:   true,
				SameSite: utils.SetCookieSameSite(),
				Domain:   os.Getenv("DOMAIN"),
			})

			var ind string
			getDb := config.DB.Table("login_id_sessions").Select("login_id").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Limit(1).Scan(&ind)
			if getDb.RowsAffected < 1 {
				if err := config.DB.Table("login_id_sessions").Create(&loginIdSes).Error; err != nil {
					utils.GetErrorJson("BAD_REQUEST", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
					return
				}
			} else {
				updateData := map[string]interface{}{
					"user_id":  user.UserID,
					"login_id": loginId,
				}

				if err := config.DB.Table("login_id_sessions").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Updates(updateData).Error; err != nil {
					utils.GetErrorJson("BAD_REQUEST", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
					return
				}
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		auth.GET("/getLastLogin", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			getCookie, err := ctx.Cookie(os.Getenv("KEY_LAST_LOGIN"))
			if getCookie == "" || err != nil {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var loginData models.LoginIdSession
			getDb := config.DB.Table("login_id_sessions").Where("LOWER(login_id) = ?", strings.ToLower(getCookie)).Select("user_id").First(&loginData)
			if getDb.RowsAffected < 1 {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var user models.User
			if err := config.DB.Table("users").Where("LOWER(user_id) = ?", strings.ToLower(loginData.UserId)).First(&user).Error; err != nil {
				utils.GetErrorJson("USER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"name": user.Name, "username": user.Username}, "")
		})
	}
}
