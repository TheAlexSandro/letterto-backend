package http

import (
	"LetterToBackend/config"
	"LetterToBackend/internal/middleware"
	"LetterToBackend/models"
	"LetterToBackend/pkg/utils"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

type UserResponse struct {
	Name        string `json:"name"`
	Username    string `json:"username"`
	NewPassword string `json:"new_password"`
	OldPassword string `json:"old_password"`
}

type Email struct {
	Email  string `json:"email"`
	Code   string `json:"code"`
	Action string `json:"action"`
}

type VerifyOTP struct {
	Code   string `json:"code"`
	Action string `json:"action"`
}

type VerifyTOTP struct {
	Secret string `form:"secret"`
	Code   string `form:"code"`
}

type VerifyIdentity struct {
	Model    string `json:"model" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UsersList struct {
	Offset string `form:"offset"`
}

type UserSearch struct {
	Name   string `form:"name"`
	Role   string `form:"role"`
	Offset string `form:"offset" binding:"required"`
}

type ChangeRole struct {
	UserId string `json:"user_id" binding:"required"`
	Role   string `json:"role" binding:"required"`
}

type ChangePass struct {
	UserId   string `json:"user_id" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func User(r *gin.Engine) {
	user := r.Group("user")
	{
		user.POST("/edit", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var value UserResponse

			isMaintenance := os.Getenv("MAINTENANCE")
			if isMaintenance == "true" {
				utils.GetErrorJson("MAINTENANCE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}
			ctx.ShouldBindJSON(&value)

			if value.Name == "" && value.Username == "" && value.NewPassword == "" && value.OldPassword == "" {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "one of name, username, password", 1), nil, errJson.Code)
				return
			}

			checks := []struct {
				condition bool
				feature   string
			}{
				{value.Name != user.Name, "change_name"},
				{value.Username != user.Username, "change_username"},
				{value.NewPassword != "" || value.OldPassword != "", "change_password"},
			}

			for _, c := range checks {
				if c.condition && !utils.HasFeature(user.AccountFeature, c.feature) {
					utils.GetErrorJson("FEATURE_UNAVAILABLE", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
					return
				}
			}

			if user.Role == "banned" && (value.Name != "" || value.Username != "") {
				utils.GetErrorJson("BANNED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if (value.NewPassword != "" && !utils.ValidateLength(ctx, value.NewPassword, "Password")) || (value.Username != "" && !utils.ValidateLength(ctx, value.Username, "Username")) || (value.Name != "" && !utils.ValidateLength(ctx, value.Name, "Name")) {
				return
			}

			if (value.Username != "" && !utils.RegexFormat(value.Username, ctx, "Username")) || (value.NewPassword != "" && !utils.RegexFormat(value.NewPassword, ctx, "Password")) {
				return
			}

			if value.NewPassword != "" && value.OldPassword == "" {
				utils.GetErrorJson("OPTIONAL_PARAMETER_REQUIRED", &errJson)
				rplc := strings.NewReplacer("{opt_param}", "old_password", "{param}", "password")
				utils.JSON(ctx, errJson.Http, false, rplc.Replace(errJson.Message), nil, errJson.Code)
				return
			}

			if value.OldPassword != "" && value.NewPassword == "" {
				utils.JSON(ctx, 400, false, "You forget something?", nil, "FORGET?")
				return
			}

			if value.NewPassword != "" && value.OldPassword != "" {
				if !utils.ValidateLength(ctx, value.NewPassword, "Password") {
					return
				}

				verify := utils.CheckPasswordHash(value.OldPassword, user.Password)
				if !verify {
					utils.GetErrorJson("INVALID_PASSWORD", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
					return
				}
				hash, _ := utils.HashPassword(value.NewPassword)
				value.NewPassword = hash
			} else {
				value.NewPassword = user.Password
			}

			if value.Username != user.Username {
				var t string
				verif := config.DB.Table("users").Select("username").Where("username = ?", value.Username).Limit(1).Scan(&t)

				if verif.RowsAffected > 0 {
					utils.GetErrorJson("ID_OCCUPIED", &errJson)
					msg := strings.Replace(errJson.Message, "{id}", value.Username, 1)
					utils.JSON(ctx, errJson.Http, false, msg, nil, errJson.Code)
					return
				}
			}

			if value.Name == "" {
				value.Name = user.Name
			}

			if value.Username == "" {
				value.Username = user.Username
			}

			editProfile := models.User{
				UserID:                user.UserID,
				Name:                  value.Name,
				Username:              value.Username,
				Password:              value.NewPassword,
				Profile:               "-",
				Role:                  user.Role,
				AccountFeature:        user.AccountFeature,
				LetterFeature:         user.LetterFeature,
				Email:                 user.Email,
				AuthCode:              user.AuthCode,
				BackupCodesGeneration: user.BackupCodesGeneration,
			}

			if dbErr := config.DB.Table("users").Save(&editProfile).Error; dbErr != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		user.POST("/logout", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			isMaintenance := os.Getenv("MAINTENANCE")
			if isMaintenance == "true" {
				utils.GetErrorJson("MAINTENANCE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			config.DB.Table("cookie_sessions").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Delete(&models.CookieSession{})
			config.DB.Where("user_id = ?", user.UserID).Delete(&models.Session{})
			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		user.GET("/accountInfo", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"user_id": user.UserID, "name": user.Name, "username": user.Username, "role": user.Role}, "")
		})

		user.GET("/accountFeature", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"feature": utils.ToArray(user.AccountFeature)}, "")
		})

		user.GET("/letterFeature", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"feature": utils.ToArray(user.LetterFeature)}, "")
		})

		user.GET("/2faStatus", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var email *string
			if user.Email == "-" {
				email = nil
			} else {
				parts := strings.Split(user.Email, "@")
				if len(parts) != 2 {
					email = &user.Email
					return
				}

				username := parts[0]
				domain := parts[1]
				length := len(username)
				if length <= 2 {
					e := strings.Repeat("*", length) + "@" + domain
					email = &e
					return
				}

				first := string(username[0])
				last := string(username[length-1])

				stars := strings.Repeat("*", length-2)

				e := first + stars + last + "@" + domain
				email = &e
			}

			var totp bool
			if user.AuthCode == "-" {
				totp = false
			} else {
				totp = true
			}

			var t string
			getBC := config.DB.Table("backup_codes").
				Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Limit(1).Scan(&t)

			var backup_code bool
			if getBC.RowsAffected < 1 {
				backup_code = false
			} else {
				backup_code = true
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{
				"email":       email,
				"totp":        totp,
				"backup_code": backup_code,
			}, "")
		})

		user.POST("/verifyEmail", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input Email

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}
			ctx.ShouldBindJSON(&input)
			if input.Action == "" {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "email, code, action", 1), nil, errJson.Code)
				return
			}

			if input.Email != "" && !strings.Contains(input.Email, "@") {
				utils.GetErrorJson("INVALID_EMAIL", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if strings.EqualFold(user.Email, input.Email) {
				utils.GetErrorJson("EMAIL_USED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var mail string
			if input.Email == "" && user.Email != "-" {
				mail = user.Email
			} else if input.Email != "" {
				mail = input.Email
			} else if input.Email == "" && user.Email == "-" {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "email, code, action", 1), nil, errJson.Code)
				return
			}

			var existing models.Otp
			getExisting := config.DB.Table("otps").Select("expires_at", "email").
				Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).
				First(&existing)

			if getExisting.RowsAffected > 0 && utils.NowTz().Before(existing.ExpiresAt) && strings.EqualFold(mail, existing.Email) {
				utils.GetErrorJson("COOLDOWN", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, gin.H{
					"expires_at": existing.ExpiresAt.Unix(),
				}, errJson.Code)
				return
			}

			otp, _ := utils.GenerateOtp()
			hashed := utils.HashCode(otp)
			loadClient := utils.NewBrevoClient()
			sendOtp := loadClient.SendOTP(mail, otp, hashed, user.UserID, user.Name)

			if sendOtp != nil {
				if err := sendOtp.Error(); err != "" {
					fmt.Println(err)
					utils.GetErrorJson("BAD_REQUEST", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
					return
				}
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		user.POST("/verifyIdentity", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input VerifyIdentity

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := ctx.ShouldBindJSON(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "password, model", 1), nil, errJson.Code)
				return
			}

			if !utils.ValidateEnum(ctx, "model", input.Model, []string{"vin.sid", "vem.sid"}) {
				return
			}

			checkPw := utils.CheckPasswordHash(input.Password, user.Password)
			if !checkPw {
				utils.GetErrorJson("INVALID_PASSWORD", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			config.DB.Table("cookie_sessions").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Delete(&models.CookieSession{})

			genId := utils.GenerateID(50)
			enc, encErr := utils.EncryptCookie(genId)
			if encErr != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			otpSessionData := models.CookieSession{
				SessionId: enc,
				UserId:    user.UserID,
				Name:      input.Model,
			}

			if err := config.DB.Table("cookie_sessions").Create(otpSessionData).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			cExpire, _ := strconv.Atoi(os.Getenv("C_SID_EXPIRE"))
			http.SetCookie(ctx.Writer, &http.Cookie{
				Name:     input.Model,
				Value:    enc,
				Path:     "/",
				MaxAge:   cExpire,
				HttpOnly: true,
				Secure:   true,
				SameSite: utils.SetCookieSameSite(),
				Domain:   os.Getenv("DOMAIN"),
			})

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		user.GET("/isVEM", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			getEncC, err := ctx.Cookie("vem.sid")
			if err != nil || !utils.VerifySignature(getEncC) {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var sessionCookie models.CookieSession
			getOtpSDb := config.DB.Table("cookie_sessions").Select("name").
				Where("LOWER(session_id) = ? AND LOWER(user_id) = ?", strings.ToLower(getEncC), strings.ToLower(user.UserID)).
				First(&sessionCookie)

			if getOtpSDb.RowsAffected < 1 || sessionCookie.Name != "vem.sid" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		user.POST("/addEmail", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input Email

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := ctx.ShouldBindJSON(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "email, code", 1), nil, errJson.Code)
				return
			}

			hashOtp := utils.HashCode(input.Code)

			var otpData models.Otp
			getOtpDb := config.DB.Table("otps").Select("otp", "expires_at").
				Where("LOWER(otp) = ? AND LOWER(user_id) = ?", strings.ToLower(hashOtp), strings.ToLower(user.UserID)).
				First(&otpData)

			if getOtpDb.RowsAffected < 1 {
				utils.GetErrorJson("INVALID_VERIFICATION_CODE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if !utils.VerifyOTP(otpData.Otp, hashOtp, otpData.ExpiresAt) {
				utils.GetErrorJson("INVALID_VERIFICATION_CODE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if user.Email != "-" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if !strings.Contains(input.Email, "@") {
				utils.GetErrorJson("INVALID_EMAIL", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			config.DB.Table("otps").Where("LOWER(otp) = ? AND LOWER(user_id) = ?", strings.ToLower(hashOtp), strings.ToLower(user.UserID)).Delete(&models.Otp{})

			if err := config.DB.Table("users").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Updates(map[string]interface{}{
				"email": input.Email,
			}).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		user.POST("/editEmail", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input Email

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			getEncC, err := ctx.Cookie("vem.sid")
			if err != nil || !utils.VerifySignature(getEncC) {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var sessionCookie models.CookieSession
			getOtpSDb := config.DB.Table("cookie_sessions").Select("name").
				Where("LOWER(session_id) = ? AND LOWER(user_id) = ?", strings.ToLower(getEncC), strings.ToLower(user.UserID)).
				First(&sessionCookie)

			if getOtpSDb.RowsAffected < 1 || sessionCookie.Name != "vem.sid" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := ctx.ShouldBindJSON(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "email, code", 1), nil, errJson.Code)
				return
			}

			hashOtp := utils.HashCode(input.Code)

			var otpData models.Otp
			getOtpDb := config.DB.Table("otps").Select("otp", "expires_at").
				Where("LOWER(otp) = ? AND LOWER(user_id) = ?", strings.ToLower(hashOtp), strings.ToLower(user.UserID)).
				First(&otpData)

			if getOtpDb.RowsAffected < 1 {
				utils.GetErrorJson("INVALID_VERIFICATION_CODE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if !utils.VerifyOTP(otpData.Otp, hashOtp, otpData.ExpiresAt) {
				utils.GetErrorJson("INVALID_VERIFICATION_CODE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if user.Email == "-" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if !strings.Contains(input.Email, "@") {
				utils.GetErrorJson("INVALID_EMAIL", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			config.DB.Table("otps").Where("LOWER(otp) = ? AND LOWER(user_id) = ?", strings.ToLower(hashOtp), strings.ToLower(user.UserID)).Delete(&models.Otp{})

			if err := config.DB.Table("users").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Updates(map[string]interface{}{
				"email": input.Email,
			}).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		user.POST("/rmEmail", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			getEncC, err := ctx.Cookie("vem.sid")
			if err != nil || !utils.VerifySignature(getEncC) {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var sessionCookie models.CookieSession
			getOtpSDb := config.DB.Table("cookie_sessions").Select("name").
				Where("LOWER(session_id) = ? AND LOWER(user_id) = ?", strings.ToLower(getEncC), strings.ToLower(user.UserID)).
				First(&sessionCookie)

			if getOtpSDb.RowsAffected < 1 || sessionCookie.Name != "vem.sid" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := config.DB.Table("users").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Updates(map[string]interface{}{
				"email": "-",
			}).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		user.POST("/setupTOTP", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if user.AuthCode != "-" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			gen, errTOTP := totp.Generate(totp.GenerateOpts{
				Issuer:      "LetterTo",
				AccountName: user.Username,
			})
			if errTOTP != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{
				"secret": gen.Secret(),
				"uri":    gen.URL(),
			}, "")
		})

		user.POST("/verifyTOTP", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input VerifyTOTP

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			ctx.ShouldBind(&input)
			if input.Secret == "" || input.Code == "" {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "secret, code", 1), nil, errJson.Code)
				return
			}

			isValid := totp.Validate(input.Code, input.Secret)
			if !isValid {
				utils.GetErrorJson("INVALID_VERIFICATION_CODE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := config.DB.Table("users").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Updates(map[string]interface{}{
				"auth_code": input.Secret,
			}).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		user.POST("/disableTOTP", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input VerifyTOTP

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			ctx.ShouldBind(&input)
			if input.Code == "" {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "code", 1), nil, errJson.Code)
				return
			}

			if user.AuthCode == "-" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			isValid := totp.Validate(input.Code, user.AuthCode)
			if !isValid {
				utils.GetErrorJson("INVALID_VERIFICATION_CODE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := config.DB.Table("users").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Updates(map[string]interface{}{
				"auth_code": "-",
			}).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		user.POST("/generateBC", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			getEncC, err := ctx.Cookie("vin.sid")
			if err != nil || !utils.VerifySignature(getEncC) {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var sessionOtp models.CookieSession
			getOtpSDb := config.DB.Table("cookie_sessions").Select("name").
				Where("LOWER(session_id) = ? AND LOWER(user_id) = ?", strings.ToLower(getEncC), strings.ToLower(user.UserID)).
				First(&sessionOtp)

			if getOtpSDb.RowsAffected < 1 || sessionOtp.Name != "vin.sid" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if user.BackupCodesGeneration != nil {
				const cooldown = 3 * 24 * time.Hour
				nextAllowedAt := user.BackupCodesGeneration.Add(cooldown)
				if time.Now().Before(nextAllowedAt) {
					utils.GetErrorJson("RATE_LIMITED", &errJson)
					utils.JSON(ctx, errJson.Http, false, "Backup code can only be generated every 3 days at once.", nil, errJson.Code)
					return
				}
			}

			const count = 10
			plainCodes, err := utils.GenerateBackupCodes(count)
			if err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			rows := make([]models.BackupCode, 0, count)
			for _, c := range plainCodes {
				id := utils.GenerateID(20)
				cd, _ := utils.EncryptDeterministic(c)
				rows = append(rows, models.BackupCode{
					BackupCodeId: id,
					UserID:       user.UserID,
					CodeHash:     cd,
					Used:         "no",
				})
			}

			txErr := config.DB.Transaction(func(tx *gorm.DB) error {
				if err := tx.Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).
					Delete(&models.BackupCode{}).Error; err != nil {
					return err
				}
				return tx.Create(&rows).Error
			})

			if txErr != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := config.DB.Table("users").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Updates(map[string]interface{}{
				"backup_codes_generation": utils.NowTz(),
			}).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{
				"backup_codes": plainCodes,
				"generated_on": utils.NowTz().Format("02/01/06"),
			}, "")
		})

		user.GET("/showBC", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			getEncC, err := ctx.Cookie("vin.sid")
			if err != nil || !utils.VerifySignature(getEncC) {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var sessionOtp models.CookieSession
			getOtpSDb := config.DB.Table("cookie_sessions").Select("name").
				Where("LOWER(session_id) = ? AND LOWER(user_id) = ?", strings.ToLower(getEncC), strings.ToLower(user.UserID)).
				First(&sessionOtp)

			if getOtpSDb.RowsAffected < 1 || sessionOtp.Name != "vin.sid" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var backupCodeData []models.BackupCode
			getDb := config.DB.Table("backup_codes").Select("code_hash", "used", "created_at").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Find(&backupCodeData)

			if getDb.RowsAffected < 1 {
				utils.GetErrorJson("NOT_GENERATED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			rows := make([]string, 0, len(backupCodeData))
			for _, c := range backupCodeData {
				cd, _ := utils.Decrypt(c.CodeHash)
				if c.Used == "yes" {
					rows = append(rows, strings.Repeat("-", len(cd)))
				} else {
					rows = append(rows, cd)
				}
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{
				"backup_codes": rows,
				"generated_on": backupCodeData[0].CreatedAt.Format("02/01/06"),
			}, "")
		})

		user.POST("/removeBC", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			getEncC, err := ctx.Cookie("vin.sid")
			if err != nil || !utils.VerifySignature(getEncC) {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var sessionOtp models.CookieSession
			getOtpSDb := config.DB.Table("cookie_sessions").Select("name").
				Where("LOWER(session_id) = ? AND LOWER(user_id) = ?", strings.ToLower(getEncC), strings.ToLower(user.UserID)).
				First(&sessionOtp)

			if getOtpSDb.RowsAffected < 1 || sessionOtp.Name != "vin.sid" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var backupCodeData []models.BackupCode
			getDb := config.DB.Table("backup_codes").Select("code_hash", "used", "created_at").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Find(&backupCodeData)

			if getDb.RowsAffected < 1 {
				utils.GetErrorJson("NOT_GENERATED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := config.DB.Table("backup_codes").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Delete(&models.BackupCode{}).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		user.GET("/users", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var value UsersList

			verify, user := middleware.IsLogin(ctx)
			if !verify || !(user.Role == "owner" || user.Role == "admin") {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}
			ctx.ShouldBind(&value)
			if value.Offset == "" {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "offset", 1), nil, errJson.Code)
				return
			}

			offset, err := strconv.Atoi(value.Offset)
			if err != nil || offset < 0 {
				utils.GetErrorJson("PARAMETER_INVALID", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "offset", 1), nil, errJson.Code)
				return
			}

			const limit = 20

			var users []models.User
			var total int64

			if err := config.DB.Model(&models.User{}).Count(&total).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := config.DB.
				Limit(limit).
				Offset(offset).
				Find(&users).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "success", gin.H{
				"users":  users,
				"total":  total,
				"limit":  limit,
				"offset": offset,
			}, "")
		})

		user.GET("/searchUser", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var value UserSearch

			verify, user := middleware.IsLogin(ctx)
			if !verify || !(user.Role == "owner" || user.Role == "admin") {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}
			ctx.ShouldBind(&value)
			if value.Offset == "" {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "name, offset", 1), nil, errJson.Code)
				return
			}

			offset, err := strconv.Atoi(value.Offset)
			if err != nil || offset < 0 {
				utils.GetErrorJson("PARAMETER_INVALID", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "offset", 1), nil, errJson.Code)
				return
			}

			const limit = 20
			query := config.DB.Model(&models.User{})
			if value.Name != "" {
				keyword := "%" + value.Name + "%"
				query = query.Where(
					config.DB.
						Where("name ILIKE ?", keyword).
						Or("username ILIKE ?", keyword),
				)
			}
			if value.Role != "" {
				query = query.Where("role = ?", value.Role)
			}

			var total int64
			if err := query.Count(&total).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var users []models.User
			if err := query.
				Limit(limit).
				Offset(offset).
				Find(&users).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "success", gin.H{
				"users":  users,
				"total":  total,
				"limit":  limit,
				"offset": offset,
			}, "")
		})

		user.POST("/changeRole", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var value ChangeRole
			var users models.User

			isMaintenance := os.Getenv("MAINTENANCE")
			if isMaintenance == "true" {
				utils.GetErrorJson("MAINTENANCE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			verify, user := middleware.IsLogin(ctx)
			if !verify || !(user.Role == "owner" || user.Role == "admin") {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}
			ctx.ShouldBindJSON(&value)
			if value.UserId == "" || value.Role == "" {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "user_id, role", 1), nil, errJson.Code)
				return
			}

			getUser := config.DB.Table("users").
				Where("LOWER(user_id) = ?", strings.ToLower(value.UserId)).
				First(&users)

			if getUser.RowsAffected < 1 {
				utils.GetErrorJson("USER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if users.Role == "owner" {
				utils.GetErrorJson("ROLE_LOCKED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			editProfile := models.User{
				UserID:   users.UserID,
				Name:     users.Name,
				Username: users.Username,
				Password: users.Password,
				Profile:  "-",
				Role:     value.Role,
			}

			if dbErr := config.DB.Table("users").Save(&editProfile).Error; dbErr != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		user.POST("/changePass", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var value ChangePass
			var users models.User

			isMaintenance := os.Getenv("MAINTENANCE")
			if isMaintenance == "true" {
				utils.GetErrorJson("MAINTENANCE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			verify, user := middleware.IsLogin(ctx)
			if !verify || !(user.Role == "owner" || user.Role == "admin") {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}
			ctx.ShouldBindJSON(&value)
			if value.UserId == "" || value.Password == "" {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "user_id, password", 1), nil, errJson.Code)
				return
			}

			getUser := config.DB.Table("users").
				Where("LOWER(user_id) = ?", strings.ToLower(value.UserId)).
				First(&users)

			if getUser.RowsAffected < 1 {
				utils.GetErrorJson("USER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if users.Role == "owner" {
				utils.GetErrorJson("ROLE_LOCKED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			hashedPw, err := utils.HashPassword(value.Password)
			if err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			editProfile := models.User{
				UserID:   users.UserID,
				Name:     users.Name,
				Username: users.Username,
				Password: hashedPw,
				Profile:  "-",
				Role:     users.Role,
			}

			if dbErr := config.DB.Table("users").Save(&editProfile).Error; dbErr != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})
	}
}
