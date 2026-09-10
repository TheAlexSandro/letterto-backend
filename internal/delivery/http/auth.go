package http

import (
	"LetterToBackend/config"
	"LetterToBackend/models"
	"LetterToBackend/pkg/utils"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
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

type Mfa struct {
	UserId string `json:"user_id" binding:"required"`
}

type VerifyMfa struct {
	UserId string `json:"user_id" binding:"required"`
	Code   string `json:"code" binding:"required"`
	Type   string `json:"type" binding:"required"`
}

func Auth(r *gin.Engine) {
	auth := r.Group("/auth")
	{
		auth.POST("/verifyUsername", func(ctx *gin.Context) {
			var value VerifyUsername
			var errJson models.ErrorDetail

			if err := ctx.ShouldBindJSON(&value); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "username, method", 1), nil, errJson.Code)
				return
			}

			if !utils.ValidateLength(ctx, value.Username, "Username") || !utils.RegexFormat(value.Username, ctx, "Username") {
				return
			}

			var user models.User
			getUser := config.DB.Table("users").Select("user_id", "email", "auth_code").
				Where("LOWER(username) = ?", strings.ToLower(value.Username)).
				First(&user)

			if getUser.RowsAffected < 1 && value.Method == "signin" {
				utils.GetErrorJson("USER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			} else if getUser.RowsAffected > 0 && value.Method == "signin" {
				var count int64
				config.DB.Table("backup_codes").
					Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).
					Count(&count)

				if user.Email != "-" || user.AuthCode != "-" || count > 0 {
					utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"is_mfa_active": true}, "")
				} else {
					utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"is_mfa_active": false}, "")
				}
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

			timeout, _ := strconv.Atoi(os.Getenv("SES_EXP"))
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
			expiresAt := utils.NowTz().Add(time.Duration(lastLogTimeout) * time.Second)
			oldLoginId, oldErr := ctx.Cookie(os.Getenv("KEY_LAST_LOGIN"))

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

			rewritten := false
			if oldErr == nil && oldLoginId != "" {
				result := config.DB.Table("login_id_sessions").
					Where("LOWER(login_id) = ?", strings.ToLower(oldLoginId)).
					Updates(map[string]interface{}{
						"user_id":    userId,
						"login_id":   loginId,
						"expires_at": expiresAt,
					})

				if result.Error == nil && result.RowsAffected > 0 {
					rewritten = true
				}
			}

			if !rewritten {
				loginIdSes := models.LoginIdSession{
					UserId:    userId,
					LoginId:   loginId,
					ExpiresAt: expiresAt,
				}
				if err := config.DB.Table("login_id_sessions").Create(&loginIdSes).Error; err != nil {
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

			if err := ctx.ShouldBindJSON(&value); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "username, password", 1), nil, errJson.Code)
				return
			}

			var user models.User
			getUser := config.DB.Table("users").Select("user_id", "password", "email", "auth_code", "name").
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

			var t string
			getBC := config.DB.Table("backup_codes").
				Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Limit(1).Scan(&t)
			var mfa string
			if user.AuthCode != "-" {
				mfa = "totp"
			} else if user.Email != "-" {
				mfa = "email"
				otp, _ := utils.GenerateOtp()
				hashed := utils.HashCode(otp)
				loadClient := utils.NewBrevoClient()
				sendOtp := loadClient.SendOTP(user.Email, otp, hashed, user.UserID, user.Name)

				if sendOtp != nil {
					if err := sendOtp.Error(); err != "" {
						utils.GetErrorJson("BAD_REQUEST", &errJson)
						utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
						return
					}
				}
			} else if getBC.RowsAffected > 0 {
				mfa = "backup_code"
			}

			config.DB.Table("cookie_sessions").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Delete(&models.CookieSession{})

			if user.Email == "-" && user.AuthCode == "-" && getBC.RowsAffected < 1 {
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

				timeout, _ := strconv.Atoi(os.Getenv("SES_EXP"))
				calc := time.Duration(timeout) * time.Hour
				http.SetCookie(ctx.Writer, &http.Cookie{
					Name:     os.Getenv("KEY_SES_USER"),
					Value:    signedValue,
					Path:     "/",
					MaxAge:   int(calc.Seconds()),
					HttpOnly: true,
					Secure:   true,
					SameSite: utils.SetCookieSameSite(),
					Domain:   os.Getenv("DOMAIN"),
				})

				loginId := utils.GenerateID(50)
				lastLogTimeout, _ := strconv.Atoi(os.Getenv("LAST_LOGIN_TIMEOUT"))
				expiresAt := utils.NowTz().Add(time.Duration(lastLogTimeout) * time.Second)

				oldLoginId, oldErr := ctx.Cookie(os.Getenv("KEY_LAST_LOGIN"))

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

				rewritten := false
				if oldErr == nil && oldLoginId != "" {
					result := config.DB.Table("login_id_sessions").
						Where("LOWER(login_id) = ?", strings.ToLower(oldLoginId)).
						Updates(map[string]interface{}{
							"user_id":    user.UserID,
							"login_id":   loginId,
							"expires_at": expiresAt,
						})

					if result.Error == nil && result.RowsAffected > 0 {
						rewritten = true
					}
				}

				if !rewritten {
					loginIdSes := models.LoginIdSession{
						UserId:    user.UserID,
						LoginId:   loginId,
						ExpiresAt: expiresAt,
					}
					if err := config.DB.Table("login_id_sessions").Create(&loginIdSes).Error; err != nil {
						utils.GetErrorJson("BAD_REQUEST", &errJson)
						utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
						return
					}
				}

				utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
				return
			} else {
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
					Name:      "vlg.sid",
				}

				if err := config.DB.Table("cookie_sessions").Create(otpSessionData).Error; err != nil {
					utils.GetErrorJson("BAD_REQUEST", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
					return
				}

				cExpire, _ := strconv.Atoi(os.Getenv("C_SID_EXPIRE"))
				http.SetCookie(ctx.Writer, &http.Cookie{
					Name:     "vlg.sid",
					Value:    enc,
					Path:     "/",
					MaxAge:   cExpire,
					HttpOnly: true,
					Secure:   true,
					SameSite: utils.SetCookieSameSite(),
					Domain:   os.Getenv("DOMAIN"),
				})

				utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"mfa_type": mfa, "user_id": user.UserID}, "")
				return
			}
		})

		auth.POST("/verifyMfa", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input VerifyMfa

			if err := ctx.ShouldBindJSON(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "user_id, code, type", 1), nil, errJson.Code)
				return
			}

			getEncC, err := ctx.Cookie("vlg.sid")
			if err != nil || !utils.VerifySignature(getEncC) {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var sessionCookie models.CookieSession
			getOtpSDb := config.DB.Table("cookie_sessions").Select("name").
				Where("LOWER(session_id) = ? AND LOWER(user_id) = ?", strings.ToLower(getEncC), strings.ToLower(input.UserId)).
				First(&sessionCookie)

			if getOtpSDb.RowsAffected < 1 || sessionCookie.Name != "vlg.sid" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var user models.User
			getUser := config.DB.Table("users").Select("user_id", "auth_code").
				Where("LOWER(user_id) = ?", strings.ToLower(input.UserId)).
				First(&user)

			if getUser.RowsAffected < 1 {
				utils.GetErrorJson("USER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if input.Type == "totp" {
				isValid := totp.Validate(input.Code, user.AuthCode)
				if !isValid {
					utils.GetErrorJson("INVALID_VERIFICATION_CODE", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
					return
				}
			} else if input.Type == "backup_code" {
				codee := strings.ToLower(strings.Replace(input.Code, "-", "", 0))
				normalized := utils.NormalizeBackupCode(codee)
				hash, _ := utils.EncryptDeterministic(normalized)

				var bc models.BackupCode
				findErr := config.DB.Table("backup_codes").
					Where("LOWER(user_id) = ? AND code_hash = ? AND used = ?", strings.ToLower(input.UserId), hash, "no").
					First(&bc).Error

				if findErr != nil {
					utils.GetErrorJson("INVALID_VERIFICATION_CODE", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
					return
				}
				config.DB.Model(&bc).Updates(models.BackupCode{Used: "yes"})
			} else if input.Type == "email" {
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

				config.DB.Table("otps").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Delete(&models.Otp{})
			}

			config.DB.Table("cookie_sessions").Where("LOWER(user_id) = ?", strings.ToLower(user.UserID)).Delete(&models.CookieSession{})

			refreshToken := utils.GenerateID(50)
			newSession := models.Session{
				RefreshToken: refreshToken,
				UserID:       input.UserId,
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

			timeout, _ := strconv.Atoi(os.Getenv("SES_EXP"))
			calc := time.Duration(timeout) * time.Hour
			http.SetCookie(ctx.Writer, &http.Cookie{
				Name:     os.Getenv("KEY_SES_USER"),
				Value:    signedValue,
				Path:     "/",
				MaxAge:   int(calc.Seconds()),
				HttpOnly: true,
				Secure:   true,
				SameSite: utils.SetCookieSameSite(),
				Domain:   os.Getenv("DOMAIN"),
			})

			loginId := utils.GenerateID(50)
			lastLogTimeout, _ := strconv.Atoi(os.Getenv("LAST_LOGIN_TIMEOUT"))
			expiresAt := utils.NowTz().Add(time.Duration(lastLogTimeout) * time.Second)

			oldLoginId, oldErr := ctx.Cookie(os.Getenv("KEY_LAST_LOGIN"))

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

			rewritten := false
			if oldErr == nil && oldLoginId != "" {
				result := config.DB.Table("login_id_sessions").
					Where("LOWER(login_id) = ?", strings.ToLower(oldLoginId)).
					Updates(map[string]interface{}{
						"user_id":    input.UserId,
						"login_id":   loginId,
						"expires_at": expiresAt,
					})

				if result.Error == nil && result.RowsAffected > 0 {
					rewritten = true
				}
			}

			if !rewritten {
				loginIdSes := models.LoginIdSession{
					UserId:    input.UserId,
					LoginId:   loginId,
					ExpiresAt: expiresAt,
				}
				if err := config.DB.Table("login_id_sessions").Create(&loginIdSes).Error; err != nil {
					utils.GetErrorJson("BAD_REQUEST", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
					return
				}
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		auth.POST("/sendEmailCode", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input Mfa

			if err := ctx.ShouldBindJSON(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "user_id", 1), nil, errJson.Code)
				return
			}

			getEncC, err := ctx.Cookie("vlg.sid")
			if err != nil || !utils.VerifySignature(getEncC) {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var sessionCookie models.CookieSession
			getOtpSDb := config.DB.Table("cookie_sessions").Select("name").
				Where("LOWER(session_id) = ? AND LOWER(user_id) = ?", strings.ToLower(getEncC), strings.ToLower(input.UserId)).
				First(&sessionCookie)

			if getOtpSDb.RowsAffected < 1 || sessionCookie.Name != "vlg.sid" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var userData models.User
			getDb := config.DB.Table("users").Select("user_id", "email", "name").
				Where("LOWER(user_id) = ?", strings.ToLower(input.UserId)).
				First(&userData)

			if getDb.RowsAffected < 1 {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var existing models.Otp
			getExisting := config.DB.Table("otps").Select("expires_at", "email").
				Where("LOWER(user_id) = ?", strings.ToLower(userData.UserID)).
				First(&existing)

			if getExisting.RowsAffected > 0 && utils.NowTz().After(existing.ExpiresAt) && strings.EqualFold(userData.Email, existing.Email) {
				utils.GetErrorJson("COOLDOWN", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, gin.H{
					"expires_at": existing.ExpiresAt.Unix(),
				}, errJson.Code)
				return
			}

			otp, _ := utils.GenerateOtp()
			hashed := utils.HashCode(otp)
			loadClient := utils.NewBrevoClient()
			sendOtp := loadClient.SendOTP(userData.Email, otp, hashed, userData.UserID, userData.Name)

			if sendOtp != nil {
				if err := sendOtp.Error(); err != "" {
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
			getDb := config.DB.Table("login_id_sessions").
				Where("LOWER(login_id) = ?", strings.ToLower(getCookie)).
				First(&loginData)

			if getDb.RowsAffected < 1 {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if loginData.ExpiresAt.Before(utils.NowTz()) {
				config.DB.Table("login_id_sessions").
					Where("login_id = ?", loginData.LoginId).
					Delete(&models.LoginIdSession{})

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

		auth.POST("/get2faMethod", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input Mfa

			if err := ctx.ShouldBindJSON(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "user_id", 1), nil, errJson.Code)
				return
			}

			getEncC, err := ctx.Cookie("vlg.sid")
			if err != nil || !utils.VerifySignature(getEncC) {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var sessionCookie models.CookieSession
			getOtpSDb := config.DB.Table("cookie_sessions").Select("name").
				Where("LOWER(session_id) = ? AND LOWER(user_id) = ?", strings.ToLower(getEncC), strings.ToLower(input.UserId)).
				First(&sessionCookie)

			if getOtpSDb.RowsAffected < 1 || sessionCookie.Name != "vlg.sid" {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var userData models.User
			getDb := config.DB.Table("users").Select("email", "auth_code").
				Where("LOWER(user_id) = ?", strings.ToLower(input.UserId)).
				First(&userData)

			if getDb.RowsAffected < 1 {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var hasEmail bool
			if userData.Email == "-" {
				hasEmail = false
			} else {
				hasEmail = true
			}

			var hasAuth bool
			if userData.AuthCode == "-" {
				hasAuth = false
			} else {
				hasAuth = true
			}

			var count int64
			config.DB.Table("backup_codes").
				Where("LOWER(user_id) = ?", strings.ToLower(input.UserId)).
				Count(&count)

			var hasBC bool
			if count < 1 {
				hasBC = false
			} else {
				hasBC = true
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{
				"has_email":         hasEmail,
				"has_authenticator": hasAuth,
				"has_backup_code":   hasBC,
			}, "")
		})
	}
}
