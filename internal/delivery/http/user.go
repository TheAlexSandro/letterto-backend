package http

import (
	"LetterToBackend/config"
	"LetterToBackend/internal/middleware"
	"LetterToBackend/models"
	"LetterToBackend/pkg/utils"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type UserResponse struct {
	Name        string `json:"name"`
	Username    string `json:"username"`
	NewPassword string `json:"new_password"`
	OldPassword string `json:"old_password"`
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
	User := r.Group("user")
	{
		User.POST("/edit", func(ctx *gin.Context) {
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
				UserID:   user.UserID,
				Name:     value.Name,
				Username: value.Username,
				Password: value.NewPassword,
				Profile:  "-",
				Role:     user.Role,
			}

			if dbErr := config.DB.Table("users").Save(&editProfile).Error; dbErr != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		User.POST("/logout", func(ctx *gin.Context) {
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

			config.DB.Where("user_id = ?", user.UserID).Delete(&models.Session{})
			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		User.GET("/accountInfo", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"user_id": user.UserID, "name": user.Name, "username": user.Username, "role": user.Role}, "")
		})

		User.GET("/users", func(ctx *gin.Context) {
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

		User.GET("/searchUser", func(ctx *gin.Context) {
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

		User.POST("/changeRole", func(ctx *gin.Context) {
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

		User.POST("/changePass", func(ctx *gin.Context) {
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
