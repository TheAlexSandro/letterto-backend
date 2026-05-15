package http

import (
	"LetterToBackend/config"
	"LetterToBackend/internal/middleware"
	"LetterToBackend/models"
	"LetterToBackend/pkg/utils"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type UserResponse struct {
	Name        string `json:"name"`
	Username    string `json:"username"`
	NewPassword string `json:"new_password"`
	OldPassword string `json:"old_password"`
}

func User(r *gin.Engine) {
	User := r.Group("user")
	{
		User.POST("/edit", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var value UserResponse

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

			fmt.Println("MASUK")
			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			config.DB.Where("user_id = ?", user.UserID).Delete(&models.Session{})
			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})
	}
}
