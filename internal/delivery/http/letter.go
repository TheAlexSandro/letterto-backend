package http

import (
	"LetterToBackend/config"
	"LetterToBackend/internal/middleware"
	"LetterToBackend/models"
	"LetterToBackend/pkg/utils"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type LetterInfo struct {
	ID   string `form:"id" binding:"required"`
	Edit string `form:"edit"`
}

type VerifyPassword struct {
	ID       string `json:"id" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LetterSeach struct {
	Offset        string `form:"offset" binding:"required"`
	RecipientName string `form:"recipient_name" binding:"required"`
}

type MyLetter struct {
	Offset string `form:"offset" binding:"required"`
}

type LetterResponse struct {
	LetterID      string `json:"id"`
	UserID        string `json:"user_id"`
	Sender        string `json:"sender"`
	Message       string `json:"message"`
	CreatedAt     string `json:"created_at"`
	Font          string `json:"font"`
	RecipientName string `json:"recipient_name"`
	MusicProfile  string `json:"music_profile"`
	MusicTitle    string `json:"music_title"`
	Artist        string `json:"artist"`
}

type LetterInfoResp struct {
	ID            string  `json:"id"`
	UserID        string  `json:"user_id"`
	Message       string  `json:"message"`
	CreatedAt     string  `json:"created_at"`
	Font          string  `json:"font"`
	MusicProfile  string  `json:"music_profile"`
	MusicTitle    string  `json:"music_title"`
	Artist        string  `json:"artist"`
	Music         string  `json:"music"`
	Image         *string `json:"image"`
	Video         *string `json:"video"`
	Sender        *string `json:"sender"`
	RecipientName *string `json:"recipient_name"`
}

type LetterResponsePre struct {
	LetterID      *string `json:"letter_id"`
	Message       *string `json:"message"`
	MusicProfile  string  `json:"music_profile"`
	MusicTitle    string  `json:"music_title"`
	Artist        string  `json:"artist"`
	CreatedAt     string  `json:"created_at"`
	RecipientName *string `json:"recipient_name"`
	Sender        *string `json:"sender"`
	Font          *string `json:"font"`
	IsLocked      bool    `json:"is_locked"`
}

type LetterTimeoutResp struct {
	LetterID string `json:"letter_id"`
	TimeLeft int    `json:"time_left"`
}

func Letter(r *gin.Engine) {
	letter := r.Group("letter")
	{
		letter.GET("/getInfo", func(ctx *gin.Context) {
			var letter LetterInfo
			var errJson models.ErrorDetail
			var letterInfo models.Letter

			if err := ctx.ShouldBind(&letter); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "id", 1), nil, errJson.Code)
				return
			}

			if err := config.DB.Table("letters").Where("letter_id = ?", letter.ID).First(&letterInfo).Error; err != nil {
				utils.GetErrorJson("LETTER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			letterData := LetterInfoResp{
				ID:           letterInfo.LetterID,
				UserID:       letterInfo.UserID,
				Message:      letterInfo.Message,
				CreatedAt:    letterInfo.CreatedAt,
				Font:         letterInfo.Font,
				MusicProfile: letterInfo.MusicProfile,
				MusicTitle:   letterInfo.MusicTitle,
				Artist:       letterInfo.Artist,
				Music:        letterInfo.Music,
			}

			if letterInfo.Video != "-" {
				videoUrl, _ := utils.GenerateSignedURL(letterInfo.Video)
				letterData.Video = &videoUrl
			} else {
				letterData.Video = nil
			}

			if letterInfo.Image != "-" {
				imageUrl, _ := utils.GenerateSignedURL(letterInfo.Image)
				letterData.Image = &imageUrl
			} else {
				letterData.Image = nil
			}

			if letterInfo.ShowSender == "yes" {
				var user models.User
				if config.DB.Table("users").Select("name").Where("user_id = ?", letterInfo.UserID).First(&user).RowsAffected > 0 {
					letterData.Sender = &user.Name
				} else {
					letterData.Sender = nil
				}
			} else {
				letterData.Sender = nil
			}

			if letterInfo.ShowRecipient == "yes" {
				letterData.RecipientName = &letterInfo.RecipientName
			} else {
				letterData.RecipientName = nil
			}

			isLogin, userInfo := middleware.IsLogin(ctx)
			isOwner := isLogin && letterInfo.UserID == userInfo.UserID

			if isOwner && letter.Edit == "yes" {
				editData := letterInfo

				if letterInfo.Image != "-" {
					imageUrl, _ := utils.GenerateSignedURL(letterInfo.Image)
					editData.Image = imageUrl
				}

				if letterInfo.Video != "-" {
					videoUrl, _ := utils.GenerateSignedURL(letterInfo.Video)
					editData.Video = videoUrl
				}

				utils.JSON(ctx, http.StatusOK, true, "Success!", editData, "")
				return
			}

			if letter.Edit == "yes" && !isOwner {
				utils.GetErrorJson("LETTER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if !isOwner && letterInfo.IsBurned == "yes" {
				utils.GetErrorJson("BURNED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if letterInfo.Password != "-" && !middleware.VerifyLetter(ctx, letter.ID) {
				utils.GetErrorJson("LETTER_LOCKED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", letterData, "")
		})

		letter.POST("/verifyPassword", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input VerifyPassword
			var letterInfo models.Letter

			if err := ctx.ShouldBindJSON(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "id, password", 1), nil, errJson.Code)
				return
			}

			getDb := config.DB.Table("letters").Select("password").Where("letter_id = ?", input.ID).First(&letterInfo)
			if getDb.RowsAffected < 0 {
				utils.GetErrorJson("LETTER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if input.Password != letterInfo.Password {
				utils.GetErrorJson("INVALID_PASSWORD", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			refreshToken := utils.GenerateID(50)

			newSession := models.LetterSession{
				SessionID: refreshToken,
				LetterID:  input.ID,
				ExpiresAt: utils.NowTz().Add(utils.GetExpiry()),
				AccessAt:  utils.NowTz(),
			}

			if err := config.DB.Table("letter_sessions").Create(&newSession).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			cookieData := models.LetterCookieData{
				SessionID: refreshToken,
				LetterID:  input.ID,
			}
			jsonBytes, _ := json.Marshal(cookieData)

			signedValue, cookieErr := utils.EncodeCookie(os.Getenv("KEY_SES_LETTER"), string(jsonBytes))
			if cookieErr != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			timeout, _ := strconv.Atoi(os.Getenv("COOKIE_TIMEOUT"))
			http.SetCookie(ctx.Writer, &http.Cookie{
				Name:     os.Getenv("KEY_SES_LETTER"),
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

		letter.POST("/new", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			letterId := ctx.PostForm("letter_id")
			recipientName := ctx.PostForm("recipient_name")
			message := ctx.PostForm("message")
			music := ctx.PostForm("music")
			musicProfile := ctx.PostForm("music_profile")
			musicTitle := ctx.PostForm("music_title")
			privacy := ctx.PostForm("privacy")
			password := ctx.PostForm("password")
			font := ctx.PostForm("font")
			showSender := ctx.PostForm("show_sender")
			showRecipient := ctx.PostForm("show_recipient")
			artist := ctx.PostForm("artist")
			viewOnce := ctx.PostForm("view_once")
			timeout := ctx.PostForm("timeout")

			if letterId == "" || recipientName == "" || message == "" || music == "" || musicProfile == "" || musicTitle == "" || privacy == "" || font == "" || showSender == "" || showRecipient == "" || artist == "" {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "letter_id, recipient_name, message, music, music_profile, music_title, privacy, font, show_sender, show_recipient, arist", 1), nil, errJson.Code)
				return
			}

			var t string
			getDb := config.DB.Table("letters").Select("letter_id").Where("letter_id = ?", letterId).Limit(1).Scan(&t)
			if getDb.RowsAffected > 0 {
				utils.GetErrorJson("ID_OCCUPIED", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{id}", letterId, 1), nil, errJson.Code)
				return
			}

			if !utils.ValidateEnum(ctx, "privacy", privacy, []string{"public", "private"}) ||
				!utils.ValidateEnum(ctx, "show_sender", showSender, []string{"yes", "no"}) ||
				!utils.ValidateEnum(ctx, "show_recipient", showRecipient, []string{"yes", "no"}) {
				return
			}

			if !utils.ValidateLength(ctx, letterId, "ID") || (password != "" && !utils.ValidateLength(ctx, password, "Password")) {
				return
			}

			if !utils.RegexFormat(letterId, ctx, "ID") {
				return
			}

			form, _ := ctx.MultipartForm()

			var imageUrl string
			var videoUrl string

			allowed := map[string]string{
				"image": "image",
				"video": "video",
			}
			for fieldName := range form.File {
				if _, ok := allowed[fieldName]; !ok {
					utils.GetErrorJson("INVALID_FILETYPE", &errJson)
					utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{media}", "image, video", 1), nil, errJson.Code)
					return
				}
			}

			for fieldName, files := range form.File {
				for _, file := range files {
					if len(files) == 0 {
						continue
					}

					if len(files) > 1 {
						utils.GetErrorJson("TOO_MANY_FILES", &errJson)
						utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
						return
					}

					switch fieldName {
					case "image":
						size, _ := strconv.Atoi(os.Getenv("IMAGE_MAX_SIZE"))
						if file.Size > int64(size) {
							utils.InvFileSizeRes(ctx, "image", int64(size))
							return
						}
					case "video":
						size, _ := strconv.Atoi(os.Getenv("VIDEO_MAX_SIZE"))
						if file.Size > int64(size) {
							utils.InvFileSizeRes(ctx, "video", int64(size))
							return
						}
					}
					fileType, errType := utils.GetFileType(file)
					if errType != nil || fileType != allowed[fieldName] {
						utils.GetErrorJson("INVALID_FILETYPE", &errJson)
						utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{media}", "image, video", 1), nil, errJson.Code)
						return
					}
					url, errUpload := utils.UploadToR2(file)
					if errUpload != nil {
						continue
					}

					switch fieldName {
					case "image":
						imageUrl = url
					case "video":
						videoUrl = url
					}
				}
			}

			if password == "" {
				password = "-"
			} else {
				if !utils.RegexFormat(password, ctx, "Password") {
					return
				}
			}

			var tms int
			if timeout != "" {
				tm, errT := utils.ParseMMSS(timeout)
				if !errT {
					utils.GetErrorJson("INVALID_TIMEOUT_FORMAT", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, "")
				}
				tms = tm
			}

			now := time.Now()
			newLetter := models.Letter{
				LetterID:      letterId,
				UserID:        user.UserID,
				RecipientName: strings.TrimSpace(recipientName),
				Message:       message,
				Music:         music,
				MusicProfile:  musicProfile,
				MusicTitle:    musicTitle,
				Privacy:       privacy,
				Password:      password,
				Font:          font,
				ShowSender:    showSender,
				ShowRecipient: showRecipient,
				CreatedAt:     now.Format("02/01/06"),
				Artist:        artist,
				ViewOnce:      viewOnce,
				Timeout:       &tms,
			}

			if imageUrl != "" {
				newLetter.Image = imageUrl
			} else {
				newLetter.Image = "-"
			}

			if videoUrl != "" {
				newLetter.Video = videoUrl
			} else {
				newLetter.Video = "-"
			}

			if err := config.DB.Table("letters").Create(&newLetter).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"letter_id": letterId}, "")
		})

		letter.GET("/total", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var c int64
			config.DB.Table("letters").
				Select("letter_id").
				Where("user_id = ?", user.UserID).Count(&c)

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"total": c}, "")
		})

		letter.GET("/myLetters", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var letterList []LetterResponse
			var input MyLetter

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := ctx.ShouldBind(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "offset", 1), nil, "")
				return
			}

			offsetStr := input.Offset
			offset, err := strconv.Atoi(offsetStr)
			if err != nil || offset < 1 || offset > 5 {
				offset = 1
			}

			limit := 5
			skip := (offset - 1) * limit

			getDb := config.DB.Table("letters").
				Select("letter_id", "user_id", "message", "created_at", "font", "recipient_name", "music_profile", "music_title", "artist").
				Where("user_id = ?", user.UserID).
				Offset(skip).
				Limit(limit).
				Find(&letterList)

			if getDb.RowsAffected < 1 {
				utils.GetErrorJson("LETTER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			for i := range letterList {
				letterList[i].Sender = user.Name
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", letterList, "")
		})

		letter.POST("/edit", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			letterId := ctx.PostForm("letter_id")
			recipientName := ctx.PostForm("recipient_name")
			message := ctx.PostForm("message")
			music := ctx.PostForm("music")
			musicProfile := ctx.PostForm("music_profile")
			musicTitle := ctx.PostForm("music_title")
			privacy := ctx.PostForm("privacy")
			password := ctx.PostForm("password")
			font := ctx.PostForm("font")
			showSender := ctx.PostForm("show_sender")
			showRecipient := ctx.PostForm("show_recipient")
			artist := ctx.PostForm("artist")
			new_letterId := ctx.PostForm("new_letterid")
			view_once := ctx.PostForm("view_once")
			is_burned := ctx.PostForm("is_burned")
			timeout := ctx.PostForm("timeout")

			delImg := ctx.PostForm("image")
			delVid := ctx.PostForm("video")

			var existing models.Letter
			if err := config.DB.Table("letters").Where("letter_id = ? AND user_id = ?", letterId, user.UserID).First(&existing).Error; err != nil {
				utils.GetErrorJson("LETTER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if letterId == "" || recipientName == "" || message == "" || music == "" || artist == "" {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				msg := strings.Replace(errJson.Message, "{param}", "letter_id, recipient_name, message, music, artist", 1)
				utils.JSON(ctx, errJson.Http, false, msg, nil, errJson.Code)
				return
			}

			if letterId != new_letterId {
				var checkId string
				config.DB.Table("letters").Select("letter_id").Where("letter_id = ?", new_letterId).Limit(1).Scan(&checkId)
				if checkId != "" {
					utils.GetErrorJson("ID_OCCUPIED", &errJson)
					msg := strings.Replace(errJson.Message, "{id}", new_letterId, 1)
					utils.JSON(ctx, errJson.Http, false, msg, nil, errJson.Code)
					return
				}

				if !utils.ValidateLength(ctx, new_letterId, "ID") {
					return
				}
			}

			if new_letterId == "" {
				new_letterId = existing.LetterID
			}

			if is_burned == "" {
				is_burned = existing.IsBurned
			}

			if !utils.ValidateEnum(ctx, "privacy", privacy, []string{"public", "private"}) ||
				!utils.ValidateEnum(ctx, "show_sender", showSender, []string{"yes", "no"}) ||
				!utils.ValidateEnum(ctx, "show_recipient", showRecipient, []string{"yes", "no"}) {
				return
			}

			if !utils.RegexFormat(new_letterId, ctx, "ID") {
				return
			}

			imageUrl := existing.Image
			videoUrl := existing.Video

			if delImg == "-" && imageUrl != "" {
				utils.DeleteFromR2(imageUrl)
				imageUrl = "-"
			}
			if delVid == "-" && videoUrl != "" {
				utils.DeleteFromR2(videoUrl)
				videoUrl = "-"
			}

			form, _ := ctx.MultipartForm()
			if form != nil && form.File != nil {
				allowed := map[string]string{"image": "image", "video": "video"}

				for fieldName, files := range form.File {
					if len(files) == 0 {
						continue
					}
					file := files[0]

					if len(files) > 1 {
						utils.GetErrorJson("TOO_MANY_FILES", &errJson)
						utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
						return
					}

					fileType, errType := utils.GetFileType(file)
					if errType != nil || fileType != allowed[fieldName] {
						utils.GetErrorJson("INVALID_FILETYPE", &errJson)
						msg := strings.Replace(errJson.Message, "{media}", "image, video", 1)
						utils.JSON(ctx, errJson.Http, false, msg, nil, errJson.Code)
						return
					}

					maxSizeKey := "IMAGE_MAX_SIZE"
					if fieldName == "video" {
						maxSizeKey = "VIDEO_MAX_SIZE"
					}
					size, _ := strconv.Atoi(os.Getenv(maxSizeKey))

					if file.Size > int64(size) {
						utils.GetErrorJson("FILE_TOO_LARGE", &errJson)
						msg := strings.Replace(errJson.Message, "{param}", fieldName, 1)
						msg = strings.Replace(msg, "{size}", strconv.Itoa(size), 1)
						utils.JSON(ctx, errJson.Http, false, msg, nil, errJson.Code)
						return
					}

					if fieldName == "image" && imageUrl != "" {
						utils.DeleteFromR2(imageUrl)
					}
					if fieldName == "video" && videoUrl != "" {
						utils.DeleteFromR2(videoUrl)
					}

					newUrl, errUpload := utils.UploadToR2(file)
					if errUpload == nil {
						switch fieldName {
						case "image":
							imageUrl = newUrl
						case "video":
							videoUrl = newUrl
						}
					}
				}
			}

			var tms int
			if timeout != "" {
				tm, errT := utils.ParseMMSS(timeout)
				if !errT {
					utils.GetErrorJson("INVALID_TIMEOUT_FORMAT", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, "")
				}
				tms = tm
			} else if existing.Timeout != nil {
				tms = *existing.Timeout
			}

			updateData := map[string]interface{}{
				"letter_id":      new_letterId,
				"recipient_name": strings.TrimSpace(recipientName),
				"message":        message,
				"music":          music,
				"music_profile":  musicProfile,
				"music_title":    musicTitle,
				"privacy":        privacy,
				"font":           font,
				"show_sender":    showSender,
				"show_recipient": showRecipient,
				"artist":         artist,
				"image":          imageUrl,
				"video":          videoUrl,
				"view_once":      view_once,
				"is_burned":      is_burned,
				"timeout":        tms,
			}

			if password != "" && password != "-" {
				if utils.ValidateLength(ctx, password, "Password") {
					if !utils.RegexFormat(password, ctx, "Password") {
						return
					}
					updateData["password"] = password
				} else {
					return
				}
			} else {
				updateData["password"] = "-"
			}

			if err := config.DB.Table("letters").Where("letter_id = ? AND user_id = ?", letterId, user.UserID).Updates(updateData).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"letter_id": letterId}, "")
		})

		letter.POST("/remove", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input LetterInfo
			var letter models.Letter

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := ctx.ShouldBind(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				msg := strings.Replace(errJson.Message, "{param}", "id", 1)
				utils.JSON(ctx, errJson.Http, false, msg, nil, errJson.Code)
				return
			}

			getDB := config.DB.Table("letters").Where("letter_id = ? AND user_id = ?", input.ID, user.UserID).First(&letter)
			if getDB.RowsAffected < 1 {
				utils.GetErrorJson("LETTER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			imageUrl := letter.Image
			videoUrl := letter.Video

			if imageUrl != "-" {
				utils.DeleteFromR2(imageUrl)
			}

			if videoUrl != "-" {
				utils.DeleteFromR2(videoUrl)
			}

			config.DB.Table("letters").Where("letter_id = ?", input.ID).Delete(&models.Letter{})
			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		letter.GET("/search", func(ctx *gin.Context) {
			var input LetterSeach
			var errJson models.ErrorDetail
			var letters []models.Letter

			if err := ctx.ShouldBind(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				msg := strings.Replace(errJson.Message, "{param}", "recipient_name", 1)
				utils.JSON(ctx, errJson.Http, false, msg, nil, errJson.Code)
				return
			}

			offsetStr := input.Offset
			offset, err := strconv.Atoi(offsetStr)
			if err != nil || offset < 1 {
				offset = 1
			}
			skip := (offset - 1) * 7
			reciName := "%" + strings.TrimSpace(input.RecipientName) + "%"

			var total int64
			config.DB.Table("letters").
				Where("recipient_name ILIKE ?", reciName).
				Count(&total)

			config.DB.Table("letters").
				Select("letter_id", "music_profile", "music_title", "created_at", "recipient_name", "show_sender", "show_recipient", "privacy", "user_id", "message", "font", "password", "artist", "is_burned").
				Where("recipient_name ILIKE ? AND privacy = ? AND is_burned = ? AND show_recipient = ?", reciName, "public", "no", "yes").
				Offset(skip).
				Limit(7).
				Find(&letters)

			var result []LetterResponsePre

			for _, l := range letters {
				item := LetterResponsePre{
					LetterID:      &l.LetterID,
					MusicProfile:  l.MusicProfile,
					MusicTitle:    l.MusicTitle,
					CreatedAt:     l.CreatedAt,
					Artist:        l.Artist,
					RecipientName: &l.RecipientName,
				}

				if l.Password != "-" && l.Password != "" {
					item.IsLocked = true
					item.Message = nil
					item.Font = nil
				} else {
					item.Message = &l.Message
					item.IsLocked = false
					item.Font = &l.Font
				}

				if l.ShowSender == "yes" {
					var user models.User
					config.DB.Table("users").Select("name").Where("user_id = ?", l.UserID).First(&user)
					item.Sender = &user.Name
				} else {
					item.Sender = nil
				}

				result = append(result, item)
			}

			rand.Shuffle(len(result), func(i, j int) {
				result[i], result[j] = result[j], result[i]
			})

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{
				"total":   total,
				"offset":  offset,
				"letters": result,
			}, "")
		})

		letter.POST("/burn", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var letter models.Letter
			var input LetterInfo

			if err := ctx.ShouldBind(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "id", 1), nil, errJson.Code)
				return
			}

			getDb := config.DB.Table("letters").
				Select("user_id", "view_once", "timeout", "opened_at").
				Where("letter_id = ?", input.ID).
				First(&letter)

			if getDb.RowsAffected < 1 {
				utils.GetErrorJson("LETTER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, "")
				return
			}

			if letter.ViewOnce == "yes" {
				verify, user := middleware.IsLogin(ctx)
				shouldBurn := !verify || letter.UserID != user.UserID

				if shouldBurn {
					if letter.Timeout != nil {
						now := utils.NowTz()
						if letter.OpenedAt == nil {
							result := config.DB.Table("letters").
								Where("letter_id = ? AND opened_at IS NULL", input.ID).
								Update("opened_at", now)

							if result.RowsAffected > 0 {
								letter.OpenedAt = &now
							} else {
								config.DB.Table("letters").
									Select("opened_at").
									Where("letter_id = ?", input.ID).
									First(&letter)
							}
						}

						expiredAt := letter.OpenedAt.Add(time.Duration(*letter.Timeout) * time.Second)
						if now.After(expiredAt) {
							config.DB.Table("letters").
								Where("letter_id = ?", input.ID).
								Update("is_burned", "yes")
						}

					} else {
						if err := config.DB.Table("letters").
							Where("letter_id = ?", input.ID).
							Update("is_burned", "yes").Error; err != nil {

							utils.GetErrorJson("BAD_REQUEST", &errJson)
							utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
							return
						}
					}
				}
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", nil, "")
		})

		letter.GET("/timeLeft", func(ctx *gin.Context) {
			var input LetterInfo
			var errJson models.ErrorDetail
			var letter models.Letter

			if err := ctx.ShouldBind(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "id", 1), nil, errJson.Code)
				return
			}

			getDb := config.DB.Table("letters").
				Select("opened_at", "timeout").
				Where("letter_id = ?", input.ID).
				First(&letter)

			if getDb.RowsAffected < 1 {
				utils.GetErrorJson("LETTER_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, "")
				return
			}

			expiredAt := letter.OpenedAt.Add(time.Duration(*letter.Timeout) * time.Second)
			remaining := time.Until(expiredAt)

			resp := LetterTimeoutResp{
				LetterID: input.ID,
				TimeLeft: int(remaining.Seconds()),
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", resp, "")
		})

		letter.GET("/letterTotal", func(ctx *gin.Context) {
			var count int64

			config.DB.Table("letters").
				Select("letter_id").Count(&count)

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"total": count}, "")
		})

		letter.GET("/letterList", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var letters []models.Letter

			getDb := config.DB.Table("letters").
				Select("letter_id", "message", "created_at", "font", "recipient_name", "music_profile", "music_title", "password").
				Find(&letters)

			if getDb.RowsAffected < 1 {
				utils.GetErrorJson("LETTER_LIST_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, "")
				return
			}

			var result []LetterResponsePre

			for _, l := range letters {
				if l.Privacy == "private" || l.Password != "-" {
					continue
				}

				item := LetterResponsePre{
					LetterID:     &l.LetterID,
					MusicProfile: l.MusicProfile,
					MusicTitle:   l.MusicTitle,
					CreatedAt:    l.CreatedAt,
					Message:      &l.Message,
					IsLocked:     false,
				}

				if l.ShowRecipient == "yes" {
					item.RecipientName = &l.RecipientName
				} else {
					item.RecipientName = nil
				}

				if l.ShowSender == "yes" {
					var user models.User
					config.DB.Table("users").Select("name").Where("user_id = ?", l.UserID).First(&user)
					item.Sender = &user.Name
				} else {
					item.Sender = nil
				}

				result = append(result, item)
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", result, "")
		})

		letter.GET("/random", func(ctx *gin.Context) {
			var letters []models.Letter

			config.DB.Table("letters").
				Select("letter_id", "music_profile", "music_title", "created_at", "recipient_name", "show_recipient", "privacy", "user_id", "message", "font", "password", "artist", "is_burned").
				Where("privacy = ? AND password = ? AND is_burned = ? AND LENGTH(message) > ?", "public", "-", "no", 70).
				Order("RANDOM()").
				Limit(10).
				Find(&letters)

			var result []LetterResponsePre

			for _, l := range letters {
				item := LetterResponsePre{
					LetterID:     nil,
					MusicProfile: l.MusicProfile,
					MusicTitle:   l.MusicTitle,
					CreatedAt:    l.CreatedAt,
					Artist:       l.Artist,
					Message:      &l.Message,
					IsLocked:     false,
					Font:         &l.Font,
					Sender:       nil,
				}

				if l.ShowRecipient == "no" {
					item.RecipientName = nil
				} else {
					item.RecipientName = &l.RecipientName
				}

				result = append(result, item)
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{
				"letters": result,
			}, "")
		})
	}
}
