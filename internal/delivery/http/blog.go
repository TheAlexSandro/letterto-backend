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
	"time"

	"github.com/gin-gonic/gin"
)

type BlogCreate struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type BlogEdit struct {
	BlogId  string `json:"blog_id"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

type BlogGet struct {
	BlogId string `json:"blog_id"`
}

type RespBlog struct {
	BlogId    string   `json:"blog_id"`
	CreatorId string   `json:"creator_id"`
	CreatedAt string   `json:"created_at"`
	Title     string   `json:"title"`
	Content   string   `json:"content"`
	Like      string   `json:"like"`
	Dislike   string   `json:"dislike"`
	Comments  []string `json:"comments"`
}

type BlogResponse struct {
	BlogId      string `json:"blog_id"`
	CreatorName string `json:"creator_name"`
	CreatedAt   string `json:"created_at"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	Viewer      int    `json:"viewer"`
}

type BlogEditConfig struct {
	BlogId          string `json:"blog_id"`
	ShowCreatorName string `json:"show_creator_name"`
	Privacy         string `json:"privacy"`
}

func limitString(s string, max int) string {
	runes := []rune(s)
	if len(runes) > max {
		return string(runes[:max])
	}
	return s
}

func Blog(r *gin.Engine) {
	blog := r.Group("blog")
	{
		blog.POST("/new", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input BlogCreate

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if !utils.HasFeature(user.AccountFeature, "blog_create") {
				utils.GetErrorJson("FEATURE_UNAVAILABLE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := ctx.ShouldBindJSON(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "title, content", 1), nil, errJson.Code)
				return
			}

			blogId := utils.GenerateID(10)
			newBlog := models.Blog{
				BlogId:    blogId,
				CreatorId: user.UserID,
				CreatedAt: time.Now(),
				Title:     input.Title,
				Content:   input.Content,
			}

			if err := config.DB.Table("blogs").Create(&newBlog).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"blog_id": blogId}, "")
		})

		blog.POST("/edit", func(ctx *gin.Context) {
			var errJson models.ErrorDetail
			var input BlogEdit

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if !utils.HasFeature(user.AccountFeature, "blog_manage") {
				utils.GetErrorJson("FEATURE_UNAVAILABLE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := ctx.ShouldBindJSON(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "blog_id, title, content", 1), nil, errJson.Code)
				return
			}

			var blogData models.Blog
			if err := config.DB.Table("blogs").Where("LOWER(blog_id) = ?", strings.ToLower(input.BlogId)).First(&blogData).Error; err != nil {
				utils.GetErrorJson("BLOG_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if blogData.CreatorId != user.UserID {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := config.DB.Table("blogs").
				Where("LOWER(blog_id) = ?", strings.ToLower(blogData.BlogId)).
				Updates(map[string]interface{}{
					"title":     input.Title,
					"content":   input.Content,
					"last_edit": time.Now(),
				}).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"blog_id": blogData.BlogId}, "")
		})

		blog.POST("/edit/config", func(ctx *gin.Context) {
			var input BlogEditConfig
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if !utils.HasFeature(user.AccountFeature, "blog_manage") {
				utils.GetErrorJson("FEATURE_UNAVAILABLE", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := ctx.ShouldBindJSON(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "blog_id, show_creator_name, config", 1), nil, errJson.Code)
				return
			}

			if !utils.ValidateEnum(ctx, "show_creator_name", input.ShowCreatorName, []string{"yes", "no"}) || !utils.ValidateEnum(ctx, "privacy", input.Privacy, []string{"public", "private"}) {
				return
			}

			var blogData models.Blog
			if err := config.DB.Table("blogs").Where("LOWER(blog_id) = ?", strings.ToLower(input.BlogId)).First(&blogData).Error; err != nil {
				utils.GetErrorJson("BLOG_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if blogData.CreatorId != user.UserID {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := config.DB.Table("blogs").
				Where("LOWER(blog_id) = ?", strings.ToLower(blogData.BlogId)).
				Updates(map[string]interface{}{
					"show_creator_name": input.ShowCreatorName,
					"privacy":           input.Privacy,
				}).Error; err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", gin.H{"blog_id": blogData.BlogId}, "")
		})

		blog.GET("/list", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			isLogin, user := middleware.IsLogin(ctx)
			const limit = 7
			offset, err := strconv.Atoi(ctx.DefaultQuery("offset", "0"))
			if err != nil || offset < 0 {
				offset = 0
			}

			var blogList []models.Blog

			result := config.DB.Table("blogs").Select("blog_id", "creator_id", "created_at", "title", "LEFT(content, 150) AS content", "last_edit", "viewer", "privacy", "show_creator_name").
				Order("created_at DESC").
				Limit(limit).
				Offset(offset).
				Find(&blogList)

			if result.Error != nil {
				utils.GetErrorJson("BAD_GATEWAY", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			creatorIds := make([]string, 0, len(blogList))
			seen := make(map[string]bool)
			for _, b := range blogList {
				if !seen[b.CreatorId] {
					seen[b.CreatorId] = true
					creatorIds = append(creatorIds, b.CreatorId)
				}
			}

			var users []models.User
			if len(creatorIds) > 0 {
				if err := config.DB.Table("users").
					Where("user_id IN ?", creatorIds).
					Find(&users).Error; err != nil {
					utils.GetErrorJson("BAD_GATEWAY", &errJson)
					utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
					return
				}
			}

			nameMap := make(map[string]string, len(users))
			for _, u := range users {
				nameMap[u.UserID] = u.Name
			}

			respList := make([]BlogResponse, 0, len(blogList))
			for _, b := range blogList {
				if b.Privacy == "private" && (!isLogin || !utils.HasFeature(user.AccountFeature, "blog_manage")) {
					continue
				}

				creatorName := nameMap[b.CreatorId]
				if creatorName == "" || b.ShowCreatorName == "no" {
					creatorName = "Administrator"
				}

				respList = append(respList, BlogResponse{
					BlogId:      b.BlogId,
					CreatorName: creatorName,
					CreatedAt:   b.CreatedAt.Format("02/01/06"),
					Title:       b.Title,
					Content:     b.Content,
					Viewer:      b.Viewer,
				})
			}

			hasMore := len(blogList) == limit

			utils.JSON(ctx, http.StatusOK, true, "success", gin.H{
				"data":     respList,
				"offset":   offset + len(blogList),
				"has_more": hasMore,
			}, "")
		})

		blog.GET("/getBlog", func(ctx *gin.Context) {
			var errJson models.ErrorDetail

			blogId := ctx.Query("blog_id")
			if blogId == "" {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "blog_id", 1), nil, errJson.Code)
				return
			}

			var blogData models.Blog
			if err := config.DB.Table("blogs").Where("LOWER(blog_id) = ?", strings.ToLower(blogId)).First(&blogData).Error; err != nil {
				utils.GetErrorJson("BLOG_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			creatorName := "Administrator"
			var creatorUser models.User
			if err := config.DB.Table("users").Where("user_id = ?", blogData.CreatorId).First(&creatorUser).Error; err == nil && blogData.ShowCreatorName == "yes" {
				creatorName = creatorUser.Name
			}

			isLogin, user := middleware.IsLogin(ctx)
			isOwner := isLogin && blogData.CreatorId == user.UserID

			if blogData.Privacy == "private" && (!isLogin || !utils.HasFeature(user.AccountFeature, "blog_manage")) {
				utils.GetErrorJson("BLOG_NOT_FOUND", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			resp := gin.H{
				"blog_id":      blogData.BlogId,
				"creator_id":   blogData.CreatorId,
				"creator_name": creatorName,
				"created_at":   blogData.CreatedAt.Format("02/01/06"),
				"title":        blogData.Title,
				"content":      blogData.Content,
				"viewer":       blogData.Viewer,
				"is_owner":     isOwner,
			}

			if isOwner {
				resp["privacy"] = blogData.Privacy
				resp["show_creator_name"] = blogData.ShowCreatorName
			}

			if blogData.LastEdit == "-" {
				resp["last_edit"] = nil
			} else {
				dateStr := blogData.LastEdit
				if idx := strings.Index(dateStr, " m="); idx != -1 {
					dateStr = dateStr[:idx]
				}
				layout := "2006-01-02 15:04:05.999999999 -0700 MST"
				date, err := time.Parse(layout, dateStr)
				if err != nil {
					panic(err)
				}
				dt := date.Format("02/01/06")

				resp["last_edit"] = &dt
			}

			if !isOwner {
				getCookie, _ := ctx.Cookie(blogData.BlogId + "-view__")
				if getCookie == "" {
					newView := blogData.Viewer + 1
					config.DB.Table("blogs").
						Where("LOWER(blog_id) = ?", strings.ToLower(blogData.BlogId)).
						Update("viewer", newView)
					resp["viewer"] = newView

					token := utils.GenerateID(20)

					http.SetCookie(ctx.Writer, &http.Cookie{
						Name:     blogData.BlogId + "-view__",
						Value:    token,
						Path:     "/",
						MaxAge:   86400,
						HttpOnly: true,
						Secure:   true,
						SameSite: utils.SetCookieSameSite(),
						Domain:   os.Getenv("DOMAIN"),
					})
				}
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", resp, "")
		})
	}
}
