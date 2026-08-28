package http

import (
	"LetterToBackend/internal/middleware"
	"LetterToBackend/models"
	"LetterToBackend/pkg/utils"
	"strings"

	"github.com/gin-gonic/gin"
)

type GiveRequest struct {
	Thumb    string `json:"thumb"`
	Style    string `json:"style"`
	Lang     string `json:"lang"`
	Feedback string `json:"feedback"`
}

func Feedback(r *gin.Engine) {
	feedback := r.Group("feedback")
	{
		feedback.POST("/give", func(ctx *gin.Context) {
			var input GiveRequest
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := ctx.ShouldBindJSON(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "thumb, style, lang, feedback", 1), nil, errJson.Code)
				return
			}

			var th string
			if input.Thumb == "up" {
				th = "👍"
			} else {
				th = "👎"
			}

			utils.SendLog("User memberi feedback:\n\nFitur: AI Gemini\nNama: "+user.Name+"\nID: <code>"+user.UserID+"</code>\nThumb: "+th+"\nStyle: "+input.Style+"\nLang: "+input.Lang+"\nFeedback: "+input.Feedback, "")

			utils.JSON(ctx, 200, true, "Success!", nil, "")
		})
	}
}
