package http

import (
	"LetterToBackend/internal/middleware"
	"LetterToBackend/models"
	"LetterToBackend/pkg/utils"
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type Rephrase struct {
	Style string `json:"style" binding:"required"`
	Text  string `json:"text" binding:"required"`
	Lang  string `json:"lang" binding:"required"`
}

type ResultDetail struct {
	Prompt    string `json:"prompt"`
	SessionId string `json:"session_id"`
	Response  string `json:"response"`
}

type Result struct {
	Platform string       `json:"platform"`
	Status   bool         `json:"status"`
	Result   ResultDetail `json:"result"`
}

var aiClient = &http.Client{
	Timeout: 120 * time.Second,
}

func AI(r *gin.Engine) {
	ai := r.Group("ai")
	{
		ai.POST("/rephrase", func(ctx *gin.Context) {
			var input Rephrase
			var errJson models.ErrorDetail

			verify, user := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := ctx.ShouldBindJSON(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "style, text, lang", 1), nil, errJson.Code)
				return
			}

			getStyles := strings.Split(os.Getenv("REFRASE_STYLE"), ",")
			if !utils.ValidateEnum(ctx, "style", input.Style, getStyles) {
				return
			}

			style := strings.ReplaceAll(input.Style, "_", " ")
			cmd := os.Getenv("REFRASE_PROMPT")
			apiKey := os.Getenv("AI_API_KEY")
			apiEnd := os.Getenv("AI_END")

			replacer := strings.NewReplacer(
				"{STYLE}", style,
				"{TEXT}", input.Text,
				"{LANG}", input.Lang,
			)
			payload := map[string]string{
				"prompt":     replacer.Replace(cmd),
				"session_id": user.UserID,
			}

			apiURL, err := url.Parse(apiEnd)
			if err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			q := apiURL.Query()
			q.Set("apikey", apiKey)
			apiURL.RawQuery = q.Encode()

			body, err := json.Marshal(payload)
			if err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			resp, err := http.Post(apiURL.String(), "application/json", bytes.NewReader(body))
			if err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}
			defer resp.Body.Close()

			var result Result
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			var hasil *string
			if result.Result.Response == "rejected" {
				hasil = nil
			} else {
				hasil = &result.Result.Response
			}

			utils.SendLog("User Akses Gemini AI:\n\nNama: "+user.Name+"\nID: <code>"+user.UserID+"</code>\nText:\n<blockquote expandable>"+input.Text+"</blockquote>\nStyle: "+style+"\nLang: "+input.Lang+"\nAI Result: <blockquote expandable>"+result.Result.Response+"</blockquote>", user.Role)

			utils.JSON(ctx, 200, true, "Success!", gin.H{"result": hasil}, "")
		})
	}
}
