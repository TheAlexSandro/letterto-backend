package http

import (
	"LetterToBackend/internal/middleware"
	"LetterToBackend/models"
	"LetterToBackend/pkg/utils"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type SearchMusic struct {
	Q string `form:"q" binding:"required"`
}

type PreviewMusic struct {
	Id string `form:"id" binding:"required"`
}

type deezerErrorField struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type deezerSearchResponse struct {
	Data  json.RawMessage   `json:"data"`
	Error *deezerErrorField `json:"error"`
}

var deezerClient = &http.Client{
	Timeout: 8 * time.Second,
}

func Music(r *gin.Engine) {
	music := r.Group("/music")
	{
		music.GET("/search", func(ctx *gin.Context) {
			var input SearchMusic
			var errJson models.ErrorDetail

			verify, _ := middleware.IsLogin(ctx)
			if !verify {
				utils.GetErrorJson("UNAUTHORIZED", &errJson)
				utils.JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
				return
			}

			if err := ctx.ShouldBind(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "q", 1), nil, errJson.Code)
				return
			}

			api := os.Getenv("DEEZER_API")
			target := api + "/search?q=" + url.QueryEscape(input.Q) + "&limit=10"

			body, err := fetchDeezer(ctx, target)
			if err != nil {
				utils.GetErrorJson("BAD_GATEWAY", &errJson)
				utils.JSON(ctx, http.StatusBadGateway, false, err.Error(), nil, errJson.Code)
				return
			}

			var dr deezerSearchResponse
			if err := json.Unmarshal(body, &dr); err != nil {
				utils.GetErrorJson("BAD_GATEWAY", &errJson)
				utils.JSON(ctx, http.StatusBadGateway, false, "invalid deezer response", nil, errJson.Code)
				return
			}

			if dr.Error != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, http.StatusBadGateway, false, dr.Error.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", dr.Data, "")
		})

		music.GET("/preview", func(ctx *gin.Context) {
			var input PreviewMusic
			var errJson models.ErrorDetail

			if err := ctx.ShouldBind(&input); err != nil {
				utils.GetErrorJson("PARAMETER_EMPTY", &errJson)
				utils.JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{param}", "id", 1), nil, errJson.Code)
				return
			}

			api := os.Getenv("DEEZER_API")
			target := api + "/track/" + url.PathEscape(input.Id)

			body, err := fetchDeezer(ctx, target)
			if err != nil {
				utils.GetErrorJson("BAD_GATEWAY", &errJson)
				utils.JSON(ctx, http.StatusBadGateway, false, err.Error(), nil, errJson.Code)
				return
			}

			var probe struct {
				Error *deezerErrorField `json:"error"`
			}
			if err := json.Unmarshal(body, &probe); err != nil {
				utils.GetErrorJson("BAD_GATEWAY", &errJson)
				utils.JSON(ctx, http.StatusBadGateway, false, "invalid deezer response", nil, errJson.Code)
				return
			}

			if probe.Error != nil {
				utils.GetErrorJson("BAD_REQUEST", &errJson)
				utils.JSON(ctx, http.StatusBadGateway, false, probe.Error.Message, nil, errJson.Code)
				return
			}

			utils.JSON(ctx, http.StatusOK, true, "Success!", json.RawMessage(body), "")
		})
	}
}

func fetchDeezer(ctx *gin.Context, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx.Request.Context(), http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}

	res, err := deezerClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return io.ReadAll(res.Body)
}
