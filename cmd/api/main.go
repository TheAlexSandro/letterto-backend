package main

import (
	"LetterToBackend/config"
	router "LetterToBackend/internal/delivery/http"
	"LetterToBackend/pkg/utils"
	"net/http"

	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	config.ConnectDatabase()
	utils.InitR2()
	utils.InitCookie()
	r := gin.Default()
	r.GET("/", func(ctx *gin.Context) {
		utils.JSON(ctx, http.StatusOK, true, "OK!", nil, "")
	})
	router.Auth(r)
	router.Letter(r)
	router.User(r)
	r.Run(":8000")
	log.Print("started...")
}
