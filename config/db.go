package config

import (
	"LetterToBackend/models"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDatabase() {
	DB_STRING := os.Getenv("DB_STRING")
	database, err := gorm.Open(postgres.Open(DB_STRING), &gorm.Config{})

	tabel := database.AutoMigrate(&models.User{}, &models.Session{}, &models.Letter{}, &models.LetterSession{})
	if tabel != nil {
		log.Fatal("Failed to migrate table:", tabel)
	}
	if err != nil {
		log.Fatal("Failed to connect to db: ", err)
	}

	DB = database
	log.Println("Connected to db!")
}
