package config

import (
	"LetterToBackend/models"
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDatabase() {
	DB_STRING := os.Getenv("DB_STRING")

	database, err := gorm.Open(postgres.Open(DB_STRING), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to db: ", err)
	}

	sqlDB, err := database.DB()
	if err != nil {
		log.Fatal("Failed to get sql.DB: ", err)
	}

	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	database.Exec("SET TIME ZONE 'Asia/Jakarta'")

	tabel := database.AutoMigrate(&models.User{}, &models.Session{}, &models.Letter{}, &models.LetterSession{})
	if tabel != nil {
		log.Fatal("Failed to migrate table:", tabel)
	}

	var tz string
	database.Raw("SHOW timezone").Scan(&tz)
	log.Println("DB timezone:", tz)

	DB = database
	log.Println("Connected to db!")
}
