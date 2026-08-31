package models

import (
	"time"
)

type User struct {
	UserID         string `gorm:"primaryKey;type:varchar(10);not null" json:"id"`
	Name           string `gorm:"type:varchar(100);not null" json:"name"`
	Username       string `gorm:"uniqueIndex;type:text;not null" json:"username"`
	Password       string `gorm:"type:text;not null" json:"password"`
	Profile        string `gorm:"type:text;default-" json:"profile"`
	Role           string `gorm:"type:text;default:user" json:"role"`
	AccountFeature string `gorm:"type:text;default:new_letter,edit_letter,remove_letter,find_letter,access_letter,change_password,change_username,change_name" json:"account_feature"`
	LetterFeature  string `gorm:"type:text;default:privacy,view_once,password,font,custom_id,music_autoplay,show_sender,show_recipient,rephrase,upload_image,upload_video" json:"letter_feature"`
}

type Session struct {
	RefreshToken string    `gorm:"primaryKey;type:text;not null" json:"refresh_token"`
	UserID       string    `gorm:"type:varchar(10);not null" json:"id"`
	ExpiresAt    time.Time `gorm:"type:timestamptz;not null" json:"expires_at"`
	LoginAt      time.Time `gorm:"type:timestamptz" json:"login_at"`
}

type Letter struct {
	LetterID      string     `gorm:"primaryKey;type:varchar(20);not null" json:"id"`
	UserID        string     `gorm:"primaryKey;type:varchar(10);not null" json:"user_id"`
	RecipientName string     `gorm:"type:text;not null" json:"recipient_name"`
	Message       string     `gorm:"type:text;not null" json:"message"`
	Music         string     `gorm:"type:text;not null" json:"music"`
	MusicProfile  string     `gorm:"type:text;not null" json:"music_profile"`
	MusicTitle    string     `gorm:"type:text;not null" json:"music_title"`
	Artist        string     `gorm:"type:text;not null" json:"artist"`
	Image         string     `gorm:"type:text;default:-" json:"image"`
	Video         string     `gorm:"type:text;default:-" json:"video"`
	Privacy       string     `gorm:"type:varchar(10);not null;default:public" json:"privacy"`
	Password      string     `gorm:"type:text;default:-" json:"password"`
	Font          string     `gorm:"type:text;not null" json:"font"`
	ShowSender    string     `gorm:"type:varchar(3);not null;" json:"show_sender"`
	ShowRecipient string     `gorm:"type:varchar(3);not null" json:"show_recipient"`
	CreatedAt     string     `gorm:"type:text;not null" json:"created_at"`
	ViewOnce      string     `gorm:"type:text;not null" json:"view_once"`
	IsBurned      string     `gorm:"type:varchar(3);default:no" json:"is_burned"`
	Timeout       *int       `gorm:"type:integer" json:"timeout"`
	OpenedAt      *time.Time `gorm:"type:timestamptz" json:"opened_at"`
	Warn          string     `gorm:"type:text" json:"warn"`
	Viewer        int        `gorm:"type:integer;default:0" json:"viewer"`
	AudioAutoplay string     `gorm:"type:text;default:yes" json:"audio_autoplay"`
}

type LetterSession struct {
	SessionID string    `gorm:"primaryKey;type:text;not null" json:"id"`
	LetterID  string    `gorm:"type:varchar(20);not null" json:"letter_id"`
	ExpiresAt time.Time `gorm:"type:timestamptz;not null" json:"expires_at"`
	AccessAt  time.Time `gorm:"type:timestamptz" json:"access_at"`
}

type LoginIdSession struct {
	UserId    string    `gorm:"primaryKey;type:text;not null" json:"user_id"`
	LoginId   string    `gorm:"primaryKey;type:text;not null" json:"login_id"`
	ExpiresAt time.Time `gorm:"type:timestamptz" json:"expires_at"`
}

type ErrorDetail struct {
	Http    int    `json:"http"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Blog struct {
	BlogId    string    `gorm:"primaryKey;type:varchar(10);not null" json:"blog_id"`
	CreatorId string    `gorm:"type:text;not null" json:"creator_id"`
	CreatedAt time.Time `gorm:"type:timestamptz;not null" json:"created_at"`
	Title     string    `gorm:"type:text;not null" json:"title"`
	Content   string    `gorm:"type:text;not null" json:"content"`
	LastEdit  string    `gorm:"type:text;default:-" json:"last_edit"`
	Viewer    int       `gorm:"type:integer;default:0" json:"viewer"`
}

var ErrorMapping map[string]ErrorDetail

type LetterCookieData struct {
	SessionID string `json:"session_id"`
	LetterID  string `json:"letter_id"`
}
