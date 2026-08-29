package utils

import (
	"LetterToBackend/models"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
)

var R2Client *s3.Client

type signedURLCache struct {
	url       string
	expiresAt time.Time
}

type SignedPayload struct {
	Key string `json:"key"`
	Exp int64  `json:"exp"`
}

var (
	urlCache  = make(map[string]signedURLCache)
	urlCache_ sync.RWMutex
)

func InitR2() {
	r2Endpoint := os.Getenv("R2_END")
	r2AccessKey := os.Getenv("R2_ACCESS_KEY")
	r2SecretKey := os.Getenv("R2_SECRET")

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				r2AccessKey,
				r2SecretKey,
				"",
			),
		),
		config.WithRegion("auto"),
	)
	if err != nil {
		panic("Failed to load R2 config: " + err.Error())
	}

	R2Client = s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(r2Endpoint)
	})

	go cleanupURLCache()

	fmt.Println("Connected to R2 Storage.")
}

func UploadToR2(file *multipart.FileHeader) (string, error) {
	f, err := file.Open()
	if err != nil {
		return "", err
	}
	defer f.Close()

	fileName := GenerateID(30)

	_, err = R2Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:       aws.String(os.Getenv("R2_BUCKET")),
		Key:          aws.String(fileName),
		Body:         f,
		ContentType:  aws.String(file.Header.Get("Content-Type")),
		CacheControl: aws.String("no-store, no-cache"),
	})
	if err != nil {
		return "", err
	}

	return fileName, nil
}

func GeneratePresignedUploadURL(key string, contentType string) (string, int, error) {
	expMin, _ := strconv.Atoi(os.Getenv("PRESIGN_UPLOAD_EXP"))
	if expMin <= 0 {
		expMin = 10
	}
	expiry := time.Duration(expMin) * time.Minute

	presignClient := s3.NewPresignClient(R2Client)

	req, err := presignClient.PresignPutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:       aws.String(os.Getenv("R2_BUCKET")),
		Key:          aws.String(key),
		ContentType:  aws.String(contentType),
		CacheControl: aws.String("no-store, no-cache"),
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", 0, err
	}

	return req.URL, int(expiry.Seconds()), nil
}

func HeadR2Object(key string) (*s3.HeadObjectOutput, error) {
	return R2Client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(os.Getenv("R2_BUCKET")),
		Key:    aws.String(key),
	})
}

func DeleteFromR2(fileUrl string) error {
	if fileUrl == "" {
		return nil
	}

	_, err := R2Client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(os.Getenv("R2_BUCKET")),
		Key:    aws.String(fileUrl),
	})

	if err == nil {
		urlCache_.Lock()
		delete(urlCache, fileUrl)
		urlCache_.Unlock()
	}

	return err
}

func GenerateSignedURL(key string) (string, error) {
	getSigExp, _ := strconv.Atoi(os.Getenv("SIGNED_URL_EXP"))
	signedURLExpiry := time.Duration(getSigExp) * time.Minute
	getCaBuff, _ := strconv.Atoi(os.Getenv("CACHE_BUFFER"))
	cacheBuffer := time.Duration(getCaBuff) * time.Minute

	urlCache_.RLock()
	cached, found := urlCache[key]
	urlCache_.RUnlock()

	if found && time.Now().Before(cached.expiresAt.Add(-cacheBuffer)) {
		return cached.url, nil
	}

	payload := SignedPayload{
		Key: key,
		Exp: time.Now().Add(signedURLExpiry).Unix(),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	token := base64.RawURLEncoding.EncodeToString(payloadBytes)

	h := hmac.New(sha256.New, []byte(os.Getenv("SIGN_SECRET")))
	h.Write(payloadBytes)

	signature := hex.EncodeToString(h.Sum(nil))

	finalURL := fmt.Sprintf(
		"https://%s/%s?token=%s&sig=%s",
		os.Getenv("R2_PUBLIC_URL"),
		key,
		token,
		signature,
	)

	urlCache_.Lock()
	urlCache[key] = signedURLCache{
		url:       finalURL,
		expiresAt: time.Now().Add(signedURLExpiry),
	}
	urlCache_.Unlock()

	return finalURL, nil
}

func cleanupURLCache() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		urlCache_.Lock()
		for key, cached := range urlCache {
			if now.After(cached.expiresAt) {
				delete(urlCache, key)
			}
		}
		urlCache_.Unlock()
	}
}

func VerifyUploadedR2Key(ctx *gin.Context, errJson *models.ErrorDetail, field string, key string, features string) (string, bool) {
	if field == "image" && !HasFeature(features, "upload_image") {
		DeleteFromR2(key)
		GetErrorJson("FEATURE_UNAVAILABLE", errJson)
		JSON(ctx, errJson.Http, false, errJson.Message, nil, "")
		return "", false
	}

	if field == "video" && !HasFeature(features, "upload_video") {
		DeleteFromR2(key)
		GetErrorJson("FEATURE_UNAVAILABLE", errJson)
		JSON(ctx, errJson.Http, false, errJson.Message, nil, "")
		return "", false
	}

	if key == "" {
		return "", true
	}

	head, errHead := HeadR2Object(key)
	if errHead != nil {
		GetErrorJson("BAD_REQUEST", errJson)
		JSON(ctx, errJson.Http, false, errJson.Message, nil, errJson.Code)
		return "", false
	}

	typePrefix := map[string]string{"image": "image/", "video": "video/"}
	maxSizeKey := map[string]string{"image": "IMAGE_MAX_SIZE", "video": "VIDEO_MAX_SIZE"}

	contentType := ""
	if head.ContentType != nil {
		contentType = *head.ContentType
	}
	if !strings.HasPrefix(contentType, typePrefix[field]) {
		DeleteFromR2(key)
		GetErrorJson("INVALID_FILETYPE", errJson)
		JSON(ctx, errJson.Http, false, strings.Replace(errJson.Message, "{media}", "image, video", 1), nil, errJson.Code)
		return "", false
	}

	maxSize, _ := strconv.Atoi(os.Getenv(maxSizeKey[field]))
	if head.ContentLength != nil && *head.ContentLength > int64(maxSize) {
		DeleteFromR2(key)
		InvFileSizeRes(ctx, field, int64(maxSize))
		return "", false
	}

	return key, true
}
