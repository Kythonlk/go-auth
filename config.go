package sqlauthgo

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"github.com/golang-jwt/jwt/v4"
)

var (
	jwtKey             = getJWTKey()
	accessTokenExpiry  = getEnvAsInt("SQLAUTHGO_ACCESS_EXPIRY", 30)
	refreshTokenExpiry = getEnvAsInt("SQLAUTHGO_REFRESH_EXPIRY", 7*24*60)
)

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

var db *sql.DB

func getEnvAsInt(name string, defaultValue int) int {
	valueStr := os.Getenv(name)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func getJWTKey() []byte {
	key := os.Getenv("SQLAUTHGO_TOKEN")
	if key == "" {
		newKey := generateRandomKey()
		fmt.Printf("Generated new JWT key: %s\n", newKey)
		if err := saveKeyToEnvFile("SQLAUTHGO_TOKEN", newKey); err != nil {
			fmt.Printf("Failed to save JWT key to .env file: %v\n", err)
		}
		return []byte(newKey)
	}
	return []byte(key)
}

func generateRandomKey() string {
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		panic("Failed to generate random key")
	}
	return base64.StdEncoding.EncodeToString(key)
}

func saveKeyToEnvFile(key, value string) error {
	envFile := ".env"
	f, err := os.OpenFile(envFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(fmt.Sprintf("%s=%s\n", key, value)); err != nil {
		return err
	}
	return nil
}
