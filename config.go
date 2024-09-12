package sqlauthgo

import (
	"database/sql"
	"os"
	"strconv"

	"github.com/golang-jwt/jwt/v4"
)

var (
	jwtKey             = []byte(os.Getenv("SQLAUTHGO_TOKEN"))
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
