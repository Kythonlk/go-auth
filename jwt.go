package sqlauthgo

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func generateAccessToken(username, role string) (string, error) {
	expirationTime := time.Now().Add(time.Duration(accessTokenExpiry) * time.Minute)
	claims := &Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func generateRefreshToken(username, role string) (string, error) {
	expirationTime := time.Now().Add(time.Duration(refreshTokenExpiry) * time.Minute)
	claims := &Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}
