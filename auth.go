package sqlauthgo

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func InitAuth(driver, dsn string) error {
	var err error
	db, err = sql.Open(driver, dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	if err = setupTables(); err != nil {
		return fmt.Errorf("failed to setup tables: %v", err)
	}
	return nil
}

func Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var storedPassword, role string
	err := db.QueryRow("SELECT password, role FROM users WHERE username = ?", loginRequest.Username).Scan(&storedPassword, &role)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(loginRequest.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	accessToken, err := generateAccessToken(loginRequest.Username, role)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateRefreshToken(loginRequest.Username)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	expirationTime := time.Now().Add(7 * 24 * time.Hour)
	_, err = db.Exec("INSERT OR REPLACE INTO tokens (username, access_token, refresh_token, expires_at) VALUES (?, ?, ?, ?)",
		loginRequest.Username, accessToken, refreshToken, expirationTime)
	if err != nil {
		http.Error(w, "Failed to store tokens", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func Register(w http.ResponseWriter, r *http.Request) {
	var registerRequest RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&registerRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var usernameExists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", registerRequest.Username).Scan(&usernameExists)
	if err != nil || usernameExists {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registerRequest.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to process password", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", registerRequest.Username, hashedPassword, registerRequest.Role)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	var requestBody map[string]string
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	refreshToken := requestBody["refresh_token"]
	if refreshToken == "" {
		http.Error(w, "Refresh token is missing", http.StatusBadRequest)
		return
	}

	token, err := jwt.ParseWithClaims(refreshToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		log.Printf("Error parsing refresh token: %v", err)
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	var storedRefreshToken, role string
	err = db.QueryRow("SELECT refresh_token, role FROM tokens WHERE username = ?", claims.Username).Scan(&storedRefreshToken, &role)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Refresh token not found", http.StatusUnauthorized)
		} else {
			log.Printf("Error querying refresh token: %v", err)
			http.Error(w, "Failed to verify refresh token", http.StatusInternalServerError)
		}
		return
	}

	storedRefreshToken = strings.TrimSpace(storedRefreshToken)

	if storedRefreshToken != refreshToken {
		log.Printf("Refresh token mismatch: stored=%s, received=%s", storedRefreshToken, refreshToken)
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	newAccessToken, err := generateAccessToken(claims.Username, role)
	if err != nil {
		log.Printf("Error generating new access token: %v", err)
		http.Error(w, "Failed to generate new access token", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("UPDATE tokens SET access_token = ? WHERE username = ?", newAccessToken, claims.Username)
	if err != nil {
		log.Printf("Error updating access token in the database: %v", err)
		http.Error(w, "Failed to update access token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"access_token": newAccessToken})
}
