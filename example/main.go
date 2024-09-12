package main

import (
	"log"
	"net/http"

	"github.com/kythonlk/sqlauthgo"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	err := sqlauthgo.InitAuth("sqlite3", "./test.db")
	if err != nil {
		log.Fatalf("Error initializing auth library: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/register", sqlauthgo.Register)
	mux.HandleFunc("/login", sqlauthgo.Login)
	mux.HandleFunc("/refresh", sqlauthgo.RefreshToken)

	mux.HandleFunc("/admin", sqlauthgo.AuthMiddleware(sqlauthgo.RoleBasedMiddleware("admin", handleAdmin)))

	http.ListenAndServe(":8080", mux)
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome, Admin!"))
}
