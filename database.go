package sqlauthgo

import (
	"database/sql"
	"log"
)

func SetDB(driver, dsn string) (*sql.DB, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
		return nil, err
	}
	return db, nil
}

func setupTables() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user'
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS tokens (
			username TEXT PRIMARY KEY,
			access_token TEXT,
			refresh_token TEXT,
			expires_at DATETIME
		)
	`)
	return err
}
