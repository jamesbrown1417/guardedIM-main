package server

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func OpenDB(addr string, port uint16, db_username string, cert_dir string) (*sql.DB, error) {
	db_access_url := fmt.Sprintf(
		"postgresql://%s@%s:%d/defaultdb?sslmode=verify-full&sslrootcert=%s&sslcert=%s&sslkey=%s",
		db_username, addr, port,
		filepath.Join(cert_dir, "ca.crt"),
		filepath.Join(cert_dir, fmt.Sprintf("client.%s.crt", db_username)),
		filepath.Join(cert_dir, fmt.Sprintf("client.%s.key", db_username)),
	)

	return OpenDBWithURL(db_access_url)
}

func CraftDBAccessURL(addr string, port uint16, db_username string, cert_dir string) string {
	db_access_url := fmt.Sprintf(
		"postgresql://%s@%s:%d/defaultdb?sslmode=verify-full&sslrootcert=%s&sslcert=%s&sslkey=%s",
		db_username, addr, port,
		filepath.Join(cert_dir, "ca.crt"),
		filepath.Join(cert_dir, fmt.Sprintf("client.%s.crt", db_username)),
		filepath.Join(cert_dir, fmt.Sprintf("client.%s.key", db_username)),
	)
	return db_access_url
}

func OpenDBWithURL(db_access_url string) (*sql.DB, error) {
	db, err := sql.Open("pgx", db_access_url)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(25)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return db, nil
}
