package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func AddUser(db *sql.DB, username string, display_name string, pubkey string, latest_ip string) (int64, error) {
	// input check
	wgpubkey, err := wgtypes.ParseKey(pubkey)
	if err != nil {
		return -1, errors.New("invalid public key")
	}
	if n := len(username); n <= 0 || n > 64 {
		return -2, errors.New("invalid username! It's empty or too long")
	}
	for i := 0; i < len(username); i++ {
		if username[i] > 0x7F {
			return -3, errors.New("invalid username! Special characters are not allowed")
		}
	}
	if !utf8.ValidString(display_name) {
		return -4, errors.New("illegal display name! It's not a valid UTF8 string")
	}
	if n := len(display_name); n <= 0 || n > 128 {
		return -5, errors.New("display name too long! Please choose a shorter one")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	const add_user_sql = `
		INSERT INTO user_info_table
			(username, display_name, user_pubkey, latest_ip)
		VALUES ($1, $2, $3, $4)
		RETURNING user_id;
	`

	var new_user_id int64
	err = db.QueryRowContext(ctx, add_user_sql,
		username,
		display_name,
		wgpubkey[:], // []byte{32}
		[]byte(latest_ip),
	).Scan(&new_user_id)
	if err != nil {
		if err == context.DeadlineExceeded {
			return -6, fmt.Errorf("db timeout: %w", err)
		}
		return -6, fmt.Errorf("insert user_info_table: %w", err)
	}

	return new_user_id, nil
}
