package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func AddServer(db *sql.DB, server_name string, server_pubip string, server_port uint16, server_privip string, server_pubkey string, server_presharedkey string) (int64, error) {
	// input check
	if len(server_name) == 0 {
		server_name = "default_server_name"
	}
	wgpubkey, err := wgtypes.ParseKey(server_pubkey)
	if err != nil {
		return -1, errors.New("invalid public key")
	}
	wgpsk, err := wgtypes.ParseKey(server_presharedkey)
	if err != nil {
		return -2, errors.New("invalid preshared key")
	}
	if n := len(server_name); n > 64 {
		return -3, errors.New("invalid servername! it's too long")
	}
	pubIP := net.ParseIP(server_pubip)
	if pubIP == nil {
		return -4, errors.New("invalid public IP! please check")
	}
	privIP := net.ParseIP(server_privip)
	if privIP == nil {
		return -5, errors.New("invalid private IP! please check")
	}

	// ensure private IP falls within 10.0.0.0/8
	_, subnet10, _ := net.ParseCIDR("10.0.0.0/8")
	if !subnet10.Contains(privIP) {
		return -6, errors.New("invalid private IP: must be within 10.0.0.0/8")
	}

	// database operation
	pubIP16 := pubIP.To16()
	privIP16 := privIP.To16()
	wgpubkeyBytes := wgpubkey[:]
	wgpskBytes := wgpsk[:]

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	const addserver_sql = `
			INSERT INTO server_info_table
            (server_name, server_pubip, server_port, server_privip, server_pubkey, server_presharedkey)
        	VALUES ($1, $2, $3, $4, $5, $6)
        	RETURNING server_id;`
	var new_server_id int64
	err = db.QueryRowContext(ctx, addserver_sql,
		server_name,
		pubIP16,
		server_port,
		privIP16,
		wgpubkeyBytes,
		wgpskBytes).Scan(&new_server_id)
	if err != nil {
		return -7, fmt.Errorf("error when inserting into Relay Server Table: %w", err)
	}
	return new_server_id, nil
}
