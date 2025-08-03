package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"time"
)

type RelayRow struct {
	ServerID   uint64 `json:"id"`
	ServerName string `json:"name,omitempty"`
	PubIP      []byte `json:"pub_ip"`
	Port       uint16 `json:"port"`
	PrivIP     []byte `json:"priv_ip"`
	PubKey     []byte `json:"pub_key"`
}

func httpHandleRelayTable(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		rows, err := db.QueryContext(ctx, `
		SELECT server_id, server_name, server_pubip, server_port, server_privip, server_pubkey
		FROM server_info_table`)
		if err != nil {
			http.Error(w, "db query failed", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var list []RelayRow
		for rows.Next() {
			var row RelayRow
			if err := rows.Scan(&row.ServerID,
				&row.ServerName,
				&row.PubIP,
				&row.Port,
				&row.PrivIP,
				&row.PubKey); err != nil {
				http.Error(w, "scan error", http.StatusInternalServerError)
				return

			}
			list = append(list, row)
		}
		if rows.Err() != nil {
			http.Error(w, "rows error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	}
}

// nonceEntry holds the nonce bytes and expiry timestamp
type nonceEntry struct {
	val    []byte
	expiry time.Time
}

// globalNonceStore is now map[user_id]nonceEntry
var globalNonceStore = make(map[uint64]nonceEntry)

// httpHandleReplaceIP serves BOTH phases:
//   - Phase‑1 challenge:  client POSTs  {user_id, ip_address}
//     ↳ server returns   {nonce: "<hex>"}
//   - Phase‑2 verify:    client POSTs  {user_id, ip_address, sig: "<base64>"}
//     ↳ server returns   {free: bool, written: bool}
//
// A nonce is single‑use and stored only in RAM.  It expires after 30 s.
func httpHandleReplaceIP(db *sql.DB) http.HandlerFunc {
	type request struct {
		UserID    uint64 `json:"user_id"`
		IPAddress string `json:"ip_address"`
		SigB64    string `json:"sig,omitempty"`
	}
	type respChallenge struct {
		Nonce string `json:"nonce"`
	}
	type respResult struct {
		Free    bool `json:"free"`
		Written bool `json:"written"`
	}

	const nonceTTL = 30 * time.Second

	// background goroutine to purge stale nonces
	go func() {
		for {
			time.Sleep(nonceTTL)
			now := time.Now()
			for uid, entry := range globalNonceStore {
				if now.After(entry.expiry) {
					delete(globalNonceStore, uid)
				}
			}
		}
	}()

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		// basic IP validity check
		if net.ParseIP(req.IPAddress) == nil {
			http.Error(w, "invalid ip", http.StatusBadRequest)
			return
		}

		// ---- Phase 1: challenge ----
		if req.SigB64 == "" {
			nonce := make([]byte, 32)
			if _, err := rand.Read(nonce); err != nil {
				http.Error(w, "rand", http.StatusInternalServerError)
				return
			}
			globalNonceStore[req.UserID] = nonceEntry{val: nonce, expiry: time.Now().Add(nonceTTL)}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(respChallenge{Nonce: hex.EncodeToString(nonce)})
			return
		}

		// ---- Phase 2: verify signature ----
		entry, ok := globalNonceStore[req.UserID]
		if !ok || time.Now().After(entry.expiry) {
			http.Error(w, "no nonce", http.StatusForbidden)
			return
		}
		delete(globalNonceStore, req.UserID) // single-use

		sig, err := base64.StdEncoding.DecodeString(req.SigB64)
		if err != nil {
			http.Error(w, "bad sig encoding", http.StatusBadRequest)
			return
		}
		var pubKey []byte
		if err := db.QueryRow(`SELECT user_pubkey FROM user_info_table WHERE user_id=$1`, req.UserID).
			Scan(&pubKey); err != nil {
			http.Error(w, "user not found", http.StatusForbidden)
			return
		}
		if !ed25519.Verify(pubKey, entry.val, sig) {
			http.Error(w, "signature fail", http.StatusForbidden)
			return
		}

		// ---- check IP and update ----
		var occupiedBy uint64
		e := db.QueryRow(`SELECT user_id FROM user_info_table WHERE latest_ip = $1`, req.IPAddress).Scan(&occupiedBy)
		if e != nil && e != sql.ErrNoRows {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		free := e == sql.ErrNoRows || occupiedBy == req.UserID
		written := false
		if free {
			res, err := db.Exec(`UPDATE user_info_table SET latest_ip = $1 WHERE user_id = $2`, req.IPAddress, req.UserID)
			if err != nil {
				http.Error(w, "update fail", http.StatusInternalServerError)
				return
			}
			if n, _ := res.RowsAffected(); n == 1 {
				written = true
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(respResult{Free: free, Written: written})
	}
}
