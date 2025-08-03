package main

import (
	"database/sql"
	"flag"
	"fmt"
	"guardedim/server"
)

func addUserCmd(db *sql.DB, args []string) {
	fs := flag.NewFlagSet("adduser", flag.ExitOnError)
	username := fs.String("username", "", "username (required)")
	display_name := fs.String("display-name", "", "display name (optional)")
	latest_ip := fs.String("latest-ip", "", "user wireguard ip address (required)")
	pubkey := fs.String("public-key", "", "wireguard public key (required)")
	fs.Parse(args)

	if *username == "" || *pubkey == "" {
		fs.Usage()
		return
	}

	if _, err := server.AddUser(db, *username, *display_name, *pubkey, *latest_ip); err == nil {
		fmt.Println("successfully added the user")
	} else {
		fmt.Printf("failed to add the user: %v\n", err)
	}
}
