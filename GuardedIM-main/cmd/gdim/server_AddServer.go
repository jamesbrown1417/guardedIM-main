package main

import (
	"database/sql"
	"flag"
	"fmt"
	"guardedim/server"
)

func addServerCmd(db *sql.DB, args []string) {
	fs := flag.NewFlagSet("addserver", flag.ExitOnError)
	server_name := fs.String("server-name", "default_name", "optional")
	pub_ip := fs.String("public-ip", "", "public IP (required)")
	port := fs.Int("port", 51820, "wireguard listening port")
	server_privip := fs.String("private-ip", "", "subnet IP (required)")
	server_pubkey := fs.String("public-key", "", "wireguard public key (required)")
	server_presharedkey := fs.String("preshared-key", "", "wireguard preshared key (required)")
	fs.Parse(args)

	if *pub_ip == "" || *server_privip == "" || *server_pubkey == "" || *server_presharedkey == "" {
		fs.Usage()
		return
	}

	if *port > 65535 || *port < 0 {
		fs.Usage()
		return
	}
	server_port := (uint16(*port))

	if _, err := server.AddServer(db, *server_name, *pub_ip, server_port, *server_privip, *server_pubkey, *server_presharedkey); err == nil {
		fmt.Println("server successfully added")
	} else {
		fmt.Printf("error when adding server: %v\n", err)
	}
}
