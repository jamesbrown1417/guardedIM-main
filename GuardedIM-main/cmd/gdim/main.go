package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"guardedim/server"
	"os"
	"os/exec"
	"strconv"
)

const configFile = "guarded_im_config.json"

// typedConfig provides convenient strongly-typed access to critical fields
type typedConfig struct {
	OperationMode string `json:"operation_mode"`
	SelfIP        string `json:"self_server_wireguard_ip"`
	PrivateKey    string `json:"self_server_wireguard_private_key"`
	ListenPort    int    `json:"self_server_wireguard_listen_port"`
	MTU           int    `json:"self_server_wireguard_mtu"`
	PublicIP      string `json:"self_server_public_ip"`
	LocalDB       string `json:"self_client_localdb"`

	DBHost    string `json:"database_host"`
	DBPort    uint16 `json:"database_port"`
	DBCertDir string `json:"database_cert_directory"`
	DBName    string `json:"database_dbname"`
	DBUser    string `json:"database_username"`
}

var cfg typedConfig

func loadConfig() error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return errors.New("config not found")
	}
	// Also decode into typed struct for convenience
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	return nil
}

func main() {
	if err := loadConfig(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		fmt.Println("usage: gdim <command> [flags]")
		os.Exit(1)
	}

	switch cfg.OperationMode {
	case "server":
		db, err := server.OpenDB(cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBCertDir)
		if err != nil {
			fmt.Println("database connection failed")
			os.Exit(1)
		}

		switch os.Args[1] {
		case "adduser":
			addUserCmd(db, os.Args[2:])
		case "addserver":
			addServerCmd(db, os.Args[2:])
		case "startserver":
			exec.Command("systemctl", "set-environment",
				"GDIM_DAEMON_OPMODE="+"server",
				"GDIM_WG_PRIVKEY="+cfg.PrivateKey,
				"GDIM_DB_ACCESS_URL="+server.CraftDBAccessURL(cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBCertDir),
				"GDIM_CERT_DIR="+cfg.DBCertDir,
				"GDIM_WG_PRIVIP="+cfg.SelfIP,
				"GDIM_WG_PORT="+strconv.Itoa(cfg.ListenPort),
				"GDIM_WG_MTU="+strconv.Itoa(cfg.MTU)).Run()
			startServerCmd(os.Args[2:])
		case "serverstatus":
		case "stopserver":
		case "updateconn":
		default:
			fmt.Println("unrecognized subcommand, try again")
			os.Exit(1)
		}
	case "client":
		switch os.Args[1] {
		case "startclient":
			exec.Command("systemctl", "set-environment",
				"GDIM_CLIENT_LOCALDB_FILEPATH="+cfg.LocalDB)
			startClientCmd(os.Args[2:])
		case "fetchserverinfo":
		case "invite":
		default:
			fmt.Println("unsupported subcommand")
			os.Exit(1)
		}

	default:
		fmt.Println("operation mode not supported!")
		os.Exit(1)
	}

}
