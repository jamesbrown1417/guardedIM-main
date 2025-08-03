package server

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"strings"
	"time"

	_ "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func UpdateConnection(db *sql.DB) error {

	// preparations
	type server_row struct {
		PubIP  []byte
		Port   int
		PrivIP []byte
		PubKey []byte
		PSK    []byte
	}
	keepalive_interval := 25 * time.Second

	// connect to the wireguard control
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	// read existing wg0 device
	wg_dev, err := client.Device("wg0")
	if err != nil {
		return err
	}

	// keep the old configuration
	new_conf := wgtypes.Config{
		PrivateKey:   &wg_dev.PrivateKey,
		ListenPort:   &wg_dev.ListenPort,
		FirewallMark: &wg_dev.FirewallMark,
		ReplacePeers: true,
	}

	// extract wg interface IP address
	wg_iface, err := net.InterfaceByName("wg0")
	if err != nil {
		return err
	}
	addrs, err := wg_iface.Addrs()
	if err != nil {
		return err
	}
	var wg_privip string
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if v4 := ipnet.IP.To4(); v4 != nil {
				wg_privip = v4.String()
			}
		}
	}
	if len(wg_privip) == 0 {
		return errors.New("unable to get wireguard interface IP address")
	}

	// database query
	peer_server_SQL := `SELECT server_pubip, server_port, server_privip, server_pubkey, server_presharedkey
						FROM server_info_table
						WHERE server_privip <> $1;`

	peer_user_SQL := `SELECT user_pubkey, latest_ip
					  FROM user_info_table
					  WHERE latest_ip LIKE $1;`

	// start crafting server peers
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, peer_server_SQL, wg_privip)
	if err != nil {
		return err
	}
	defer rows.Close()

	new_peers := []wgtypes.PeerConfig{}
	for rows.Next() {
		var row server_row
		if err := rows.Scan(&row.PubIP, &row.Port, &row.PrivIP, &row.PubKey, &row.PSK); err != nil {
			log.Printf("scan server row failed: %v", err)
			continue
		}

		pubkey, err := wgtypes.NewKey(row.PubKey)
		if err != nil {
			log.Printf("skip server peer: invalid pubkey: %v", err)
			continue
		}
		psk, err := wgtypes.NewKey(row.PSK)
		if err != nil {
			log.Printf("skip server peer: invalid psk: %v", err)
			continue
		}

		pubIP := net.IP(row.PubIP)
		privIP := net.IP(row.PrivIP)
		if pubIP == nil || privIP == nil {
			log.Printf("skip server peer: invalid IP bytes")
			continue
		}

		new_peers = append(new_peers, wgtypes.PeerConfig{
			PublicKey:                   pubkey,
			PresharedKey:                &psk,
			Endpoint:                    &net.UDPAddr{IP: pubIP, Port: row.Port},
			AllowedIPs:                  []net.IPNet{{IP: privIP, Mask: net.CIDRMask(32, 32)}},
			PersistentKeepaliveInterval: &keepalive_interval,
			ReplaceAllowedIPs:           true,
		})
	}

	// start crafting user peers
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wg_privip_prefix := wg_privip[:strings.LastIndex(wg_privip, ".")+1] + "%"

	rows, err = db.QueryContext(ctx, peer_user_SQL, wg_privip_prefix)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var pubKeyBytes []byte
		var userIP string
		if err := rows.Scan(&pubKeyBytes, &userIP); err != nil {
			log.Printf("scan user row failed: %v", err)
			continue
		}
		pubkey, err := wgtypes.NewKey(pubKeyBytes)
		if err != nil {
			log.Printf("skip user peer: invalid pubkey: %v", err)
			continue
		}
		new_peers = append(new_peers, wgtypes.PeerConfig{
			PublicKey: pubkey,
			AllowedIPs: []net.IPNet{{
				IP:   net.ParseIP(userIP),
				Mask: net.CIDRMask(32, 32),
			}},
			ReplaceAllowedIPs:           true,
			PersistentKeepaliveInterval: &keepalive_interval,
		})
	}

	new_conf.Peers = new_peers
	if err := client.ConfigureDevice("wg0", new_conf); err != nil {
		return err
	}
	return nil

}
