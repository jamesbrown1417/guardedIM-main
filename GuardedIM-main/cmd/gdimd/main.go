package main

import (
	"context"
	"fmt"
	"guardedim/client"
	"guardedim/server"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"golang.org/x/sync/errgroup"
)

func main() {

	opmode := os.Getenv("GDIM_DAEMON_OPMODE")
	privkey := os.Getenv("GDIM_WG_PRIVKEY")
	db_access_url := os.Getenv("GDIM_DB_ACCESS_URL")
	cert_dir := os.Getenv("GDIM_CERT_DIR")
	wg_privip := os.Getenv("GDIM_WG_PRIVIP")
	wg_port := os.Getenv("GDIM_WG_PORT")
	client_localdb_path := os.Getenv("GDIM_CLIENT_LOCALDB_FILEPATH")
	wg_MTU, err := strconv.Atoi(os.Getenv("GDIM_WG_MTU"))
	if err != nil {
		fmt.Printf("the given MTU is invalid: %v", err)
		os.Exit(1)
	}

	switch opmode {
	case "client":
		_, err := client.InitializeLocalDB(client_localdb_path)
		if err != nil {
			fmt.Printf("database access failed: %v", err)
		}
		ctx, cancel := signal.NotifyContext(context.Background(),
			syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		g, ctx := errgroup.WithContext(ctx)
		g.Go(func() error {
			wgDev, err := client.InitializeInterface(wg_privip, wg_privip, wg_MTU)
			if err != nil {
				fmt.Printf("wireguard interface initialization failed: %v", err)
				return err
			}
			<-ctx.Done()
			wgDev.Close()
			return nil
		})

		// ---------- wait & exit ----------
		if err := g.Wait(); err != nil {
			log.Fatalf("daemon stopped: %v", err)
		}
		log.Println("daemon exited cleanly")
	case "server":
		db, err := server.OpenDBWithURL(db_access_url)
		if err != nil {
			fmt.Printf("database access failed: %v", err)
		}
		// ---------- shared context ----------
		ctx, cancel := signal.NotifyContext(context.Background(),
			syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		g, ctx := errgroup.WithContext(ctx)

		// ---------- WireGuard ----------
		g.Go(func() error {
			wgDev, err := server.InitializeInterface(wg_privip, privkey, wg_port, wg_MTU, db_access_url)
			if err != nil {
				fmt.Printf("wireguard interface initialization failed: %v", err)
				return err
			}
			<-ctx.Done()
			wgDev.Close()
			return nil
		})

		// ---------- HTTP control (mTLS) ----------
		g.Go(func() error {
			// certDir points to ca.crt / node.crt / node.key
			return server.InitializeControlServ(ctx, db, cert_dir)
		})

		// ---------- wait & exit ----------
		if err := g.Wait(); err != nil {
			log.Fatalf("daemon stopped: %v", err)
		}
		log.Println("daemon exited cleanly")
	default:
		fmt.Println("Unsupported operation mode!")
		os.Exit(1)
	}
}
