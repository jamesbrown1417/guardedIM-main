package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func InitializeControlServ(ctx context.Context, db *sql.DB, certDir string) error {
	// --- TLS / mTLS setup ---
	caPem, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("read ca: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPem) {
		return errors.New("failed to append CA cert")
	}

	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "node.crt"),
		filepath.Join(certDir, "node.key"),
	)
	if err != nil {
		return fmt.Errorf("load server cert: %w", err)
	}

	// listen on all interfaces, port 8089
	bind := ":8089"

	mux := http.NewServeMux()
	mux.HandleFunc("/relay-table", httpHandleRelayTable(db))
	mux.HandleFunc("/ip/replace", httpHandleReplaceIP(db))

	srvTLS := &tls.Config{
		Certificates:             []tls.Certificate{serverCert},
		ClientCAs:                caPool,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
	}

	srv := &http.Server{
		Addr:         bind,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		TLSConfig:    srvTLS,
	}

	// graceful shutdown when ctx is cancelled
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	// empty strings because certificates are provided via TLSConfig
	return srv.ListenAndServeTLS("", "")
}

// NOTE: Update any invocations elsewhere to pass the context and certificate directory path.
