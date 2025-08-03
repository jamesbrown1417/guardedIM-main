package main

import (
	"flag"
	"fmt"
	_ "guardedim/server"
	"os"
	"os/exec"
	"text/template"
)

// startServerCmd ensures gdimd.service exists, reloads systemd, enables & starts it.
// Called like: gdim startserver
func startServerCmd(args []string) {
	fs := flag.NewFlagSet("startserver", flag.ExitOnError)
	servicePath := fs.String("unit-path", "/etc/systemd/system/gdimd.service",
		"location for generated systemd unit")
	binaryPath := fs.String("bin", "/usr/local/bin/gdimd", "path to daemon binary")
	fs.Parse(args)

	// 1) If the unit file doesn't exist, create it from template
	if _, err := os.Stat(*servicePath); os.IsNotExist(err) {
		if err := writeUnitFile(*servicePath, *binaryPath); err != nil {
			fmt.Printf("cannot write unit file: %v\n", err)
			return
		}
		// reload systemd to pick up the new unit
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "enable", "gdimd").Run()
		fmt.Println("installed and started gdimd.service")
	}
	// 2) (re)start the service
	if err := exec.Command("systemctl", "restart", "gdimd").Run(); err != nil {
		fmt.Printf("failed to start gdimd: %v\n", err)
		fmt.Println("gdimd started")
	}
}

// writeUnitFile renders a minimal systemd unit.
func writeUnitFile(path, bin string) error {
	const tmpl = `[Unit]
Description=GuardedIM Daemon
After=network-online.target

[Service]
ExecStart={{ .Bin }}
Restart=on-failure
Type=simple

[Install]
WantedBy=multi-user.target
`
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return template.Must(template.New("unit").Parse(tmpl)).Execute(f, struct{ Bin string }{bin})
}
