package client

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ──────────── createWG0Client ──────────────────────────────────────────
// Creates a userspace WireGuard interface for a **client**.
// • No ListenPort: outbound UDP uses an ephemeral port.
// • If wg_privkey is empty, a fresh key is generated.
func createWG0Client(wg_privkey string) (*device.Device, error) {

	// declare the variables beforehand to prevent shadowing
	var key wgtypes.Key
	var err error

	// allow for empty privatekey
	if len(wg_privkey) != 0 {
		key, err = wgtypes.ParseKey(wg_privkey)
		if err != nil {
			return nil, err
		}
	} else {
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
	}

	wg_privkey = hex.EncodeToString(key[:])

	tun_dev, err := tun.CreateTUN("wg0", 1500)
	if err != nil {
		return nil, err
	}

	bind := conn.NewDefaultBind()
	logger := device.NewLogger(device.LogLevelVerbose, "wg0: ")
	wgDev := device.NewDevice(tun_dev, bind, logger)
	go wgDev.RoutineTUNEventReader()

	cfg := fmt.Sprintf("private_key=%s\n", wg_privkey)
	return wgDev, wgDev.IpcSet(cfg)
}

// ──────────── setupWG0LinuxClient ─────────────────────────────────────
// Assigns the client's IP, sets MTU (default 1280), and brings the link UP.
func setupWG0LinuxClient(clientIP string, MTU int) error {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return errors.New("invalid client IP")
	}

	var ipNet *net.IPNet
	if v4 := ip.To4(); v4 != nil {
		ipNet = &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	} else {
		ip16 := ip.To16()
		ipNet = &net.IPNet{IP: ip16, Mask: net.CIDRMask(128, 128)}
	}

	if MTU == 0 {
		MTU = 1500
	}
	if MTU < 800 || MTU > 1700 {
		return errors.New("MTU out of reasonable range")
	}

	link, err := netlink.LinkByName("wg0")
	if err != nil {
		return err
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet}); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	if err := netlink.LinkSetMTU(link, MTU); err != nil {
		return err
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
	}
	if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

// ──────────── InitializeInterface (client) ─────────────────────────────
// Convenience wrapper that creates wg0 and configures IP/MTU.
// Returns the *device.Device so the caller can add peers later.
func InitializeInterface(clientIP, wg_privkey string, MTU int) (*device.Device, error) {
	wgDev, err := createWG0Client(wg_privkey)
	if err != nil {
		return nil, err
	}
	if err = setupWG0LinuxClient(clientIP, MTU); err != nil {
		return nil, err
	}
	return wgDev, nil
}
