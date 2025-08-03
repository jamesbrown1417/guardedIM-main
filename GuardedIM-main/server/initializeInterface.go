package server

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// this function creates a wireguard interface inside user space
// it utilizes system TUN functionality
// can generate a new private key if not provided
// return the created wireguard interface and error
func createWG0(wg_privkey string, server_port string) (*device.Device, error) {

	// declare the variables beforehand to prevent shadowing
	var key wgtypes.Key
	var err error

	// check if the port is valid
	port, err := strconv.Atoi(server_port)
	if port < 0 || port > 65535 || err != nil {
		return nil, errors.New("port out of range")
	}

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

	// create a TUN device first
	tun_dev, err := tun.CreateTUN("wg0", 1500)
	if err != nil {
		return nil, err
	}

	bind := conn.NewDefaultBind()
	logger := device.NewLogger(device.LogLevelVerbose, "wg0: ")

	// create wireguard device
	wg_dev := device.NewDevice(tun_dev, bind, logger)
	go wg_dev.RoutineTUNEventReader()

	// generate the configuration
	wg_config := fmt.Sprintf("private_key=%s\nlisten_port=%s", wg_privkey, server_port)

	return wg_dev, wg_dev.IpcSet(wg_config)
}

// this function sets IP layer parameters under Linux environment and adds route for this new interface
// needs private IP, but MTU can be set to zero to use the default value
// return error
func setupWG0Linux(server_privip string, MTU int) error {

	privip := net.ParseIP(server_privip)
	var ip_net *net.IPNet
	if privip == nil {
		return errors.New("the given IP address is not valid")
	}
	if v4 := privip.To4(); v4 != nil {
		if v4[3] != 1 {
			return errors.New("IPv4 server_privip must end with .1")
		}
		ip_net = &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	} else {
		ip16 := privip.To16()
		if binary.BigEndian.Uint16(ip16[14:]) != 1 {
			return errors.New("IPv6 server_privip must end with …:1")
		}
		ip_net = &net.IPNet{IP: ip16, Mask: net.CIDRMask(128, 128)}
	}

	if MTU == 0 {
		MTU = 1500
	}

	if MTU > 1700 || MTU < 800 {
		return errors.New("the MTU is either too large or too small")
	}

	link, err := netlink.LinkByName("wg0")
	if err != nil {
		return err
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ip_net}); err != nil {
		return err
	}

	if err = netlink.LinkSetUp(link); err != nil {
		return err
	}

	if err = netlink.LinkSetMTU(link, MTU); err != nil {
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

// this function initializes the entire wireguard interface under Linux
// return the initialized wireguard device pointer
func InitializeInterface(server_privip string, server_privkey string, server_port string, MTU int, db_access_url string) (*device.Device, error) {
	var wg_dev *device.Device
	var err error
	wg_dev, err = createWG0(server_privkey, server_port)
	if err != nil {
		return nil, err
	}
	err = setupWG0Linux(server_privip, MTU)
	if err != nil {
		return nil, err
	}
	db, err := OpenDBWithURL(db_access_url)
	if err != nil {
		fmt.Println("database connect failed!")
		return nil, err
	}
	err = UpdateConnection(db)
	if err != nil {
		fmt.Println("initial connection update failed")
		return nil, err
	}
	return wg_dev, nil
}
