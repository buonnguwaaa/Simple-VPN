package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

type tunnel struct {
	tun *water.Interface
}

// Open creates a TUN, assigns addr, and adds routes on that device.
//
// Full tunnel uses 0.0.0.0/1 and 128.0.0.0/1 (not 0.0.0.0/0). Those prefixes
// beat the existing default route; 0.0.0.0/0 would conflict with it.
// Call ProtectHost first so the VPN server UDP endpoint does not follow the TUN.
func Open(ctx context.Context, addr string, routes ...string) (*tunnel, error) {
	tun, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, err
	}

	ifName := tun.Name()
	log.Printf("Created TUN interface: %s\n", ifName)

	// Addr is the IP address of the TUN interface -> Who is tun0
	if addr != "" {
		if err := exec.CommandContext(
			ctx, "ip", "addr", "add", addr, "dev", ifName,
		).Run(); err != nil {
			return nil, err
		}
	}

	if err := exec.CommandContext(
		ctx, "ip", "link", "set", "dev", ifName, "up",
	).Run(); err != nil {
		return nil, err
	}

	for _, route := range routes {
		if route == "" {
			continue
		}

		if err := exec.CommandContext(
			ctx, "ip", "route", "add", route, "dev", ifName,
		).Run(); err != nil {
			return nil, err
		}
	}

	log.Printf("TUN interface %s configured and up\n", ifName)

	return &tunnel{
		tun: tun,
	}, nil
}

// ProtectHost adds a host route via the current default gateway so packets to
// host stay on the physical NIC. Loopback and unspecified addresses are no-ops.
func ProtectHost(ctx context.Context, host net.IP) error {
	if host == nil || host.IsLoopback() || host.IsUnspecified() {
		return nil
	}

	gw, iface, err := defaultGateway(ctx)
	if err != nil {
		return err
	}

	return exec.CommandContext(
		ctx, "ip", "route", "add", host.String()+"/32", "via", gw, "dev", iface,
	).Run()
}

func defaultGateway(ctx context.Context) (gw, iface string, err error) {
	out, err := exec.CommandContext(ctx, "ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", "", err
	}

	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			gw = fields[i+1]
		}
		if f == "dev" && i+1 < len(fields) {
			iface = fields[i+1]
		}
	}

	if gw == "" || iface == "" {
		return "", "", fmt.Errorf("no default IPv4 route")
	}

	return gw, iface, nil
}

func (t *tunnel) Read(buffer []byte) (int, error) {
	return t.tun.Read(buffer)
}

func (t *tunnel) Write(buffer []byte) (int, error) {
	return t.tun.Write(buffer)
}

func (t *tunnel) Close() error {
	if err := t.tun.Close(); err != nil {
		return err
	}

	log.Printf("TUN interface %s closed\n", t.tun.Name())

	return nil
}
