package tunnel

import (
	"log"
	"os/exec"

	"github.com/songgao/water"
)

type tunnel struct {
	tun *water.Interface
}

type Tunnel interface {
	Read(buffer []byte) (int, error)
	Write(buffer []byte) (int, error)
	Close() error
}

func Open(addr, route string) (*tunnel, error) {
	tun, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, err
	}

	ifName := tun.Name()
	log.Printf("Created TUN interface: %s\n", ifName)

	// Addr is the IP address of the TUN interface -> Who is tun0
	exec.Command(
		"ip", "addr", "add", addr, "dev", ifName,
	).Run()

	if err := exec.Command(
		"ip", "link", "set", "dev", ifName, "up",
	).Run(); err != nil {
		return nil, err
	}

	log.Printf("TUN interface %s configured and up\n", ifName)

	// Route is the route to the TUN interface -> Use tun0 to go where?
	if err := exec.Command(
		"ip", "route", "add", route, "dev", ifName,
	).Run(); err != nil {
		return nil, err
	}

	log.Printf("TUN interface %s configured and up\n", ifName)

	return &tunnel{
		tun: tun,
	}, nil
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
