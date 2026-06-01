package main

import (
	"my-vpn/internal/server"
)

func main() {
	s := server.NewVPNServer("51820")
	s.Start()
}
