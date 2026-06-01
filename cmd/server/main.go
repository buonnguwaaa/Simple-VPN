package main

import (
	"Simple-VPN/internal/server"
)

func main() {
	s := server.NewVPNServer("51820")
	s.Start()
}
