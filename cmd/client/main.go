package main

import (
	"my-vpn/internal/client"
)

func main() {
	client := client.NewVPNClient("51820")
	client.Start()
}
