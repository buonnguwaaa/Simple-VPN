package main

import (
	"Simple-VPN/internal/app/client"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load(".env")
	client := client.NewVPNClient(os.Getenv("PORT"))
	client.Start()
}
