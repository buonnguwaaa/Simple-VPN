package main

import (
	"Simple-VPN/internal/app/server"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load(".env")
	s := server.NewVPNServer(os.Getenv("PORT"))
	s.Start()
}
