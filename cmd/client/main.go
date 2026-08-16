package main

import (
	"Simple-VPN/internal/app/client"
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	_ = godotenv.Load(".env")

	client := client.NewVPNClient(os.Getenv("PORT"))
	errCh := make(chan error, 1)

	go func() {
		errCh <- client.Run()
	}()

	select {
	case <-ctx.Done():
		log.Println("Shutdown signal received")

	case err := <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("client.Run failed: %v", err)
		}
	}

	if err := client.Stop(); err != nil {
		log.Printf("client.Stop failed: %v", err)
	}

	log.Println("Client shutdown successfully")
}
