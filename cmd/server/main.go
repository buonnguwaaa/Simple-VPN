package main

import (
	"Simple-VPN/internal/app/server"
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

	s := server.NewVPNServer(os.Getenv("PORT"))
	errCh := make(chan error, 1)

	go func() {
		errCh <- s.Run()
	}()

	select {
	case <-ctx.Done():
		log.Println("Shutdown signal received")

	case err := <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("server.Run failed: %v", err)
		}
	}

	if err := s.Stop(); err != nil {
		log.Printf("server.Stop failed: %v", err)
	}

	log.Println("Server shutdown successfully")
}
