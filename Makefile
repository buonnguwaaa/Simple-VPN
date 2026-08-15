client:
	echo "Starting client..."
	go run cmd/client/main.go

server:
	echo "Starting server..."
	go run cmd/server/main.go

format:
	echo "Formatting code..."
	gofmt -w -s .
	goimports -w .