package tunnel

type Tunnel interface {
	Read(buffer []byte) (int, error)
	Write(buffer []byte) (int, error)
	Close() error
}