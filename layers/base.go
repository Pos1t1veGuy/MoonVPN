package layers

type NetLayer interface {
	Wrap(data []byte) ([]byte, error)
	Unwrap(data []byte) ([]byte, error)
}

type DefaultNetLayer struct{}
