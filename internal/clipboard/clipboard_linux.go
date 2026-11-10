package clipboard

import "errors"

func Copy(b []byte) error {
	return errors.New("clipboard: not implemented on linux")
}

func Read() ([]byte, error) {
	return nil, errors.New("clipboard: not implemented on linux")
}

func Clear() error {
	return errors.New("clipboard: not implemented on linux")
}
