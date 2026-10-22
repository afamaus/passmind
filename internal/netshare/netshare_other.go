//go:build !windows

package netshare

// Supported meldet, ob PassMind Freigaben selbst verbinden kann.
const Supported = false

// Connect ist nur unter Windows verfügbar.
func Connect(share, user, password string) error { return ErrUnsupported }

// Disconnect ist nur unter Windows verfügbar.
func Disconnect(share string) {}

// Protect ist nur unter Windows verfügbar.
func Protect(secret []byte) ([]byte, error) { return nil, ErrUnsupported }

// Unprotect ist nur unter Windows verfügbar.
func Unprotect(blob []byte) ([]byte, error) { return nil, ErrUnsupported }
