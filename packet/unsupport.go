//go:build linux || darwin

package packet

// as linux and darwin default use utf8, there is no need to handle them again
func codepageToUTF8Native(b []byte) ([]byte, error) {
	return b, nil
}
