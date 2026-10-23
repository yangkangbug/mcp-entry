//go:build !linux && !darwin

package main

import "errors"

// No weaker file-opening fallback is available on unsupported platforms.
func readPrivate(string, int64) ([]byte, error) {
	return nil, errors.New("secure private-file input unsupported on this platform")
}
