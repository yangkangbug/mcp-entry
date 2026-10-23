//go:build linux || darwin

package main

import (
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// openPrivate traverses without following symlinks, then verifies the opened
// descriptor rather than racing a path-based permission check against open.
func readPrivate(path string, limit int64) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || path == "" {
		return nil, errPrivate
	}
	parts := strings.Split(strings.TrimPrefix(absolute, "/"), "/")
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errPrivate
	}
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(dir, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dir)
		if e != nil {
			return nil, errPrivate
		}
		dir = next
	}
	fd, err := unix.Openat(dir, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	unix.Close(dir)
	if err != nil {
		return nil, errPrivate
	}
	file := os.NewFile(uintptr(fd), "private-credential")
	defer file.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Mode&07000 != 0 || st.Uid != uint32(os.Geteuid()) || st.Size < 1 || st.Size > limit {
		return nil, errPrivate
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		clear(data)
		return nil, errPrivate
	}
	return data, nil
}
