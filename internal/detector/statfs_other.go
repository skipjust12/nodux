//go:build !(linux || darwin || freebsd)

package detector

import "errors"

func statfs(string) (DiskUsage, error) {
	return DiskUsage{}, errors.New("disk checks are not supported on this OS")
}
