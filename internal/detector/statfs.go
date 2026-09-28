//go:build linux || darwin || freebsd

package detector

import "syscall"

func statfs(path string) (DiskUsage, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return DiskUsage{}, err
	}
	bsize := uint64(st.Bsize)
	u := DiskUsage{
		Used:        (uint64(st.Blocks) - uint64(st.Bfree)) * bsize,
		Avail:       uint64(st.Bavail) * bsize,
		InodesTotal: uint64(st.Files),
	}
	if u.InodesTotal > 0 {
		u.InodesUsed = u.InodesTotal - uint64(st.Ffree)
	}
	return u, nil
}
