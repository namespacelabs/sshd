//go:build !unix

package ssh

import (
	"golang.org/x/sys/unix"
)

func FillTermiosFromOps(ops map[int]uint32, t *unix.Termios) {
}
