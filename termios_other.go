//go:build !unix

package ssh

type Termios = struct{}

func FillTermiosFromOps(ops map[int]uint32, t *Termios) {
}
