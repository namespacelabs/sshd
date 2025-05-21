//go:build unix

package ssh

import (
	"golang.org/x/sys/unix"
)

// FillTermiosFromOps updates a unix.Termios structure based on the Pty.Termios.
// Only the subset of flags that is common across unix platforms is actually set.
func FillTermiosFromOps(ops map[int]uint32, t *unix.Termios) {
	for k, v := range ops {
		switch k {
		// Character opcodes (c_cc array)
		case TTY_VINTR:
			t.Cc[unix.VINTR] = byte(v)
		case TTY_VQUIT:
			t.Cc[unix.VQUIT] = byte(v)
		case TTY_VERASE:
			t.Cc[unix.VERASE] = byte(v)
		case TTY_VKILL:
			t.Cc[unix.VKILL] = byte(v)
		case TTY_VEOF:
			t.Cc[unix.VEOF] = byte(v)
		case TTY_VEOL:
			t.Cc[unix.VEOL] = byte(v)
		case TTY_VEOL2:
			t.Cc[unix.VEOL2] = byte(v)
		case TTY_VSTART:
			t.Cc[unix.VSTART] = byte(v)
		case TTY_VSTOP:
			t.Cc[unix.VSTOP] = byte(v)
		case TTY_VSUSP:
			t.Cc[unix.VSUSP] = byte(v)

		// Input flags (c_iflag)
		case TTY_IGNPAR:
			setTermiosFlag(&t.Iflag, unix.IGNPAR, v)
		case TTY_PARMRK:
			setTermiosFlag(&t.Iflag, unix.PARMRK, v)
		case TTY_INPCK:
			setTermiosFlag(&t.Iflag, unix.INPCK, v)
		case TTY_ISTRIP:
			setTermiosFlag(&t.Iflag, unix.ISTRIP, v)
		case TTY_INLCR:
			setTermiosFlag(&t.Iflag, unix.INLCR, v)
		case TTY_IGNCR:
			setTermiosFlag(&t.Iflag, unix.IGNCR, v)
		case TTY_ICRNL:
			setTermiosFlag(&t.Iflag, unix.ICRNL, v)
		case TTY_IXON:
			setTermiosFlag(&t.Iflag, unix.IXON, v)
		case TTY_IXANY:
			setTermiosFlag(&t.Iflag, unix.IXANY, v)
		case TTY_IXOFF:
			setTermiosFlag(&t.Iflag, unix.IXOFF, v)

		// Local flags (c_lflag)
		case TTY_ISIG:
			setTermiosFlag(&t.Lflag, unix.ISIG, v)
		case TTY_ICANON:
			setTermiosFlag(&t.Lflag, unix.ICANON, v)
		case TTY_ECHO:
			setTermiosFlag(&t.Lflag, unix.ECHO, v)
		case TTY_ECHOE:
			setTermiosFlag(&t.Lflag, unix.ECHOE, v)
		case TTY_ECHOK:
			setTermiosFlag(&t.Lflag, unix.ECHOK, v)
		case TTY_ECHONL:
			setTermiosFlag(&t.Lflag, unix.ECHONL, v)
		case TTY_NOFLSH:
			setTermiosFlag(&t.Lflag, unix.NOFLSH, v)
		case TTY_TOSTOP:
			setTermiosFlag(&t.Lflag, unix.TOSTOP, v)
		case TTY_IEXTEN:
			setTermiosFlag(&t.Lflag, unix.IEXTEN, v)

		// Output flags (c_oflag)
		case TTY_OPOST:
			setTermiosFlag(&t.Oflag, unix.OPOST, v)
		case TTY_ONLCR:
			setTermiosFlag(&t.Oflag, unix.ONLCR, v)
		case TTY_OCRNL:
			setTermiosFlag(&t.Oflag, unix.OCRNL, v)
		case TTY_ONOCR:
			setTermiosFlag(&t.Oflag, unix.ONOCR, v)
		case TTY_ONLRET:
			setTermiosFlag(&t.Oflag, unix.ONLRET, v)

		// Control flags (c_cflag)
		case TTY_CS7:
			setTermiosFlag(&t.Cflag, unix.CS7, v)
		case TTY_CS8:
			setTermiosFlag(&t.Cflag, unix.CS8, v)
		case TTY_PARENB:
			setTermiosFlag(&t.Cflag, unix.PARENB, v)
		case TTY_PARODD:
			setTermiosFlag(&t.Cflag, unix.PARODD, v)
		}
	}
}

// Generic to accommondate all (?) unix platforms.
func setTermiosFlag[T ~uint32 | ~uint64](flagField *T, flag T, value uint32) {
	if value != 0 {
		*flagField |= flag
	} else {
		*flagField &= ^flag
	}
}
