package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"

	"golang.org/x/crypto/ssh"
)

func generateSigner() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func parsePtyRequest(s []byte) (pty Pty, ok bool) {
	term, s, ok := parseString(s)
	if !ok {
		return
	}
	width32, s, ok := parseUint32(s)
	if !ok {
		return
	}
	height32, s, ok := parseUint32(s)
	if !ok {
		return
	}
	xpixels32, s, ok := parseUint32(s)
	if !ok {
		return
	}
	ypixels32, s, ok := parseUint32(s)
	if !ok {
		return
	}
	opsStr, _, ok := parseString(s)
	if !ok {
		return
	}
	ops, ok := parseOps([]byte(opsStr))
	if !ok {
		return
	}
	pty = Pty{
		Term: term,
		Window: Window{
			Width:   int(width32),
			Height:  int(height32),
			XPixels: int(xpixels32),
			YPixels: int(ypixels32),
		},
		Termios: ops,
	}
	return
}

func parseWinchRequest(s []byte) (win Window, ok bool) {
	width32, s, ok := parseUint32(s)
	if width32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if height32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	xpixels32, _, ok := parseUint32(s)
	if !ok {
		return
	}
	ypixels32, _, ok := parseUint32(s)
	if !ok {
		return
	}
	win = Window{
		Width:   int(width32),
		Height:  int(height32),
		XPixels: int(xpixels32),
		YPixels: int(ypixels32),
	}
	return
}

func parseString(in []byte) (out string, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = string(in[4 : 4+length])
	rest = in[4+length:]
	ok = true
	return
}

func parseOps(in []byte) (map[int]uint32, bool) {
	out := make(map[int]uint32)
	for {
		var opcode uint8
		var ok bool

		opcode, in, ok = parseUint8(in)
		if !ok {
			return nil, false
		}

		switch {
		case opcode == TTY_OP_END:
			if len(in) != 0 {
				// Unexpected data after TTY_OP_END
				return nil, false
			}
			return out, true

		case opcode >= 1 && opcode <= 159: // operand is uint32 per RFC4254
			var value uint32
			value, in, ok = parseUint32(in)
			if !ok {
				return nil, false
			}

			out[int(opcode)] = value

		default:
			// Opcodes >159 are not defined (and we don't know the operand length).
			return nil, false
		}
	}
}

func parseUint8(in []byte) (uint8, []byte, bool) {
	if len(in) < 1 {
		return 0, nil, false
	}
	return in[0], in[1:], true
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

// SSH TTY mode opcodes as defined in RFC 4254, section 8.
const (
	// Special opcodes
	TTY_OP_END    = 0   // Indicates end of options
	TTY_OP_ISPEED = 128 // Input speed (followed by uint32)
	TTY_OP_OSPEED = 129 // Output speed (followed by uint32)

	// Character opcodes (TTYCHAR)
	TTY_VINTR    = 1  // Interrupt character
	TTY_VQUIT    = 2  // Quit character
	TTY_VERASE   = 3  // Erase character
	TTY_VKILL    = 4  // Kill character
	TTY_VEOF     = 5  // End-of-file character
	TTY_VEOL     = 6  // End-of-line character
	TTY_VEOL2    = 7  // Second end-of-line character
	TTY_VSTART   = 8  // Start character
	TTY_VSTOP    = 9  // Stop character
	TTY_VSUSP    = 10 // Suspend character
	TTY_VDSUSP   = 11 // Delayed suspend character
	TTY_VREPRINT = 12 // Reprint character
	TTY_VWERASE  = 13 // Word erase character
	TTY_VLNEXT   = 14 // Literal next character
	TTY_VFLUSH   = 15 // Flush character
	TTY_VSWTCH   = 16 // Switch character
	TTY_VSTATUS  = 17 // Status character
	TTY_VDISCARD = 18 // Discard character

	// Input flags (c_iflag)
	TTY_IGNPAR  = 30 // Ignore parity errors
	TTY_PARMRK  = 31 // Mark parity errors
	TTY_INPCK   = 32 // Enable parity check
	TTY_ISTRIP  = 33 // Strip 8th bit off characters
	TTY_INLCR   = 34 // Translate NL to CR on input
	TTY_IGNCR   = 35 // Ignore CR on input
	TTY_ICRNL   = 36 // Translate CR to NL on input
	TTY_IUCLC   = 37 // Map uppercase to lowercase on input
	TTY_IXON    = 38 // Enable start/stop output control
	TTY_IXANY   = 39 // Allow any character to restart output
	TTY_IXOFF   = 40 // Enable start/stop input control
	TTY_IMAXBEL = 41 // Ring bell when input queue is full
	TTY_IUTF8   = 42 // Input is UTF8

	// Local flags (c_lflag)
	TTY_ISIG    = 50 // Enable signals
	TTY_ICANON  = 51 // Canonical input (erase and kill processing)
	TTY_XCASE   = 52 // Canonical upper/lower presentation
	TTY_ECHO    = 53 // Enable echo
	TTY_ECHOE   = 54 // Echo erase character as BS-SP-BS
	TTY_ECHOK   = 55 // Echo NL after kill character
	TTY_ECHONL  = 56 // Echo NL
	TTY_NOFLSH  = 57 // Disable flush after interrupt or quit
	TTY_TOSTOP  = 58 // Stop background jobs that try to write to terminal
	TTY_IEXTEN  = 59 // Enable extended input character processing
	TTY_ECHOCTL = 60 // Echo control characters as ^X
	TTY_ECHOKE  = 61 // Echo kill character in special way
	TTY_PENDIN  = 62 // Retype pending input at next read or input char

	// Output flags (c_oflag)
	TTY_OPOST  = 70 // Post-process output
	TTY_OLCUC  = 71 // Map lowercase to uppercase on output
	TTY_ONLCR  = 72 // Map NL to CR-NL on output
	TTY_OCRNL  = 73 // Map CR to NL on output
	TTY_ONOCR  = 74 // Don't output CR at column 0
	TTY_ONLRET = 75 // Don't output CR

	// Control flags (c_cflag)
	TTY_CS7    = 90 // 7 bit character size
	TTY_CS8    = 91 // 8 bit character size
	TTY_PARENB = 92 // Enable parity generation and detection
	TTY_PARODD = 93 // Use odd parity instead of even
)
