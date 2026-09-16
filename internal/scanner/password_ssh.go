package scanner

import (
	"context"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/thomaslaurenson/prongs/internal/config"
)

// sshPort is the TCP port the SSH probe targets.
const sshPort = 22

// probeUser is the username offered to the server. It is deliberately one no
// real account would use, so a server that does accept the empty password
// cannot be one this probe happened to guess a real account on.
const probeUser = "cats_are_mythical"

// PasswordSSH reports whether an SSH server has password authentication
// enabled. It does not attempt to guess a password: it offers one empty
// password and reads back which methods the server was willing to try.
type PasswordSSH struct{}

var _ Scanner = (*PasswordSSH)(nil)

func (s *PasswordSSH) Name() string         { return "password-ssh" }
func (s *PasswordSSH) DefaultEnabled() bool { return true }

func (s *PasswordSSH) Run(ctx context.Context, ip net.IP) (Result, bool) {
	return s.probe(ctx, ip, addr(ip, sshPort))
}

// probe handshakes with the SSH server at target and, on a finding, returns a
// Result for ip. Run supplies ip:22; a test supplies a local server's address.
func (s *PasswordSSH) probe(ctx context.Context, ip net.IP, target string) (Result, bool) {
	d := net.Dialer{Timeout: config.DefaultTimeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return Result{}, false
	}
	defer func() { _ = conn.Close() }()

	// x/crypto/ssh sends a "none" auth request first (RFC 4252 section 5.2) to
	// learn the server's supported method list, then tries only the methods
	// supplied here that appear in it. The error therefore reports what was
	// actually attempted:
	//
	//   "ssh: unable to authenticate, attempted methods [none password], ..."
	//
	// "password" in that list means the server offered it. A server without
	// password auth never has it tried, so the word is absent.
	cfg := &ssh.ClientConfig{
		User:            probeUser,
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // a scanner has no host key to trust
	}

	// ClientConfig.Timeout only bounds the dial, which has already happened, so
	// the handshake needs a deadline of its own. Without it a host that accepts
	// the connection and then says nothing holds a worker for the whole scan.
	if err := conn.SetDeadline(time.Now().Add(config.DefaultTimeout)); err != nil {
		return Result{}, false
	}

	// Hand the dialled connection to NewClientConn rather than calling ssh.Dial,
	// which dials for itself and so has no way to take the context.
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, target, cfg)
	if err == nil {
		// The empty password was accepted, which is a finding in its own right.
		// Wrap the connection in a Client before closing it, exactly as ssh.Dial
		// does: NewClientConn documents that its channel and request channels
		// must be serviced or the connection hangs, and NewClient is what
		// services them. Discarding the two channels here would leave the
		// transport goroutine blocked on a send the moment a server opened a
		// channel or sent a global request.
		_ = ssh.NewClient(sshConn, chans, reqs).Close()
		return finding(s, ip, sshPort), true
	}

	if methodInError(err.Error(), "password") {
		return finding(s, ip, sshPort), true
	}
	return Result{}, false
}

// methodInError reports whether method appears in a bracket-delimited method
// list in an x/crypto/ssh error string, as in "attempted methods [none
// password], no supported methods remain". Match inside the brackets rather
// than grepping the whole string, which would also hit the word "password" in
// unrelated messages.
func methodInError(errStr, method string) bool {
	inBracket := false
	start := 0
	for i, c := range errStr {
		switch c {
		case '[':
			inBracket = true
			start = i + 1
		case ']':
			if inBracket {
				for _, m := range strings.Fields(errStr[start:i]) {
					if strings.TrimRight(m, ",") == method {
						return true
					}
				}
			}
			inBracket = false
		}
	}
	return false
}
