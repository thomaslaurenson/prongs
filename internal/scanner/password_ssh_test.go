package scanner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestMethodInError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		errStr string
		method string
		want   bool
	}{
		{
			name:   "method present",
			errStr: "ssh: unable to authenticate, attempted methods [none password], no supported methods remain",
			method: "password",
			want:   true,
		},
		{
			name:   "method absent",
			errStr: "ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain",
			method: "password",
			want:   false,
		},
		{
			name:   "no brackets",
			errStr: "connection refused",
			method: "password",
			want:   false,
		},
		{
			name:   "empty string",
			errStr: "",
			method: "password",
			want:   false,
		},
		{
			name:   "partial match does not count",
			errStr: "ssh: attempted methods [none passwordless], no match",
			method: "password",
			want:   false,
		},
		{
			name:   "multiple bracket groups",
			errStr: "attempted methods [none] then [password publickey]",
			method: "password",
			want:   true,
		},
		{
			name:   "trailing comma stripped",
			errStr: "ssh: attempted methods [none, password,], no match",
			method: "password",
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := methodInError(tt.errStr, tt.method)
			if got != tt.want {
				t.Errorf("methodInError(%q, %q) = %v, want %v", tt.errStr, tt.method, got, tt.want)
			}
		})
	}
}

// sshServer starts an SSH server on loopback with the given auth callbacks set
// and returns its address. Which callbacks are non-nil is what decides the auth
// methods the server advertises, which is exactly what the probe reads back.
func sshServer(t *testing.T, cfg *ssh.ServerConfig) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // the listener was closed by the cleanup above
			}
			go serve(conn, cfg)
		}
	}()
	return ln.Addr().String()
}

// serve completes one server-side handshake and then shuts the connection down.
// A successful handshake has to service both channels or the transport blocks,
// which is the same obligation the client side carries.
func serve(conn net.Conn, cfg *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()

	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return // an auth failure, which is what most of these cases expect
	}
	defer func() { _ = sc.Close() }()

	go ssh.DiscardRequests(reqs)

	// Send the client a global request, as a real server does. This is what the
	// client has to service: a client that discarded its request channel would
	// leave its transport goroutine blocked on delivering this.
	go func() { _, _, _ = sc.SendRequest("keepalive@openssh.com", true, nil) }()

	for nc := range chans {
		_ = nc.Reject(ssh.Prohibited, "this server serves no channels")
	}
}

func TestPasswordSSHProbe(t *testing.T) {
	t.Parallel()
	denied := errors.New("denied")

	tests := []struct {
		name string
		cfg  *ssh.ServerConfig
		want bool
	}{
		{
			name: "server offers password and rejects it",
			cfg: &ssh.ServerConfig{
				PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
					return nil, denied
				},
			},
			want: true,
		},
		{
			name: "server accepts the empty password",
			cfg: &ssh.ServerConfig{
				PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
					if len(pw) == 0 {
						return &ssh.Permissions{}, nil
					}
					return nil, denied
				},
			},
			want: true,
		},
		{
			name: "server offers publickey only",
			cfg: &ssh.ServerConfig{
				PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
					return nil, denied
				},
			},
			want: false,
		},
		{
			name: "server offers keyboard-interactive only",
			cfg: &ssh.ServerConfig{
				KeyboardInteractiveCallback: func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
					return nil, denied
				},
			},
			want: false,
		},
	}

	s := &PasswordSSH{}
	ip := net.ParseIP("192.0.2.10")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			target := sshServer(t, tc.cfg)

			res, found := s.probe(context.Background(), ip, target)
			if found != tc.want {
				t.Fatalf("probe found = %v, want %v", found, tc.want)
			}
			if !found {
				return
			}
			// The Result describes the scanned host, not the address the test
			// dialled, so it always names port 22.
			if res.Port != sshPort {
				t.Errorf("Port = %d, want %d", res.Port, sshPort)
			}
			if res.ScanType != s.Name() {
				t.Errorf("ScanType = %q, want %q", res.ScanType, s.Name())
			}
			if !res.IP.Equal(ip) {
				t.Errorf("IP = %v, want %v", res.IP, ip)
			}
		})
	}
}

func TestPasswordSSHProbeNonSSHService(t *testing.T) {
	t.Parallel()
	// A port that answers but speaks no SSH must not be reported: the handshake
	// fails with an error that carries no method list at all.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		_ = conn.Close()
	}()

	s := &PasswordSSH{}
	if _, found := s.probe(context.Background(), net.ParseIP("192.0.2.10"), ln.Addr().String()); found {
		t.Error("probe against a non-SSH service reported a finding")
	}
}
