package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServedOverPlaintext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		status   int
		location string
		want     bool
	}{
		{name: "200 serves content", status: 200, want: true},
		{name: "204 no content is still plaintext", status: 204, want: true},
		{name: "301 to https is clean", status: 301, location: "https://example.com/", want: false},
		{name: "302 to https is clean", status: 302, location: "https://example.com/", want: false},
		{name: "308 to uppercase https is clean", status: 308, location: "HTTPS://example.com/", want: false},
		{name: "301 to http stays plaintext", status: 301, location: "http://example.com/", want: true},
		{name: "302 relative path stays plaintext", status: 302, location: "/login", want: true},
		{name: "302 scheme-relative stays plaintext", status: 302, location: "//example.com/", want: true},
		{name: "302 missing location", status: 302, location: "", want: true},
		{name: "302 unparseable location", status: 302, location: "http://a:b", want: true},
		{name: "401 cleartext auth prompt", status: 401, want: true},
		{name: "403 forbidden ignored", status: 403, want: false},
		{name: "404 not found ignored", status: 404, want: false},
		{name: "500 error ignored", status: 500, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := &http.Response{StatusCode: tc.status, Header: make(http.Header)}
			if tc.location != "" {
				resp.Header.Set("Location", tc.location)
			}
			if got := servedOverPlaintext(resp); got != tc.want {
				t.Errorf("servedOverPlaintext(status=%d, location=%q) = %v, want %v",
					tc.status, tc.location, got, tc.want)
			}
		})
	}
}

func TestInsecureHTTPProbe(t *testing.T) {
	t.Parallel()

	// A TLS server used only as an https redirect target. The scanner must not
	// follow the redirect, so this server is never actually contacted.
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsServer.Close()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    bool
	}{
		{
			name:    "serves content over http",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
			want:    true,
		},
		{
			name: "redirects to https",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tlsServer.URL, http.StatusMovedPermanently)
			},
			want: false,
		},
		{
			name: "redirects to another http url",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "http://example.com/", http.StatusFound)
			},
			want: true,
		},
		{
			name: "cleartext auth prompt",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
				w.WriteHeader(http.StatusUnauthorized)
			},
			want: true,
		},
		{
			name:    "not found is ignored",
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) },
			want:    false,
		},
	}

	s := &InsecureHTTP{}
	ip := net.ParseIP("192.0.2.10")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(tc.handler)
			defer server.Close()

			res, found := s.probe(context.Background(), ip, server.URL+"/")
			if found != tc.want {
				t.Fatalf("probe found = %v, want %v", found, tc.want)
			}
			if found {
				if res.ScanType != "insecure-http" {
					t.Errorf("ScanType = %q, want insecure-http", res.ScanType)
				}
				if res.Port != httpPort {
					t.Errorf("Port = %d, want %d", res.Port, httpPort)
				}
				if !res.IP.Equal(ip) {
					t.Errorf("IP = %v, want %v", res.IP, ip)
				}
			}
		})
	}
}

func TestInsecureHTTPProbeConnectionRefused(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL + "/"
	server.Close() // close so the connection is refused

	s := &InsecureHTTP{}
	if _, found := s.probe(context.Background(), net.ParseIP("192.0.2.10"), url); found {
		t.Errorf("probe to closed server = found, want not found")
	}
}

func TestInsecureHTTPRunNoServer(t *testing.T) {
	t.Parallel()
	// Nothing is expected on loopback port 80 in the test environment, so Run
	// exercises the request path and returns no finding.
	s := &InsecureHTTP{}
	if _, found := s.Run(context.Background(), net.ParseIP("127.0.0.1")); found {
		t.Errorf("Run against loopback:80 = found, want not found")
	}
}
