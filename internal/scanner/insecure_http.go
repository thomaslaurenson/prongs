package scanner

import (
	"context"
	"net"
	"net/http"
	"net/url"

	"github.com/thomaslaurenson/prongs/internal/config"
)

// httpPort is the single plaintext HTTP port probed. Kept as a named constant so
// a later expansion to other plaintext ports (8080, 8000) is a small change.
const httpPort = 80

// InsecureHTTP detects a website served over plaintext HTTP on port 80.
//
// It sends GET / to port 80 without following redirects and classifies the first
// response:
//
//   - TCP closed, or the reply is not parseable HTTP: not a finding (nothing is
//     listening, or a non-HTTP service occupies the port).
//   - 3xx redirect to an absolute https:// URL: not a finding. Redirecting
//     cleartext to HTTPS is the recommended configuration.
//   - 3xx redirect to http://, a relative path, or a scheme-relative //host:
//     a finding. The server redirects but keeps the client on plaintext.
//   - 2xx: a finding. The site serves content over plaintext HTTP.
//   - 401: a finding. A cleartext auth prompt carries credentials in the clear.
//   - any other 4xx or 5xx: not a finding. An error stub is not proof the site is
//     served over HTTP, and flagging it only adds noise.
//
// Scanning is by IP, so the request carries Host: <ip>. Name-based virtual hosts
// may therefore serve a default site rather than their real redirect behaviour;
// this is an inherent limitation of IP-based scanning.
type InsecureHTTP struct{}

var _ Scanner = (*InsecureHTTP)(nil)

func (s *InsecureHTTP) Name() string         { return "insecure-http" }
func (s *InsecureHTTP) DefaultEnabled() bool { return true }

func (s *InsecureHTTP) Run(ctx context.Context, ip net.IP) (Result, bool) {
	return s.probe(ctx, ip, "http://"+addr(ip, httpPort)+"/")
}

// probe issues GET rawURL and, on a plaintext finding, returns a Result for ip.
func (s *InsecureHTTP) probe(ctx context.Context, ip net.IP, rawURL string) (Result, bool) {
	// A deadline as well as the cancel: a server that accepts the connection and
	// then trickles bytes is not an interrupted request, and only the deadline
	// ends it.
	ctx, cancel := context.WithTimeout(ctx, config.DefaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Result{}, false
	}

	client := &http.Client{
		// No Client.Timeout: the context deadline above already bounds the whole
		// exchange, including reading the body.
		//
		// Do not follow redirects: we classify the first response ourselves so an
		// https redirect (clean) is distinguished from one that stays on plaintext.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{DisableKeepAlives: true},
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, false
	}
	defer func() { _ = resp.Body.Close() }()

	if !servedOverPlaintext(resp) {
		return Result{}, false
	}
	return finding(s, ip, httpPort), true
}

// servedOverPlaintext reports whether resp indicates the site is served over
// plaintext HTTP. See the InsecureHTTP doc comment for the full rule table.
func servedOverPlaintext(resp *http.Response) bool {
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// Clean only when the redirect target is an absolute https URL. A relative,
		// scheme-relative, http, missing, or unparseable Location keeps plaintext.
		u, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			return true
		}
		return u.Scheme != "https"
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true
	case resp.StatusCode == http.StatusUnauthorized:
		return true
	default:
		return false
	}
}
