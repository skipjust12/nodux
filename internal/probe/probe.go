// Package probe checks that services answer from the outside: an HTTP
// request, a TCP connect or a TLS handshake. For a container without a
// HEALTHCHECK that's the only way to know the service actually works,
// and the TLS side also tracks certificate expiry, one of the most
// common ways a small server goes down.
//
// A Prober is a detector.HostDetector ("probe"); CertDetector
// ("tls_cert") reads the certificates the prober saw. The engine runs
// both on their own loop.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

// Target is one thing to probe. Exactly one of URL, TCP and TLS is set.
type Target struct {
	Name string
	// URL is an http(s) URL to GET. Redirects aren't followed.
	URL string
	// TCP is a host:port to connect to.
	TCP string
	// TLS is a host:port to complete a TLS handshake with (verifying the
	// certificate), for TLS services that don't speak HTTP.
	TLS string
	// Container ties the probe to a container by name: its alerts carry
	// that container's state and logs.
	Container string
	// Status lists the HTTP statuses that count as up; empty = 200-399.
	Status []int
	// SkipVerify accepts any certificate (self-signed internal services).
	// Expiry is still tracked.
	SkipVerify bool
}

type Config struct {
	Targets []Target
	Timeout time.Duration
	// Failures is how many checks in a row must fail before it's a
	// problem, so a single dropped connection doesn't page anyone.
	Failures int
}

// Prober runs the checks. Each Check probes every target concurrently.
type Prober struct {
	cfg Config

	mu    sync.Mutex
	state map[string]*targetState
	now   func() time.Time
	roots *x509.CertPool // nil = the system's; set by tests
}

type targetState struct {
	failures int
	lastErr  string
	cert     *CertInfo // last certificate seen, kept while the target is down
}

// CertInfo is the certificate in a target's chain that expires first.
type CertInfo struct {
	Target   string    `json:"target"`
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	// Leaf is false when the first to expire is an intermediate.
	Leaf bool `json:"leaf"`
}

func New(cfg Config) *Prober {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Failures <= 0 {
		cfg.Failures = 1
	}
	p := &Prober{cfg: cfg, state: make(map[string]*targetState), now: time.Now}
	for _, t := range cfg.Targets {
		p.state[t.Name] = &targetState{}
	}
	return p
}

func (p *Prober) Name() string { return "probe" }

func (p *Prober) Check() []*detector.Issue {
	type result struct {
		err  error
		cert *CertInfo
	}
	results := make([]result, len(p.cfg.Targets))
	var wg sync.WaitGroup
	for i, t := range p.cfg.Targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), p.cfg.Timeout)
			defer cancel()
			cert, err := p.probe(ctx, t)
			results[i] = result{err, cert}
		}()
	}
	wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()
	var issues []*detector.Issue
	for i, t := range p.cfg.Targets {
		st, r := p.state[t.Name], results[i]
		if r.cert != nil {
			st.cert = r.cert
		}
		if r.err == nil {
			st.failures, st.lastErr = 0, ""
			continue
		}
		st.failures++
		st.lastErr = r.err.Error()
		if st.failures < p.cfg.Failures {
			continue
		}
		msg := fmt.Sprintf("%s: %s", describe(t), st.lastErr)
		if p.cfg.Failures > 1 {
			msg += fmt.Sprintf(" (%d checks in a row)", p.cfg.Failures)
		}
		issues = append(issues, &detector.Issue{
			Detector:   p.Name(),
			Severity:   detector.SeverityCritical,
			Message:    msg,
			Resource:   t.Name,
			Container:  detector.ContainerSnapshot{Name: t.Container},
			DetectedAt: p.now(),
		})
	}
	return issues
}

// Certs returns the latest certificate info per target that has one.
func (p *Prober) Certs() []CertInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []CertInfo
	for _, t := range p.cfg.Targets {
		if c := p.state[t.Name].cert; c != nil {
			out = append(out, *c)
		}
	}
	return out
}

func (p *Prober) probe(ctx context.Context, t Target) (*CertInfo, error) {
	var cert *CertInfo
	record := func(info *CertInfo) {
		info.Target = t.Name
		cert = info
	}
	var err error
	switch {
	case t.URL != "":
		err = p.probeHTTP(ctx, t, record)
	case t.TCP != "":
		var d net.Dialer
		var conn net.Conn
		if conn, err = d.DialContext(ctx, "tcp", t.TCP); err == nil {
			conn.Close()
		}
	case t.TLS != "":
		host, _, splitErr := net.SplitHostPort(t.TLS)
		if splitErr != nil {
			return nil, splitErr
		}
		d := tls.Dialer{Config: p.tlsConfig(host, t.SkipVerify, record)}
		var conn net.Conn
		if conn, err = d.DialContext(ctx, "tcp", t.TLS); err == nil {
			conn.Close()
		}
	default:
		err = errors.New("nothing to probe")
	}
	return cert, cleanErr(err)
}

func (p *Prober) probeHTTP(ctx context.Context, t Target, record func(*CertInfo)) error {
	u, err := url.Parse(t.URL)
	if err != nil {
		return err
	}
	client := &http.Client{
		Transport: &http.Transport{
			// Probes check direct reachability, not a proxy's.
			Proxy:             nil,
			TLSClientConfig:   p.tlsConfig(u.Hostname(), t.SkipVerify, record),
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "nodux")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	ok := resp.StatusCode >= 200 && resp.StatusCode < 400
	if len(t.Status) > 0 {
		ok = slices.Contains(t.Status, resp.StatusCode)
	}
	if !ok {
		return fmt.Errorf("status %s", resp.Status)
	}
	return nil
}

// tlsConfig verifies the certificate itself rather than through
// crypto/tls, so the chain is recorded even when verification fails (an
// expired certificate is exactly the case worth reporting on).
func (p *Prober) tlsConfig(serverName string, skipVerify bool, record func(*CertInfo)) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // verified in VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			certs := cs.PeerCertificates
			if len(certs) == 0 {
				return errors.New("server sent no certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range certs[1:] {
				inter.AddCert(c)
			}
			chains, err := certs[0].Verify(x509.VerifyOptions{
				DNSName:       cs.ServerName,
				Intermediates: inter,
				Roots:         p.roots,
				CurrentTime:   p.now(),
			})
			record(firstToExpire(certs, chains))
			if skipVerify {
				return nil
			}
			return err
		},
	}
}

// firstToExpire picks the certificate that will break the connection
// first. With a verified chain that's the earliest expiry in the best
// chain, root excluded: servers sometimes send extra, already-expired
// cross-signs that clients never use. Without one it's the leaf.
func firstToExpire(certs []*x509.Certificate, chains [][]*x509.Certificate) *CertInfo {
	pick := certs[0]
	var best time.Time
	for _, chain := range chains {
		var first *x509.Certificate
		for i, c := range chain {
			if i == len(chain)-1 && len(chain) > 1 {
				break // the trust anchor
			}
			if first == nil || c.NotAfter.Before(first.NotAfter) {
				first = c
			}
		}
		if first != nil && first.NotAfter.After(best) {
			best, pick = first.NotAfter, first
		}
	}
	return &CertInfo{
		Subject:  certName(pick),
		Issuer:   pick.Issuer.CommonName,
		NotAfter: pick.NotAfter,
		Leaf:     pick == certs[0],
	}
}

func certName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.DNSNames) > 0 {
		return c.DNSNames[0]
	}
	return c.Subject.String()
}

// describe names what was probed without credentials or query strings,
// which can carry tokens.
func describe(t Target) string {
	switch {
	case t.URL != "":
		return "GET " + DisplayURL(t.URL)
	case t.TCP != "":
		return "TCP connect to " + t.TCP
	default:
		return "TLS handshake with " + t.TLS
	}
}

// DisplayURL is scheme://host/path: no userinfo, no query.
func DisplayURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(invalid URL)"
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath()
}

// cleanErr strips the URL from net/http errors (describe already says
// what was probed, without secrets) and makes timeouts readable.
func cleanErr(err error) error {
	if err == nil {
		return nil
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return errors.New("timed out")
	}
	msg := strings.TrimPrefix(err.Error(), "tls: ")
	if rest, ok := strings.CutPrefix(msg, "x509: "); ok {
		msg = "certificate not valid: " + rest
	}
	return errors.New(msg)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

type savedTarget struct {
	Failures int       `json:"failures,omitempty"`
	LastErr  string    `json:"last_err,omitempty"`
	Cert     *CertInfo `json:"cert,omitempty"`
}

// SaveState keeps each target's failure streak and last certificate, so
// a restart neither resolves a failing probe nor forgets an expiring
// certificate of a target that's down.
func (p *Prober) SaveState() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]savedTarget, len(p.state))
	for name, st := range p.state {
		if st.failures > 0 || st.cert != nil {
			out[name] = savedTarget{Failures: st.failures, LastErr: st.lastErr, Cert: st.cert}
		}
	}
	return json.Marshal(out)
}

func (p *Prober) LoadState(data []byte) error {
	var in map[string]savedTarget
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, sv := range in {
		if st, ok := p.state[name]; ok { // targets removed from the config are dropped
			st.failures, st.lastErr, st.cert = sv.Failures, sv.LastErr, sv.Cert
		}
	}
	return nil
}
