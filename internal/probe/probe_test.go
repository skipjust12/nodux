package probe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
)

func TestProber_HTTP(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "nodux" {
			t.Errorf("user agent = %q", r.Header.Get("User-Agent"))
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()

	p := New(Config{Failures: 2, Targets: []Target{
		{Name: "api", URL: srv.URL + "/health?token=s3cret", Container: "api"},
		{Name: "strict", URL: srv.URL + "/", Status: []int{204}},
	}})

	issues := p.Check()
	if len(issues) != 0 {
		t.Fatalf("strict should need 2 failures: %+v", issues)
	}
	issues = p.Check()
	if len(issues) != 1 || issues[0].Resource != "strict" || !strings.Contains(issues[0].Message, "status 200 OK (2 checks in a row)") {
		t.Fatalf("got %+v", issues)
	}

	status.Store(503)
	p.Check()
	issues = p.Check()
	if len(issues) != 2 {
		t.Fatalf("got %+v", issues)
	}
	api := issues[0]
	if api.Severity != detector.SeverityCritical || api.Container.Name != "api" ||
		!strings.Contains(api.Message, "GET "+srv.URL+"/health: status 503") {
		t.Errorf("api: %+v", api)
	}
	if strings.Contains(api.Message, "s3cret") {
		t.Errorf("query string leaked: %q", api.Message)
	}

	// Redirects aren't followed: a 302 is "up" unless status says otherwise.
	status.Store(302)
	if issues := p.Check(); len(issues) != 1 || issues[0].Resource != "strict" {
		t.Fatalf("got %+v", issues)
	}
}

func TestProber_TCPAndTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	open := ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	defer ln.Close()

	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := closed.Addr().String()
	closed.Close()

	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer hang.Close()

	p := New(Config{Timeout: 100 * time.Millisecond, Targets: []Target{
		{Name: "open", TCP: open},
		{Name: "closed", TCP: closedAddr},
		{Name: "hang", URL: hang.URL},
	}})
	issues := p.Check()
	if len(issues) != 2 {
		t.Fatalf("got %+v", issues)
	}
	if issues[0].Resource != "closed" || !strings.Contains(issues[0].Message, "TCP connect to "+closedAddr) {
		t.Errorf("closed: %+v", issues[0])
	}
	if issues[1].Resource != "hang" || !strings.HasSuffix(issues[1].Message, ": timed out") {
		t.Errorf("hang: %+v", issues[1])
	}
}

// pki is a throwaway CA for test certificates.
type pki struct {
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
	roots *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &pki{ca, key, roots}
}

func (p *pki) serve(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "svc.test"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestProber_TLSAndCertExpiry(t *testing.T) {
	ca := newPKI(t)
	now := time.Now()
	soon := ca.serve(t, now.Add(10*24*time.Hour))
	expired := ca.serve(t, now.Add(-24*time.Hour))
	fine := ca.serve(t, now.Add(90*24*time.Hour))

	p := New(Config{Targets: []Target{
		{Name: "soon", TLS: soon},
		{Name: "expired", TLS: expired},
		{Name: "fine", TLS: strings.Replace(fine, "127.0.0.1", "localhost", 1)},
	}})
	p.roots = ca.roots

	issues := p.Check()
	byName := map[string]*detector.Issue{}
	for _, i := range issues {
		byName[i.Resource] = i
	}
	if len(issues) != 1 || byName["expired"] == nil || !strings.Contains(byName["expired"].Message, "certificate not valid: certificate has expired") {
		t.Fatalf("got %+v", issues)
	}

	certs := NewCertDetector(p, 14*24*time.Hour, 3*24*time.Hour)
	got := map[string]*detector.Issue{}
	for _, i := range certs.Check() {
		got[i.Resource] = i
	}
	if len(got) != 2 {
		t.Fatalf("cert issues: %+v", got)
	}
	if s := got["soon"]; s.Severity != detector.SeverityWarning || !strings.Contains(s.Message, "certificate svc.test expires in 9 days") ||
		!strings.Contains(s.Message, "issued by Test CA") {
		t.Errorf("soon: %+v", s)
	}
	if e := got["expired"]; e.Severity != detector.SeverityCritical || !strings.Contains(e.Message, "expired 1 day ago") {
		t.Errorf("expired: %+v", e)
	}

	// Two days later "soon" is within the critical window.
	certs.now = func() time.Time { return now.Add(8 * 24 * time.Hour) }
	for _, i := range certs.Check() {
		if i.Resource == "soon" && i.Severity != detector.SeverityCritical {
			t.Errorf("soon should be critical now: %+v", i)
		}
	}
}

func TestProber_SkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	p := New(Config{Targets: []Target{
		{Name: "strict", URL: srv.URL},
		{Name: "lax", URL: srv.URL, SkipVerify: true},
	}})
	issues := p.Check()
	if len(issues) != 1 || issues[0].Resource != "strict" || !strings.Contains(issues[0].Message, "certificate not valid") {
		t.Fatalf("got %+v", issues)
	}
	if len(p.Certs()) != 2 {
		t.Fatalf("certificates should be recorded even when verification fails: %+v", p.Certs())
	}
}
