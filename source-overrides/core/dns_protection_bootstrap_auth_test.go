package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/dns"
	D "github.com/miekg/dns"
)

func namedBootstrapServer(t *testing.T) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"resolver.example.test"},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if r.Method == http.MethodGet {
			body, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		}
		request := new(D.Msg)
		if err != nil || request.Unpack(body) != nil {
			t.Error("invalid DoH request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		answer := new(D.Msg).SetReply(request)
		wire, err := answer.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, certificate
}

func TestBootstrapNamedCertificateStillRequiresTrustedChainAndExactName(t *testing.T) {
	server, certificate := namedBootstrapServer(t)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	for _, test := range []struct {
		name            string
		certificateName string
		roots           *x509.CertPool
		want            string
	}{
		{"literal IP without override", "", roots, "DP_TLS_CERTIFICATE"},
		{"authenticated name", "resolver.example.test", roots, ""},
		{"wrong name", "other.example.test", roots, "DP_TLS_CERTIFICATE"},
		{"untrusted chain", "resolver.example.test", x509.NewCertPool(), "DP_TLS_CERTIFICATE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint := preflightServer(server.URL + "/dns-query")
			if test.certificateName != "" {
				endpoint.Params["name-cert-verify"] = test.certificateName
			}
			result := probeBootstrapServer(context.Background(), endpoint, test.roots)
			if result.ErrorCode != test.want {
				t.Fatalf("got %+v, want error %q", result, test.want)
			}
			if test.want == "" {
				if result.Result != "success" || result.Stage != "complete" {
					t.Fatalf("authenticated response did not finish: %+v", result)
				}
			} else if result.Stage != "tls_handshake" || result.ErrorCategory != "tls" {
				t.Fatalf("TLS failure was not diagnosed: %+v", result)
			}
		})
	}
}

func TestMihomoUsesTheSameNamedCertificateForLiteralIPBootstrap(t *testing.T) {
	server, certificate := namedBootstrapServer(t)
	if err := ca.AddCertificate(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.ResetCertificate)
	endpoint := preflightServer(server.URL + "/dns-query")
	endpoint.Params["name-cert-verify"] = "resolver.example.test"
	endpoint.ProxyAdapter = outbound.NewDirect()
	resolvers := dns.NewResolver(dns.Config{Main: []dns.NameServer{endpoint}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	answer, err := resolvers.ExchangeContext(ctx, new(D.Msg).SetQuestion("interop.example.test.", D.TypeTXT))
	if err != nil || answer == nil || answer.Rcode != D.RcodeSuccess {
		t.Fatalf("Mihomo rejected authenticated literal-IP DoH: answer=%v err=%v", answer, err)
	}
}

func TestBootstrapRejectsCertificateNameInjection(t *testing.T) {
	for _, name := range []string{"", "*.example.com", "example.com&skip-cert-verify=true", "example.com:443", "127.0.0.1", "example.com.", "bad_name.example"} {
		endpoint := preflightServer("https://127.0.0.1/dns-query")
		endpoint.Params["name-cert-verify"] = name
		if validateProtectedServers([]dns.NameServer{endpoint}, "DIRECT", true) == nil {
			t.Fatalf("invalid certificate identity accepted: %q", name)
		}
	}
}

func TestBootstrapDiagnosticsPreserveSocketErrorCode(t *testing.T) {
	var result bootstrapProbe
	result.setFailure(&os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED})
	if result.OSError == nil || *result.OSError != uint64(syscall.ECONNREFUSED) || result.ErrorCategory != "connection" {
		t.Fatalf("lost socket failure details: %+v", result)
	}
}

func TestPublicBootstrapProviderInterop(t *testing.T) {
	if os.Getenv("DNS2_TEST_LIVE_BOOTSTRAP") != "1" {
		t.Skip("public-provider interoperability is an explicit integration check")
	}
	for _, address := range []string{"https://223.5.5.5/dns-query", "https://223.6.6.6/dns-query"} {
		endpoint := preflightServer(address)
		endpoint.Params["name-cert-verify"] = "dns.alidns.com"
		result := probeBootstrapServer(context.Background(), endpoint, ca.GetCertPool())
		t.Logf("public provider preflight: %+v", result)
		if result.Result != "success" {
			continue
		}
		endpoint.ProxyAdapter = outbound.NewDirect()
		resolvers := dns.NewResolver(dns.Config{Main: []dns.NameServer{endpoint}})
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		answer, err := resolvers.ExchangeContext(ctx, new(D.Msg).SetQuestion("bootstrap-interop.example.com.", D.TypeTXT))
		cancel()
		if err == nil && answer != nil && (answer.Rcode == D.RcodeSuccess || answer.Rcode == D.RcodeNameError) {
			t.Logf("Mihomo public-provider DoH passed: address=%s rcode=%d", address, answer.Rcode)
			return
		}
		t.Logf("Mihomo public-provider DoH failed: answer=%v err=%v", answer, err)
	}
	t.Fatal("no public-provider endpoint completed both authenticated preflight and Mihomo DNS exchange")
}
