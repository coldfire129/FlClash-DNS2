package core

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/dns"
	D "github.com/miekg/dns"
)

func preflightServer(address string) dns.NameServer {
	return dns.NameServer{
		Net: "https", Addr: address, ProxyName: "DIRECT",
		Params: map[string]string{"ecs": "0.0.0.0/0", "ecs-override": "true"},
	}
}

func TestBootstrapProbeRequiresAnAuthenticatedCorrelatedDNSResponse(t *testing.T) {
	for _, test := range []struct {
		name    string
		rcode   int
		corrupt bool
		want    string
	}{
		{"negative answer", D.RcodeNameError, false, "success"},
		{"normal answer", D.RcodeSuccess, false, "success"},
		{"server failure", D.RcodeServerFailure, false, "failed"},
		{"refused", D.RcodeRefused, false, "failed"},
		{"wrong question", D.RcodeSuccess, true, "failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
					t.Error("preflight did not use wire-format DoH")
				}
				body, _ := io.ReadAll(r.Body)
				request := new(D.Msg)
				if err := request.Unpack(body); err != nil {
					t.Error(err)
					return
				}
				if subnet, ok := request.IsEdns0().Option[0].(*D.EDNS0_SUBNET); !ok || subnet.SourceNetmask != 0 {
					t.Error("preflight disclosed ECS")
				}
				answer := new(D.Msg)
				answer.SetReply(request)
				answer.Rcode = test.rcode
				if test.corrupt {
					answer.Question[0].Name = "different.example.com."
				}
				wire, _ := answer.Pack()
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(wire)
			}))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			result := probeBootstrapServer(context.Background(), preflightServer(server.URL+"/dns-query"), roots)
			if result.Result != test.want {
				t.Fatalf("got %+v", result)
			}
		})
	}
}

func TestBootstrapProbeNeverUsesCertificateBypassOrFollowsRedirects(t *testing.T) {
	var redirected atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer server.Close()
	withSkipCertVerify(t, true)
	result := probeBootstrapServer(context.Background(), preflightServer(server.URL+"/dns-query"), x509.NewCertPool())
	if result.Result != "failed" || result.ErrorCode != "DP_TLS_CERTIFICATE" {
		t.Fatalf("untrusted TLS accepted: %+v", result)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	result = probeBootstrapServer(context.Background(), preflightServer(server.URL+"/dns-query"), roots)
	if result.ErrorCode != "DP_DOH_BAD_RESPONSE" || redirected.Load() != 0 {
		t.Fatalf("redirect escaped the encrypted endpoint: %+v", result)
	}
}

func TestBootstrapProbeDoesNotTreatHTTP200AsDNS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write([]byte("not a DNS message"))
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	result := probeBootstrapServer(context.Background(), preflightServer(server.URL), roots)
	if result.ErrorCode != "DP_DOH_BAD_RESPONSE" {
		t.Fatalf("got %+v", result)
	}
}

func TestBootstrapProbeRejectsUnsafeEndpointsBeforeNetworkAccess(t *testing.T) {
	for _, address := range []string{"http://127.0.0.1/dns-query", "https://resolver.example.com/dns-query", "https://[::1]/dns-query"} {
		result := probeBootstrapServer(context.Background(), preflightServer(address), nil)
		if result.ErrorCode != "DP_UNSAFE_UPSTREAM" {
			t.Fatalf("got %+v", result)
		}
	}
}

func TestBootstrapProbeHonorsCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	result := probeBootstrapServer(ctx, preflightServer(server.URL), roots)
	if result.ErrorCode != "DP_UPSTREAM_TIMEOUT" {
		t.Fatalf("got %+v", result)
	}
}
