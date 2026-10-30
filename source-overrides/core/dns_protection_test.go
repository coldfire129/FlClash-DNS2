package core

import (
	"context"
	"crypto/tls"
	"errors"
	"runtime"
	"testing"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
)

func TestProtectedFieldsSurviveMihomoParsing(t *testing.T) {
	cfg, err := config.Parse([]byte(`
mode: global
ipv6: false
external-controller: ''
proxies:
  - {name: HK-01, type: socks5, server: 198.51.100.1, port: 1080}
tun:
  enable: true
  device: FlClashDNS
  auto-route: true
  strict-route: true
  dns-mode: hijack
  dns-hijack: ['any:53', 'tcp://any:53']
dns:
  enable: true
  ipv6: false
  listen: 127.0.0.1:1053
  nameserver: ['https://1.1.1.1/dns-query#HK-01&ecs=0.0.0.0/0&ecs-override=true']
  direct-nameserver: ['tls://1.1.1.1#HK-01&ecs=0.0.0.0/0&ecs-override=true']
  default-nameserver: ['https://1.1.1.1/dns-query#DIRECT&ecs=0.0.0.0/0&ecs-override=true']
  proxy-server-nameserver: ['https://1.1.1.1/dns-query#DIRECT&ecs=0.0.0.0/0&ecs-override=true']
  fallback: []
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, list := range [][]dns.NameServer{cfg.DNS.NameServer, cfg.DNS.DirectNameServer} {
		if err := validateProtectedServers(list, "HK-01", false); err != nil {
			t.Fatal(err)
		}
	}
	for _, list := range [][]dns.NameServer{cfg.DNS.DefaultNameserver, cfg.DNS.ProxyServerNameserver} {
		if err := validateProtectedServers(list, "DIRECT", true); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS == "windows" {
		if err := validateProtectedConfig(cfg, &SetupParams{DnsProxyTarget: "HK-01"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProtectedErrorsRemainUsefulWithoutPrivateErrorText(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
	}{
		{nil, ""}, {context.Canceled, "DP_QUERY_CANCELLED"}, {context.DeadlineExceeded, "DP_UPSTREAM_TIMEOUT"},
		{&tls.CertificateVerificationError{Err: errors.New("private host")}, "DP_TLS_CERTIFICATE"},
		{errors.New("secret resolver error"), "DP_UPSTREAM_FAILURE"},
	} {
		if got := protectedQueryError(test.err); got != test.code {
			t.Errorf("got %q want %q", got, test.code)
		}
	}
}

func TestProtectedResolverRejectsBypass(t *testing.T) {
	valid := dns.NameServer{Net: "https", Addr: "https://1.1.1.1/dns-query", ProxyName: "HK-01", Params: map[string]string{"ecs": "0.0.0.0/0", "ecs-override": "true"}}
	if err := validateProtectedServers([]dns.NameServer{valid}, "HK-01", false); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		server dns.NameServer
	}{
		{"system", dns.NameServer{Net: "system"}},
		{"plaintext", dns.NameServer{Net: "udp", Addr: "8.8.8.8:53", ProxyName: "HK-01"}},
		{"direct fallback", func() dns.NameServer { s := valid; s.ProxyName = "DIRECT"; return s }()},
		{"missing ECS", func() dns.NameServer { s := valid; s.Params = nil; return s }()},
		{"insecure TLS", func() dns.NameServer {
			s := valid
			s.Params = map[string]string{"skip-cert-verify": "true", "ecs": "0.0.0.0/0", "ecs-override": "true"}
			return s
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if validateProtectedServers([]dns.NameServer{test.server}, "HK-01", false) == nil {
				t.Fatal("unsafe resolver accepted")
			}
		})
	}
	if validateProtectedServers(nil, "HK-01", false) == nil {
		t.Fatal("empty resolver list accepted")
	}
	valid.ProxyName = "DIRECT"
	if err := validateProtectedServers([]dns.NameServer{valid}, "DIRECT", true); err != nil {
		t.Fatal(err)
	}
	valid.Addr = "https://dns.example/dns-query"
	if validateProtectedServers([]dns.NameServer{valid}, "DIRECT", true) == nil {
		t.Fatal("bootstrap resolution loop accepted")
	}
}

func TestProtectedRuntimeUpdateRetainsPolicy(t *testing.T) {
	previous := dnsProtectionEnabled.Swap(true)
	t.Cleanup(func() { dnsProtectionEnabled.Store(previous) })
	yes := true
	no := false
	badDevice := "OtherTUN"
	controller := ":9090"
	for _, params := range []UpdateParams{
		{IPv6: &yes}, {SkipCertVerify: &yes}, {ExternalController: &controller},
		{Tun: &tunSchema{Enable: false}},
		{Tun: &tunSchema{Enable: true, AutoRoute: &no}},
		{Tun: &tunSchema{Enable: true, Device: &badDevice}},
	} {
		if validateProtectedUpdate(&params) == nil {
			t.Fatalf("unsafe update accepted: %+v", params)
		}
	}
	if err := validateProtectedUpdate(&UpdateParams{IPv6: &no, SkipCertVerify: &no, Tun: &tunSchema{Enable: true, AutoRoute: &yes}}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectedProtectedConfigDoesNotApplyDefault(t *testing.T) {
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(previousHome) })
	previous := &config.Config{General: &config.General{}}
	withCurrentConfig(t, previous)
	oldPolicy := dnsProtectionEnabled.Swap(true)
	t.Cleanup(func() { dnsProtectionEnabled.Store(oldPolicy) })
	err := applyConfig(&SetupParams{DnsProtection: true})
	if err == nil {
		t.Fatal("missing protected profile accepted")
	}
	if currentConfig != previous {
		t.Fatal("protected profile replaced with insecure default")
	}
	if !dnsProtectionEnabled.Load() {
		t.Fatal("protection disabled after rejected profile")
	}
}
