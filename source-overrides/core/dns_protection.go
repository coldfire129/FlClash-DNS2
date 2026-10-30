package core

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
)

var dnsProtectionEnabled atomic.Bool
var dnsProtectionVerbose atomic.Bool
var dnsProtectionRevision atomic.Uint64
var dnsProtectionPolicyRevision atomic.Value

func validateProtectedConfig(cfg *config.Config, params *SetupParams) error {
	if runtime.GOOS != "windows" {
		return errors.New("DP_CONFIG_REJECTED: Windows DNS protection only")
	}
	if params.SkipCertVerify || cfg.General.IPv6 || cfg.DNS.IPv6 {
		return errors.New("DP_CONFIG_REJECTED: certificate or IPv6 policy")
	}
	tun := cfg.General.Tun
	if !tun.Enable || !tun.AutoRoute || !tun.StrictRoute || tun.DNSMode != "hijack" || tun.Device != "FlClashDNS" {
		return errors.New("DP_TUN_REQUIRED: protected TUN settings are missing")
	}
	if !slices.Contains(tun.DNSHijack, "any:53") || !slices.Contains(tun.DNSHijack, "tcp://any:53") {
		return errors.New("DP_TUN_REQUIRED: UDP and TCP DNS interception required")
	}
	controller := cfg.Controller
	if controller.ExternalController != "" || controller.ExternalControllerTLS != "" || controller.ExternalControllerPipe != "" || controller.ExternalControllerUnix != "" {
		return errors.New("DP_CONFIG_REJECTED: external controller must be closed")
	}
	d := cfg.DNS
	if !d.Enable || d.Listen != "127.0.0.1:1053" || len(d.Fallback) != 0 || len(d.NameServerPolicy) != 0 || len(d.ProxyServerPolicy) != 0 || d.DirectFollowPolicy {
		return errors.New("DP_UNSAFE_UPSTREAM: DNS bypass configuration")
	}
	proxy := cfg.Proxies[params.DnsProxyTarget]
	if proxy == nil || proxy.Type() < C.Shadowsocks {
		return errors.New("DP_NO_PROXY: select a concrete proxy in the profile")
	}
	host, port, err := net.SplitHostPort(proxy.Addr())
	if err != nil || port == "53" || port == "853" {
		return errors.New("DP_NO_PROXY: unsupported proxy endpoint")
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
		return errors.New("DP_IPV6_UNPROTECTED: IPv6-only proxy endpoint")
	}
	for _, list := range [][]dns.NameServer{d.NameServer, d.DirectNameServer} {
		if err := validateProtectedServers(list, params.DnsProxyTarget, false); err != nil {
			return err
		}
	}
	for _, list := range [][]dns.NameServer{d.DefaultNameserver, d.ProxyServerNameserver} {
		if len(list) > 8 {
			return errors.New("DP_CONFIG_REJECTED: too many bootstrap resolvers")
		}
		if err := validateProtectedServers(list, "DIRECT", true); err != nil {
			return err
		}
	}
	return nil
}

func validateProtectedServers(servers []dns.NameServer, target string, bootstrap bool) error {
	if target == "" || len(servers) == 0 {
		return errors.New("DP_UNSAFE_UPSTREAM: missing resolver or target")
	}
	for _, server := range servers {
		if server.ProxyName != target || (server.Net != "https" && server.Net != "tls") || server.Params["skip-cert-verify"] != "" || server.Params["ecs"] != "0.0.0.0/0" || server.Params["ecs-override"] != "true" {
			return errors.New("DP_UNSAFE_UPSTREAM: unprotected resolver")
		}
		if name, present := server.Params["name-cert-verify"]; present && (!bootstrap || !validBootstrapCertificateName(name)) {
			return errors.New("DP_UNSAFE_UPSTREAM: invalid bootstrap certificate name")
		}
		if server.Net == "https" {
			u, err := url.Parse(server.Addr)
			if err != nil || u.Scheme != "https" || u.User != nil {
				return errors.New("DP_UNSAFE_UPSTREAM: invalid HTTPS resolver")
			}
			if bootstrap {
				ip, err := netip.ParseAddr(u.Hostname())
				if err != nil || !ip.Is4() {
					return errors.New("DP_BOOTSTRAP_LOOP: literal IPv4 HTTPS endpoint required")
				}
			}
		} else if bootstrap {
			return errors.New("DP_BOOTSTRAP_LOOP: HTTPS bootstrap required")
		}
	}
	return nil
}

func validBootstrapCertificateName(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') {
				return false
			}
		}
	}
	return true
}

func validateProtectedUpdate(params *UpdateParams) error {
	if !dnsProtectionEnabled.Load() {
		return nil
	}
	if params.IPv6 != nil && *params.IPv6 || params.SkipCertVerify != nil && *params.SkipCertVerify || params.ExternalController != nil && *params.ExternalController != "" {
		return errors.New("DP_CONFIG_REJECTED: unsafe runtime update")
	}
	if params.Tun != nil && (!params.Tun.Enable || params.Tun.Device != nil && *params.Tun.Device != "FlClashDNS" || params.Tun.AutoRoute != nil && !*params.Tun.AutoRoute) {
		return errors.New("DP_TUN_REQUIRED: unsafe TUN update")
	}
	return nil
}

func handleDnsProtectionStatus() map[string]any {
	configMu.Lock()
	defer configMu.Unlock()
	status := map[string]any{
		"processId":       os.Getpid(),
		"enabled":         dnsProtectionEnabled.Load(),
		"revision":        dnsProtectionRevision.Load(),
		"running":         isRunning.Load(),
		"diagnosticError": diagnosticWriteError.Load(),
	}
	if revision := dnsProtectionPolicyRevision.Load(); revision != nil {
		status["policyRevision"] = revision
	}
	if preflight := lastDnsPreflight.Load(); preflight != nil {
		status["preflight"] = preflight
	}
	if cfg := currentConfig; cfg != nil && dnsProtectionEnabled.Load() {
		status["listen"] = cfg.DNS.Listen
		status["device"] = cfg.General.Tun.Device
		targets := make([]string, 0, len(cfg.DNS.NameServer))
		for _, server := range cfg.DNS.NameServer {
			targets = append(targets, server.ProxyName)
		}
		status["expectedEgress"] = strings.Join(targets, ",")
	}
	return status
}
