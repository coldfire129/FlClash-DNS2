package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/ntp"
	D "github.com/miekg/dns"
)

type bootstrapProbe struct {
	Target     string `json:"target"`
	Purpose    string `json:"purpose"`
	Result     string `json:"result"`
	ErrorCode  string `json:"errorCode,omitempty"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
	Rcode      *int   `json:"rcode,omitempty"`
	DurationMs int64  `json:"durationMs"`
}

var lastDnsPreflight atomic.Value

func handleDnsProtectionValidate(params *SetupParams) error {
	if !isInit.Load() {
		return errNotInitialized
	}
	if !params.DnsProtection {
		return errors.New("DP_CONFIG_REJECTED: protected validation required")
	}
	configMu.Lock()
	defer configMu.Unlock()
	cfg, err := loadSetupConfig(params)
	if err != nil {
		return err
	}
	return validateProtectedConfig(cfg, params)
}

func handleDnsProtectionPreflight(params *SetupParams) error {
	if !isInit.Load() {
		return errNotInitialized
	}
	if !params.DnsProtection {
		return errors.New("DP_CONFIG_REJECTED: protected preflight required")
	}
	configMu.Lock()
	cfg, err := loadSetupConfig(params)
	if err == nil {
		err = validateProtectedConfig(cfg, params)
	}
	configMu.Unlock()
	if err != nil {
		return err
	}
	startDiagnostics()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	var probes []bootstrapProbe
	ready := true
	groups := []struct {
		purpose string
		servers []dns.NameServer
	}{{"default", cfg.DNS.DefaultNameserver}, {"proxy", cfg.DNS.ProxyServerNameserver}}
	resultsByGroup := make([][]bootstrapProbe, len(groups))
	var pending sync.WaitGroup
	for i, group := range groups {
		pending.Add(1)
		safeGo("DNS bootstrap group", func() {
			defer pending.Done()
			resultsByGroup[i] = probeBootstrapGroup(ctx, group.servers, ca.GetCertPool())
		})
	}
	pending.Wait()
	for i, group := range groups {
		results := resultsByGroup[i]
		groupReady := false
		for i := range results {
			results[i].Purpose = group.purpose
			groupReady = groupReady || results[i].Result == "success"
			queueDiagnostic(map[string]any{
				"module": "dns", "event": "bootstrap_preflight", "result": results[i].Result,
				"dns_target": results[i].Target, "purpose": group.purpose,
				"error_code": results[i].ErrorCode, "http_status": results[i].HTTPStatus,
				"rcode": results[i].Rcode, "duration_ms": results[i].DurationMs,
				"requested_policy_revision": params.DnsPolicyRevision,
			})
		}
		probes = append(probes, results...)
		ready = ready && groupReady
	}
	lastDnsPreflight.Store(map[string]any{
		"ready": ready, "checkedAt": time.Now().UTC().Format(time.RFC3339Nano),
		"policyRevision": params.DnsPolicyRevision, "probes": probes,
	})
	if !ready {
		return errors.New("DP_BOOTSTRAP_UNREACHABLE: encrypted bootstrap DNS failed; Guard remains armed until protection is explicitly stopped")
	}
	return nil
}

func probeBootstrapGroup(ctx context.Context, servers []dns.NameServer, roots *x509.CertPool) []bootstrapProbe {
	results := make([]bootstrapProbe, len(servers))
	var pending sync.WaitGroup
	for i, server := range servers {
		pending.Add(1)
		safeGo("DNS bootstrap preflight", func() {
			defer pending.Done()
			results[i] = probeBootstrapServer(ctx, server, roots)
		})
	}
	pending.Wait()
	return results
}

func probeBootstrapServer(ctx context.Context, server dns.NameServer, roots *x509.CertPool) (result bootstrapProbe) {
	started := time.Now()
	result.Target, result.Result = server.Addr, "failed"
	defer func() { result.DurationMs = time.Since(started).Milliseconds() }()
	if err := validateProtectedServers([]dns.NameServer{server}, "DIRECT", true); err != nil {
		result.ErrorCode = "DP_UNSAFE_UPSTREAM"
		return
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		result.ErrorCode = "DP_PROBE_UNKNOWN"
		return
	}
	query := new(D.Msg)
	query.SetQuestion(hex.EncodeToString(nonce[:])+"-dp.example.com.", D.TypeTXT)
	query.Id = 0
	query.SetEdns0(1232, false)
	query.IsEdns0().Option = append(query.IsEdns0().Option, &D.EDNS0_SUBNET{
		Code: D.EDNS0SUBNET, Family: 1, Address: net.IPv4zero,
	})
	wire, err := query.Pack()
	if err != nil {
		result.ErrorCode = "DP_PROBE_UNKNOWN"
		return
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", address)
		},
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, Time: ntp.Now},
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.Addr, bytes.NewReader(wire))
	if err != nil {
		result.ErrorCode = "DP_UNSAFE_UPSTREAM"
		return
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := client.Do(request)
	if err != nil {
		result.ErrorCode = protectedQueryError(err)
		return
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	contentType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || contentType != "application/dns-message" {
		result.ErrorCode = "DP_DOH_BAD_RESPONSE"
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		result.ErrorCode = protectedQueryError(err)
		return
	}
	answer := new(D.Msg)
	if len(body) > 65535 || answer.Unpack(body) != nil || !answer.Response || answer.Opcode != D.OpcodeQuery || answer.Id != query.Id || len(answer.Question) != 1 || answer.Question[0] != query.Question[0] {
		result.ErrorCode = "DP_DOH_BAD_RESPONSE"
		return
	}
	result.Rcode = &answer.Rcode
	if answer.Rcode != D.RcodeSuccess && answer.Rcode != D.RcodeNameError {
		result.ErrorCode = "DP_DNS_RCODE"
		return
	}
	result.Result = "success"
	return
}

func protectedErrorCode(err error) string {
	if err == nil {
		return ""
	}
	code, _, _ := strings.Cut(err.Error(), ":")
	if strings.HasPrefix(code, "DP_") && !strings.ContainsAny(code, " \r\n") {
		return code
	}
	return "DP_CONFIG_REJECTED"
}
