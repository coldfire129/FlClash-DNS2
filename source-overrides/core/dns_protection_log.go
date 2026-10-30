package core

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	D "github.com/miekg/dns"
)

type diagnosticEntry struct {
	fields map[string]any
	flush  chan struct{}
}

var diagnosticOnce sync.Once
var diagnosticQueue = make(chan diagnosticEntry, 2048)
var diagnosticKey [32]byte
var diagnosticStarted = time.Now()
var diagnosticDropped atomic.Uint64
var diagnosticQueries atomic.Uint64
var diagnosticFailures atomic.Uint64
var diagnosticWriteError atomic.Bool

func startDiagnostics() {
	diagnosticOnce.Do(func() {
		if _, err := rand.Read(diagnosticKey[:]); err != nil {
			diagnosticWriteError.Store(true)
			return
		}
		directory := filepath.Join(C.Path.HomeDir(), "diagnostics", "dns-protection", "core")
		safeGo("dns diagnostics", func() { writeDiagnostics(directory) })
	})
}

func recordDiagnostic(module, event, result, code string) {
	startDiagnostics()
	queueDiagnostic(map[string]any{
		"module": module, "event": event, "result": result, "error_code": code,
	})
}

func queueDiagnostic(fields map[string]any) {
	fields["level"] = "info"
	if fields["result"] == "failed" || fields["result"] == "blocked" {
		fields["level"] = "error"
	}
	fields["build_id"] = "0.9.2-dns2"
	fields["pid"] = os.Getpid()
	fields["schema_version"] = 1
	fields["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	fields["mono_ms"] = time.Since(diagnosticStarted).Milliseconds()
	fields["config_revision"] = dnsProtectionRevision.Load()
	fields["policy_revision"] = dnsProtectionPolicyRevision.Load()
	select {
	case diagnosticQueue <- diagnosticEntry{fields: fields}:
	default:
		diagnosticDropped.Add(1)
	}
}

func recordProtectedQuery(record dns.QueryRecord) {
	if !dnsProtectionEnabled.Load() {
		return
	}
	diagnosticQueries.Add(1)
	badRcode := record.Msg != nil && record.Msg.Rcode != D.RcodeSuccess && record.Msg.Rcode != D.RcodeNameError
	if record.Err != nil || badRcode {
		diagnosticFailures.Add(1)
	}
	if !dnsProtectionVerbose.Load() && record.Err == nil && !badRcode {
		return
	}
	hash := hmac.New(sha256.New, diagnosticKey[:])
	_, _ = hash.Write([]byte(record.Question.Name))
	result, code := "success", ""
	if record.Err != nil {
		result, code = "failed", protectedQueryError(record.Err)
	} else if badRcode {
		result, code = "failed", "DP_DNS_RCODE"
	}
	var rcode any
	if record.Msg != nil {
		rcode = record.Msg.Rcode
	}
	fields := map[string]any{
		"module": "dns", "event": "dns_query_completed", "result": result,
		"error_code": code, "qname_hash": hex.EncodeToString(hash.Sum(nil)),
		"qtype": D.Type(record.Question.Qtype).String(), "cached": record.Cached,
		"rcode":      rcode,
		"dns_target": record.Upstream, "target_observed": record.Upstream != "", "purpose": record.Initiator,
		"duration_ms":     time.Since(record.Start).Milliseconds(),
		"observed_egress": nil,
	}
	if record.Err != nil {
		fields["error_category"] = providerRequestFailureReason(record.Err)
		var socketError syscall.Errno
		if errors.As(record.Err, &socketError) {
			fields["os_error"] = uint64(socketError)
		}
	}
	queueDiagnostic(fields)
}

func protectedQueryError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "DP_QUERY_CANCELLED"
	}
	var certificate *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &certificate) || errors.As(err, &authority) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return "DP_TLS_CERTIFICATE"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return "DP_UPSTREAM_TIMEOUT"
	}
	return "DP_UPSTREAM_FAILURE"
}

func flushDiagnostics() {
	if !dnsProtectionEnabled.Load() && len(diagnosticQueue) == 0 {
		return
	}
	done := make(chan struct{})
	select {
	case diagnosticQueue <- diagnosticEntry{flush: done}:
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	case <-time.After(time.Second):
	}
}

func writeDiagnostics(directory string) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		diagnosticWriteError.Store(true)
		return
	}
	path := filepath.Join(directory, "dns-protection.jsonl")
	for i := 1; i <= 4; i++ {
		rotated := fmt.Sprintf("%s.%d", path, i)
		if info, err := os.Stat(rotated); err == nil && time.Since(info.ModTime()) > 7*24*time.Hour {
			_ = os.Remove(rotated)
		}
	}
	var file *os.File
	var writer *bufio.Writer
	var size int64
	open := func() error {
		var err error
		file, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return err
		}
		size = info.Size()
		writer = bufio.NewWriterSize(file, 64*1024)
		return nil
	}
	if err := open(); err != nil {
		diagnosticWriteError.Store(true)
		return
	}
	defer file.Close()
	flush := func() {
		if err := writer.Flush(); err != nil {
			diagnosticWriteError.Store(true)
		}
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	summary := time.NewTicker(30 * time.Second)
	defer summary.Stop()
	for {
		select {
		case entry := <-diagnosticQueue:
			if entry.flush != nil {
				flush()
				close(entry.flush)
				continue
			}
			data, err := json.Marshal(entry.fields)
			if err != nil {
				continue
			}
			if size+int64(len(data)+1) > 20*1024*1024 {
				flush()
				_ = file.Close()
				_ = os.Remove(path + ".4")
				for i := 3; i >= 1; i-- {
					_ = os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
				}
				_ = os.Rename(path, path+".1")
				if err := open(); err != nil {
					diagnosticWriteError.Store(true)
					return
				}
			}
			n, err := writer.Write(append(data, '\n'))
			size += int64(n)
			if err != nil {
				diagnosticWriteError.Store(true)
			}
		case <-ticker.C:
			flush()
		case <-summary.C:
			if dnsProtectionEnabled.Load() {
				queries, failures := diagnosticQueries.Swap(0), diagnosticFailures.Swap(0)
				result := "success"
				if failures > 0 {
					result = "failed"
				} else if queries == 0 {
					result = "unknown"
				}
				queueDiagnostic(map[string]any{
					"module": "dns", "event": "dns_query_summary", "result": result,
					"queries": queries, "failures": failures,
					"dropped_count": diagnosticDropped.Swap(0),
				})
			}
		}
	}
}
