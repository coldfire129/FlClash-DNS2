package core

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/constant"
)

func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "flclash-core-cache-tests-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	previousHome := constant.Path.HomeDir()
	constant.SetHomeDir(home)
	cache := cachefile.Cache()
	// The diagnostic writer lives until process exit, beyond per-test TempDir cleanup.
	// Keep its records in the caller-owned output directory for collection afterward.
	diagnosticHome := os.Getenv("DNS2_TEST_DIAGNOSTIC_HOME")
	if diagnosticHome == "" {
		diagnosticHome = filepath.Join(os.TempDir(), fmt.Sprintf("flclash-core-diagnostics-%d", os.Getpid()))
	}
	constant.SetHomeDir(diagnosticHome)
	startDiagnostics()
	constant.SetHomeDir(previousHome)
	if cache.DB == nil {
		fmt.Fprintln(os.Stderr, "cannot open isolated test cache")
		_ = os.RemoveAll(home)
		os.Exit(1)
	}
	code := m.Run()
	flushDiagnostics()
	if err := cache.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	if err := os.RemoveAll(home); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}
