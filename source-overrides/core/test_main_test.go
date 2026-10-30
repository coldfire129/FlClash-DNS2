package core

import (
	"fmt"
	"os"
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
	constant.SetHomeDir(previousHome)
	if cache.DB == nil {
		fmt.Fprintln(os.Stderr, "cannot open isolated test cache")
		_ = os.RemoveAll(home)
		os.Exit(1)
	}
	code := m.Run()
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
