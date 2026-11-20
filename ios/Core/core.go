// Package pon4ikcore — тонкая обёртка над Xray-core для iOS (собирается gomobile в Pon4ikCore.xcframework).
package pon4ikcore

import (
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

var (
	mu   sync.Mutex
	inst *core.Instance
)

// Start запускает ядро с JSON-конфигом. tunFd — дескриптор utun от NetworkExtension.
func Start(configJSON string, tunFd int) error {
	mu.Lock()
	defer mu.Unlock()
	if inst != nil {
		_ = inst.Close()
		inst = nil
	}
	// Расширения VPN на iOS ограничены по памяти (около 50 МБ) — держим Go в рамках
	debug.SetMemoryLimit(32 << 20)
	debug.SetGCPercent(20)

	fd := strconv.Itoa(tunFd)
	_ = os.Setenv("xray.tun.fd", fd)
	_ = os.Setenv("XRAY_TUN_FD", fd)

	cfg, err := core.LoadConfig("json", strings.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	i, err := core.New(cfg)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if err := i.Start(); err != nil {
		_ = i.Close()
		return fmt.Errorf("start: %w", err)
	}
	inst = i
	return nil
}

// Stop останавливает ядро.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if inst != nil {
		_ = inst.Close()
		inst = nil
	}
	debug.FreeOSMemory()
}

// Version — версия Xray-core.
func Version() string { return core.Version() }

// FreeMemory просит Go вернуть память системе (вызывается при нехватке памяти).
func FreeMemory() { debug.FreeOSMemory() }
