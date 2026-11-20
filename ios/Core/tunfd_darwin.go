//go:build darwin || ios

package pon4ikcore

import (
	"strings"

	"golang.org/x/sys/unix"
)

// FindTunFd ищет дескриптор utun, который NetworkExtension открыл для туннеля.
// Возвращает -1, если не найден.
func FindTunFd() int {
	for fd := 0; fd < 1024; fd++ {
		// SYSPROTO_CONTROL = 2, UTUN_OPT_IFNAME = 2
		name, err := unix.GetsockoptString(fd, 2, 2)
		if err == nil && strings.HasPrefix(name, "utun") {
			return fd
		}
	}
	return -1
}
