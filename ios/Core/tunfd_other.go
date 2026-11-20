//go:build !darwin && !ios

package pon4ikcore

// FindTunFd — заглушка для сборки на других системах.
func FindTunFd() int { return -1 }
