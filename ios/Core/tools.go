//go:build tools

// Держит golang.org/x/mobile в go.mod — он нужен gomobile bind.
package pon4ikcore

import _ "golang.org/x/mobile/bind"
