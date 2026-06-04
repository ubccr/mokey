package server

import (
	"errors"
	"io"
	"strings"
	"syscall"

	"github.com/gofiber/fiber/v2"
)

// isBenignDisconnect reports whether err is typically caused by the client closing
// the connection early (browser navigation, HTMX redirect, load balancer probes).
func isBenignDisconnect(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) {
		return true
	}

	msg := err.Error()
	return strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "closed network connection") ||
		strings.Contains(msg, "use of closed network connection")
}

// isNoisyGatewayError is true when Fiber surfaces a generic 502 without an application bug.
func isNoisyGatewayError(code int, err error) bool {
	return code == fiber.StatusBadGateway || isBenignDisconnect(err)
}
