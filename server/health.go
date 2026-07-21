package server

import (
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
)

// Healthz is an unauthenticated health check endpoint. It verifies the
// session storage backend and FreeIPA are reachable. Registered before the
// CSRF middleware so probes don't create sessions.
func (r *Router) Healthz(c *fiber.Ctx) error {
	if _, err := r.storage.Get("healthz"); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("healthz: session storage check failed")
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"status":  "unavailable",
			"storage": err.Error(),
		})
	}

	if _, err := r.adminClient.Ping(); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("healthz: FreeIPA ping failed")
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"status":  "unavailable",
			"freeipa": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"status": "ok",
	})
}
