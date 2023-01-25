package server

import (
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/net/xsrftoken"
)

func (r *Router) CSRF(c *fiber.Ctx) error {
	sess, err := r.session(c)
	if err != nil {
		return err
	}

	var token string
	csrf := sess.Get(SessionKeyCSRF)
	if _, ok := csrf.(string); ok {
		token = csrf.(string)
	}

	switch c.Method() {
	case fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions, fiber.MethodTrace:
		if token == "" {
			token = xsrftoken.Generate(viper.GetString("server.csrf_secret"), "", "")
			sess.Set(SessionKeyCSRF, token)
			sess.Save()
		}
	default:
		if token == "" || token != c.Get("X-CSRF-Token") {
			log.WithFields(log.Fields{
				"path": c.Path(),
				"ip":   RemoteIP(c),
			}).Error("Invalid CSRF token in POST request")
			return fiber.ErrForbidden
		}
	}

	c.Locals(SessionKeyCSRF, token)

	return c.Next()
}
