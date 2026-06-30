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
		log.WithFields(log.Fields{
			"path": c.Path(),
			"ip":   RemoteIP(c),
			"err":  err,
		}).Warn("Session storage unavailable")
		if c.Get("HX-Request", "false") == "true" {
			c.Set("HX-Redirect", "/auth/login")
			return c.Status(fiber.StatusNoContent).SendString("")
		}
		return c.Redirect("/auth/login")
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
		requestToken := c.Get("X-CSRF-Token")
		if requestToken == "" {
			requestToken = c.FormValue("_csrf")
		}
		if requestToken == "" {
			requestToken = c.FormValue("csrf")
		}

		if token == "" || requestToken == "" || token != requestToken {
			log.WithFields(log.Fields{
				"path":            c.Path(),
				"ip":              RemoteIP(c),
				"is_htmx":         c.Get("HX-Request") == "true",
				"has_csrf_header": c.Get("X-CSRF-Token") != "",
				"has_csrf_form":   c.FormValue("_csrf") != "" || c.FormValue("csrf") != "",
				"session_cookie":  c.Cookies("session"),
			}).Error("Invalid CSRF token in POST request")
			return fiber.ErrForbidden
		}
	}

	c.Locals(SessionKeyCSRF, token)

	return c.Next()
}
