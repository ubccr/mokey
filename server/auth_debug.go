package server

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var authCredentialQueryKeys = []string{
	"password",
	"passwd",
	"pass",
	"pwd",
	"otp",
	"otpcode",
}

func authQueryHasCredentials(c *fiber.Ctx) bool {
	for _, key := range authCredentialQueryKeys {
		if c.Query(key) != "" {
			return true
		}
	}
	return false
}

func authFormFieldNames(c *fiber.Ctx) []string {
	names := make([]string, 0, 8)
	c.Request().PostArgs().VisitAll(func(key, _ []byte) {
		names = append(names, string(key))
	})
	return names
}

func (r *Router) authDebugFields(c *fiber.Ctx, step string) log.Fields {
	fields := log.Fields{
		"auth_step":       step,
		"path":            c.Path(),
		"method":          c.Method(),
		"ip":              RemoteIP(c),
		"is_htmx":         c.Get("HX-Request") == "true",
		"session_cookie":  c.Cookies("session"),
		"has_csrf_header": c.Get("X-CSRF-Token") != "",
		"has_csrf_form":   c.FormValue("_csrf") != "" || c.FormValue("csrf") != "",
	}

	if c.Method() == fiber.MethodPost {
		fields["form_fields"] = authFormFieldNames(c)
		fields["has_username"] = c.FormValue("username") != ""
		fields["has_password"] = c.FormValue("password") != ""
		fields["has_otp"] = c.FormValue("otp") != "" || c.FormValue("otpcode") != ""
		fields["has_challenge"] = c.FormValue("challenge") != ""
	}

	for _, key := range authCredentialQueryKeys {
		if c.Query(key) != "" {
			fields["query_has_"+key] = true
		}
	}

	return fields
}

func (r *Router) logAuthStep(c *fiber.Ctx, step string, extra log.Fields) {
	fields := r.authDebugFields(c, step)
	for k, v := range extra {
		fields[k] = v
	}

	switch step {
	case "reject_query_credentials", "strip_query_credentials":
		log.WithFields(fields).Warn("AUTH security: credentials must not appear in URL")
	default:
		if viper.GetBool("server.auth_debug") {
			log.WithFields(fields).Info("AUTH flow")
		}
	}
}

func (r *Router) redirectCleanLogin(c *fiber.Ctx, reason string) error {
	r.logAuthStep(c, "strip_query_credentials", log.Fields{
		"redirect_reason": reason,
		"redirect_to":     "/auth/login",
	})

	if c.Get("HX-Request") == "true" {
		c.Set("HX-Redirect", "/auth/login")
		return c.Status(fiber.StatusNoContent).SendString("")
	}

	return c.Redirect("/auth/login")
}

func (r *Router) sanitizeAuthQuery(c *fiber.Ctx) error {
	if c.Method() != fiber.MethodGet {
		return c.Next()
	}

	if !strings.HasPrefix(c.Path(), "/auth/") && c.Path() != "/oauth/login" {
		return c.Next()
	}

	if !authQueryHasCredentials(c) {
		return c.Next()
	}

	return r.redirectCleanLogin(c, "credentials_in_query_string")
}
